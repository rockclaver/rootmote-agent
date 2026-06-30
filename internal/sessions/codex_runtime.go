package sessions

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rockclaver/claver-agent/internal/store"
)

// codex_runtime.go drives the `codex app-server` CLI over its JSON-RPC 2.0 stdio
// protocol (the structured transport), translating its server notifications into
// normalized events and answering its exec/patch approval requests. Wire shapes
// are source-verified from `codex app-server generate-json-schema` (codex-cli
// 0.142.4); see plans/structured-agent-ui.md and codex_schema_test.go.

// codexControlTimeout bounds how long we wait for the app-server to answer a
// parent-issued JSON-RPC request (initialize/thread.start/turn.start/interrupt).
const codexControlTimeout = 60 * time.Second

// codexResponse is the result/error of a client->server JSON-RPC request.
type codexResponse struct {
	result json.RawMessage
	err    error
}

// codexConn is the JSON-RPC protocol engine over an app-server process's stdio.
// Split from process management so it can be unit-tested over in-memory pipes.
type codexConn struct {
	sink  structuredSink
	stdin io.Writer

	writeMu sync.Mutex

	reqMu   sync.Mutex
	reqN    int
	pending map[int]chan codexResponse // our request id -> response channel
	// approval request id (string) -> server method + raw JSON-RPC id to echo.
	approvalMethod map[string]string
	approvalRawID  map[string]json.RawMessage

	mu             sync.Mutex // guards thread/turn/policy
	threadID       string
	turnID         string
	approvalPolicy string // applied to the next turn/start (set via SetMode)
}

func newCodexConn(sink structuredSink, stdin io.Writer) *codexConn {
	return &codexConn{
		sink:           sink,
		stdin:          stdin,
		pending:        make(map[int]chan codexResponse),
		approvalMethod: make(map[string]string),
		approvalRawID:  make(map[string]json.RawMessage),
	}
}

// run reads JSON-RPC lines from the app-server's stdout until EOF, routing
// responses to waiting callers and translating notifications/approval requests
// into normalized events.
func (c *codexConn) run(r io.Reader) {
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			c.handleLine(line)
		}
		if err != nil {
			return
		}
	}
}

func (c *codexConn) handleLine(line []byte) {
	var env struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(line, &env) != nil {
		return
	}
	hasID := len(env.ID) > 0 && string(env.ID) != "null"
	switch {
	case env.Method == "" && hasID:
		// A response to one of our client requests.
		c.routeResponse(env.ID, env.Result, env.Error)
		return
	case env.Method != "" && hasID:
		// A server->client request. Only exec/patch approvals are answerable;
		// decline everything else so the app-server is never left waiting.
		if !codexApprovalMethods[env.Method] {
			c.respondError(env.ID, -32601, "unsupported request: "+env.Method)
			return
		}
		c.recordApproval(env.ID, env.Method)
		// fall through to translate, which emits the approval_request
	default:
		c.trackTurn(env.Method, env.Params)
	}
	evs, err := translateCodexLine(line)
	if err != nil {
		return // malformed line: log-and-skip semantics
	}
	for _, tr := range evs {
		c.sink.publish(tr)
	}
}

// trackTurn records the active turn id so Interrupt can target it.
func (c *codexConn) trackTurn(method string, params json.RawMessage) {
	if method != codexMethodTurnStarted {
		return
	}
	var p struct {
		Turn struct {
			ID string `json:"id"`
		} `json:"turn"`
	}
	if json.Unmarshal(params, &p) == nil && p.Turn.ID != "" {
		c.mu.Lock()
		c.turnID = p.Turn.ID
		c.mu.Unlock()
	}
}

func (c *codexConn) recordApproval(id json.RawMessage, method string) {
	reqID := codexRequestID(id)
	if reqID == "" {
		return
	}
	c.reqMu.Lock()
	c.approvalMethod[reqID] = method
	c.approvalRawID[reqID] = append(json.RawMessage(nil), id...)
	c.reqMu.Unlock()
}

func (c *codexConn) routeResponse(id, result, errRaw json.RawMessage) {
	var n int
	if json.Unmarshal(id, &n) != nil {
		return
	}
	c.reqMu.Lock()
	ch := c.pending[n]
	delete(c.pending, n)
	c.reqMu.Unlock()
	if ch == nil {
		return
	}
	var e error
	if len(errRaw) > 0 && string(errRaw) != "null" {
		var je struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(errRaw, &je)
		if je.Message == "" {
			je.Message = "codex request failed"
		}
		e = errors.New(je.Message)
	}
	ch <- codexResponse{result: result, err: e}
}

func (c *codexConn) writeJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err = c.stdin.Write(b)
	return err
}

// call issues a client->server JSON-RPC request and waits for its response.
func (c *codexConn) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.reqMu.Lock()
	c.reqN++
	id := c.reqN
	ch := make(chan codexResponse, 1)
	c.pending[id] = ch
	c.reqMu.Unlock()

	if err := c.writeJSON(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		c.reqMu.Lock()
		delete(c.pending, id)
		c.reqMu.Unlock()
		return nil, err
	}
	select {
	case resp := <-ch:
		return resp.result, resp.err
	case <-time.After(codexControlTimeout):
		c.reqMu.Lock()
		delete(c.pending, id)
		c.reqMu.Unlock()
		return nil, fmt.Errorf("codex request %q timed out", method)
	case <-ctx.Done():
		c.reqMu.Lock()
		delete(c.pending, id)
		c.reqMu.Unlock()
		return nil, ctx.Err()
	}
}

func (c *codexConn) notify(method string, params any) error {
	return c.writeJSON(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

func (c *codexConn) respondError(id json.RawMessage, code int, msg string) {
	_ = c.writeJSON(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": msg},
	})
}

// handshake performs the initialize -> initialized -> thread setup sequence and
// records the thread id so prompts can open turns. Runs synchronously in Start
// so a follow-on SendPrompt always sees a live thread. The thread is started
// fresh, resumed from a prior conversation, or forked off one depending on
// spec.ResumeAgentSessionID / spec.Fork. The resulting thread id is reported
// via spec.OnAgentSession so the Manager can persist it for later resume/fork.
func (c *codexConn) handshake(ctx context.Context, spec RuntimeSpec) error {
	if _, err := c.call(ctx, "initialize", map[string]any{
		"clientInfo": map[string]any{"name": "claver-agent", "title": "Claver", "version": "1"},
	}); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	if err := c.notify("initialized", map[string]any{}); err != nil {
		return err
	}
	policy := codexApprovalPolicy(spec.RunMode)
	c.mu.Lock()
	c.approvalPolicy = policy
	c.mu.Unlock()

	method := "thread/start"
	params := map[string]any{
		"cwd":            spec.WorkDir,
		"approvalPolicy": policy,
		"sandbox":        codexSandbox(spec.RunMode),
	}
	switch {
	case spec.ResumeAgentSessionID != "" && spec.Fork:
		// Fork branches a new thread off the prior one; the original is untouched.
		method = "thread/fork"
		params = map[string]any{
			"threadId":       spec.ResumeAgentSessionID,
			"approvalPolicy": policy,
			"sandbox":        codexSandbox(spec.RunMode),
		}
	case spec.ResumeAgentSessionID != "":
		// Resume reloads the prior thread and continues it in place.
		method = "thread/resume"
		params = map[string]any{
			"threadId":       spec.ResumeAgentSessionID,
			"approvalPolicy": policy,
			"sandbox":        codexSandbox(spec.RunMode),
		}
	}
	res, err := c.call(ctx, method, params)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	var r struct {
		Thread struct {
			ID string `json:"id"`
		} `json:"thread"`
	}
	if err := json.Unmarshal(res, &r); err != nil || r.Thread.ID == "" {
		return fmt.Errorf("%s returned no thread id", method)
	}
	c.mu.Lock()
	c.threadID = r.Thread.ID
	c.mu.Unlock()
	if spec.OnAgentSession != nil {
		spec.OnAgentSession(r.Thread.ID)
	}
	return nil
}

// sendPrompt opens a new turn carrying the user's text.
func (c *codexConn) sendPrompt(ctx context.Context, prompt string) error {
	c.mu.Lock()
	tid := c.threadID
	policy := c.approvalPolicy
	c.mu.Unlock()
	if tid == "" {
		return errors.New("codex thread not started")
	}
	params := map[string]any{
		"threadId": tid,
		"input":    []map[string]any{{"type": "text", "text": prompt}},
	}
	if policy != "" {
		params["approvalPolicy"] = policy
	}
	res, err := c.call(ctx, "turn/start", params)
	if err != nil {
		return err
	}
	var r struct {
		Turn struct {
			ID string `json:"id"`
		} `json:"turn"`
	}
	if json.Unmarshal(res, &r) == nil && r.Turn.ID != "" {
		c.mu.Lock()
		c.turnID = r.Turn.ID
		c.mu.Unlock()
	}
	return nil
}

func (c *codexConn) interrupt(ctx context.Context) error {
	c.mu.Lock()
	tid, turn := c.threadID, c.turnID
	c.mu.Unlock()
	if tid == "" || turn == "" {
		return nil // nothing in flight
	}
	_, err := c.call(ctx, "turn/interrupt", map[string]any{"threadId": tid, "turnId": turn})
	return err
}

// setMode adjusts the approval policy applied to subsequent turns. Codex has no
// plan-mode gate, so plan/default/acceptEdits all map to interactive approvals
// and only yolo disables them.
func (c *codexConn) setMode(mode string) {
	c.mu.Lock()
	c.approvalPolicy = codexApprovalPolicyForMode(mode)
	c.mu.Unlock()
}

// approve answers a pending exec/patch approval request with the decision mapped
// to the form (legacy ReviewDecision vs. v2 accept/decline) the request expects.
func (c *codexConn) approve(requestID, decision string) error {
	c.reqMu.Lock()
	method := c.approvalMethod[requestID]
	rawID := c.approvalRawID[requestID]
	delete(c.approvalMethod, requestID)
	delete(c.approvalRawID, requestID)
	c.reqMu.Unlock()
	if rawID == nil {
		return store.ErrNotFound
	}
	return c.writeJSON(map[string]any{
		"jsonrpc": "2.0",
		"id":      rawID,
		"result":  map[string]any{"decision": codexDecision(method, decision)},
	})
}

// codexDecision maps a normalized decision to the codex decision value the given
// approval method expects. The v2 item/* approvals use accept/acceptForSession/
// decline; the legacy exec/patch approvals use the ReviewDecision strings.
func codexDecision(method, decision string) string {
	v2 := method == codexMethodCmdApproval || method == codexMethodFileApproval
	switch decision {
	case DecisionAllowAlways:
		if v2 {
			return "acceptForSession"
		}
		return "approved_for_session"
	case DecisionDeny:
		if v2 {
			return "decline"
		}
		return "denied"
	default: // allow
		if v2 {
			return "accept"
		}
		return "approved"
	}
}

func codexApprovalPolicy(runMode string) string {
	if normalizeRunMode(runMode) == "yolo" {
		return "never"
	}
	return "on-request"
}

func codexApprovalPolicyForMode(mode string) string {
	if mode == ModeYolo {
		return "never"
	}
	return "on-request"
}

func codexSandbox(runMode string) string {
	if normalizeRunMode(runMode) == "yolo" {
		return "danger-full-access"
	}
	return "workspace-write"
}

// CodexStructuredRuntime runs each session's `codex app-server` as a child
// process driven over JSON-RPC. It implements Runtime for the structured
// transport (agent == "codex").
type CodexStructuredRuntime struct {
	ExtraPath string
	HomeDir   string
	Secrets   func(agent string) map[string]string

	mu    sync.Mutex
	procs map[string]*codexProc
}

type codexProc struct {
	conn     *codexConn
	cancel   context.CancelFunc
	stdin    io.WriteCloser
	stopping atomic.Bool
}

func NewCodexStructuredRuntime(extraPath, homeDir string, secrets func(string) map[string]string) *CodexStructuredRuntime {
	return &CodexStructuredRuntime{
		ExtraPath: extraPath,
		HomeDir:   homeDir,
		Secrets:   secrets,
		procs:     make(map[string]*codexProc),
	}
}

func (r *CodexStructuredRuntime) get(sessionID string) *codexProc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.procs[sessionID]
}

func (r *CodexStructuredRuntime) Start(ctx context.Context, spec RuntimeSpec) error {
	if spec.Agent != "codex" {
		return ErrBadAgent
	}
	if spec.Emit == nil {
		return errors.New("structured runtime requires RuntimeSpec.Emit")
	}
	if err := os.MkdirAll(spec.WorkDir, 0o700); err != nil {
		return err
	}
	if err := ensureAgentHomeDirs(r.HomeDir); err != nil {
		return err
	}

	pctx, cancel := context.WithCancel(context.Background())
	bin, err := resolveAgentBinary("codex", r.ExtraPath)
	if err != nil {
		cancel()
		return fmt.Errorf("locate codex: %w", err)
	}
	cmd := exec.CommandContext(pctx, bin, "app-server")
	cmd.Dir = spec.WorkDir
	cmd.Env = r.processEnv()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start codex: %w", err)
	}

	sink := structuredSink{sessionID: spec.SessionID, emit: spec.Emit, ephemeral: spec.EmitEphemeral}
	conn := newCodexConn(sink, stdin)
	proc := &codexProc{conn: conn, cancel: cancel, stdin: stdin}
	r.mu.Lock()
	r.procs[spec.SessionID] = proc
	r.mu.Unlock()

	go io.Copy(io.Discard, stderr) //nolint:errcheck // drain so the pipe never blocks the child
	go conn.run(stdout)
	go func() {
		_ = cmd.Wait()
		r.onExit(spec.SessionID, proc)
	}()

	// The thread must exist before the first prompt; do it synchronously.
	// Non-fatal: a failure still lets later error events reach the client.
	if err := conn.handshake(pctx, spec); err != nil {
		sink.publishError("codex init: "+err.Error(), false)
	}
	return nil
}

func (r *CodexStructuredRuntime) onExit(sessionID string, proc *codexProc) {
	r.mu.Lock()
	if r.procs[sessionID] == proc {
		delete(r.procs, sessionID)
	}
	r.mu.Unlock()
	if !proc.stopping.Load() {
		proc.conn.sink.publishError("agent process exited", true)
	}
}

func (r *CodexStructuredRuntime) SendPrompt(ctx context.Context, sessionID, prompt string) error {
	p := r.get(sessionID)
	if p == nil {
		return store.ErrNotFound
	}
	return p.conn.sendPrompt(ctx, prompt)
}

// SendInput is a no-op on the structured transport (there is no raw pty).
func (r *CodexStructuredRuntime) SendInput(context.Context, string, string) error { return nil }

func (r *CodexStructuredRuntime) Interrupt(ctx context.Context, sessionID string) error {
	p := r.get(sessionID)
	if p == nil {
		return store.ErrNotFound
	}
	return p.conn.interrupt(ctx)
}

// Resize is a no-op on the structured transport (there is no TUI grid).
func (r *CodexStructuredRuntime) Resize(context.Context, string, int, int) error { return nil }

func (r *CodexStructuredRuntime) Stop(_ context.Context, sessionID string) error {
	p := r.get(sessionID)
	if p == nil {
		return nil
	}
	p.stopping.Store(true)
	_ = p.stdin.Close() // EOF ends the conversation; cancel kills a stuck child
	p.cancel()
	r.mu.Lock()
	delete(r.procs, sessionID)
	r.mu.Unlock()
	return nil
}

// Attach cannot reattach a structured session: the child process died with the
// agent. Rehydrate treats the error as "skip", and the reaper marks it ended.
func (r *CodexStructuredRuntime) Attach(context.Context, RuntimeSpec) error {
	return errors.New("structured sessions cannot be reattached")
}

// Capture / CaptureVisible have no meaning without a pane.
func (r *CodexStructuredRuntime) Capture(context.Context, string) (string, error) {
	return "", nil
}
func (r *CodexStructuredRuntime) CaptureVisible(context.Context, string) (string, error) {
	return "", nil
}

func (r *CodexStructuredRuntime) Alive(_ context.Context, sessionID string) bool {
	return r.get(sessionID) != nil
}

func (r *CodexStructuredRuntime) SendApproval(_ context.Context, sessionID, requestID, decision, _ string) error {
	p := r.get(sessionID)
	if p == nil {
		return store.ErrNotFound
	}
	return p.conn.approve(requestID, decision)
}

func (r *CodexStructuredRuntime) SetMode(_ context.Context, sessionID, mode string) error {
	p := r.get(sessionID)
	if p == nil {
		return store.ErrNotFound
	}
	p.conn.setMode(mode)
	return nil
}

func (r *CodexStructuredRuntime) processEnv() []string {
	env := agentEnv(r.ExtraPath, r.HomeDir)
	if r.Secrets != nil {
		for k, v := range r.Secrets("codex") {
			env = append(env, k+"="+v)
		}
	}
	return env
}
