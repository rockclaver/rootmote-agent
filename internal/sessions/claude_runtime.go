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
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/rockclaver/claver-agent/internal/store"
)

// claude_runtime.go drives the `claude` CLI over its stream-json stdio protocol
// (the structured transport), translating its output into normalized events and
// answering its permission control-requests. The wire format is source-verified
// from @anthropic-ai/claude-agent-sdk; see plans/structured-agent-ui.md.

// controlTimeout bounds how long we wait for the CLI to answer a parent-issued
// control_request (initialize/interrupt/set_permission_mode).
const controlTimeout = 60 * time.Second

// claudeConn is the protocol engine over a CLI process's stdio. It is split from
// process management so it can be unit-tested over in-memory pipes.
type claudeConn struct {
	sink  structuredSink
	stdin io.Writer

	writeMu sync.Mutex

	reqMu     sync.Mutex
	reqN      int
	pending   map[string]chan json.RawMessage // parent->CLI request_id -> response
	approvals map[string]json.RawMessage      // CLI can_use_tool request_id -> original input
	tools     map[string]string               // can_use_tool request_id -> tool name
	always    map[string]bool                 // tool name -> standing allow for this session
}

func newClaudeConn(sink structuredSink, stdin io.Writer) *claudeConn {
	return &claudeConn{
		sink:      sink,
		stdin:     stdin,
		pending:   make(map[string]chan json.RawMessage),
		approvals: make(map[string]json.RawMessage),
		tools:     make(map[string]string),
		always:    make(map[string]bool),
	}
}

// run reads NDJSON lines from the CLI's stdout until EOF, routing control
// messages and translating everything else into normalized events.
func (c *claudeConn) run(r io.Reader) {
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

func (c *claudeConn) handleLine(line []byte) {
	var env struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(line, &env) != nil {
		return
	}
	switch env.Type {
	case "control_response":
		c.routeControlResponse(line)
		return
	case "control_cancel_request":
		c.dropApproval(line)
		return
	case "control_request":
		// Record the tool input so SendApproval can echo it back as updatedInput.
		c.recordApproval(line)
		if c.maybeAutoAllow(line) {
			return // a standing allow_always rule answered it; no prompt emitted.
		}
	}
	evs, err := translateClaudeLine(line)
	if err != nil {
		return // malformed line: log-and-skip semantics
	}
	for _, tr := range evs {
		c.sink.publish(tr)
	}
}

func (c *claudeConn) recordApproval(line []byte) {
	var cr struct {
		RequestID string `json:"request_id"`
		Request   struct {
			Subtype  string          `json:"subtype"`
			ToolName string          `json:"tool_name"`
			Input    json.RawMessage `json:"input"`
		} `json:"request"`
	}
	if json.Unmarshal(line, &cr) != nil || cr.Request.Subtype != "can_use_tool" {
		return
	}
	c.reqMu.Lock()
	c.approvals[cr.RequestID] = cr.Request.Input
	c.tools[cr.RequestID] = cr.Request.ToolName
	c.reqMu.Unlock()
}

func (c *claudeConn) dropApproval(line []byte) {
	var m struct {
		RequestID string `json:"request_id"`
	}
	if json.Unmarshal(line, &m) != nil {
		return
	}
	c.reqMu.Lock()
	delete(c.approvals, m.RequestID)
	delete(c.tools, m.RequestID)
	c.reqMu.Unlock()
}

// maybeAutoAllow answers a can_use_tool control_request immediately when a
// prior allow_always created a standing rule for its tool, so the user is not
// re-prompted for the same tool. Returns true if it consumed the request.
func (c *claudeConn) maybeAutoAllow(line []byte) bool {
	var cr struct {
		RequestID string `json:"request_id"`
		Request   struct {
			Subtype  string `json:"subtype"`
			ToolName string `json:"tool_name"`
		} `json:"request"`
	}
	if json.Unmarshal(line, &cr) != nil || cr.Request.Subtype != "can_use_tool" {
		return false
	}
	c.reqMu.Lock()
	allowed := c.always[cr.Request.ToolName]
	c.reqMu.Unlock()
	if !allowed {
		return false
	}
	_ = c.approve(cr.RequestID, DecisionAllow, "")
	return true
}

func (c *claudeConn) routeControlResponse(line []byte) {
	var m struct {
		Response json.RawMessage `json:"response"`
	}
	if json.Unmarshal(line, &m) != nil {
		return
	}
	var meta struct {
		RequestID string `json:"request_id"`
	}
	if json.Unmarshal(m.Response, &meta) != nil || meta.RequestID == "" {
		return
	}
	c.reqMu.Lock()
	ch := c.pending[meta.RequestID]
	delete(c.pending, meta.RequestID)
	c.reqMu.Unlock()
	if ch != nil {
		ch <- m.Response
	}
}

func (c *claudeConn) writeJSON(v any) error {
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

// sendControl issues a parent->CLI control_request and waits for its response.
func (c *claudeConn) sendControl(ctx context.Context, request map[string]any) error {
	c.reqMu.Lock()
	c.reqN++
	id := fmt.Sprintf("req_%d", c.reqN)
	ch := make(chan json.RawMessage, 1)
	c.pending[id] = ch
	c.reqMu.Unlock()

	if err := c.writeJSON(map[string]any{
		"type":       "control_request",
		"request_id": id,
		"request":    request,
	}); err != nil {
		c.reqMu.Lock()
		delete(c.pending, id)
		c.reqMu.Unlock()
		return err
	}

	select {
	case resp := <-ch:
		var r struct {
			Subtype string `json:"subtype"`
			Error   string `json:"error"`
		}
		_ = json.Unmarshal(resp, &r)
		if r.Subtype == "error" {
			if r.Error == "" {
				r.Error = "control request failed"
			}
			return errors.New(r.Error)
		}
		return nil
	case <-time.After(controlTimeout):
		c.reqMu.Lock()
		delete(c.pending, id)
		c.reqMu.Unlock()
		return fmt.Errorf("control request %q timed out", request["subtype"])
	case <-ctx.Done():
		c.reqMu.Lock()
		delete(c.pending, id)
		c.reqMu.Unlock()
		return ctx.Err()
	}
}

func (c *claudeConn) initialize(ctx context.Context) error {
	return c.sendControl(ctx, map[string]any{"subtype": "initialize", "hooks": nil})
}

func (c *claudeConn) interrupt(ctx context.Context) error {
	return c.sendControl(ctx, map[string]any{"subtype": "interrupt"})
}

func (c *claudeConn) setMode(ctx context.Context, mode string) error {
	return c.sendControl(ctx, map[string]any{"subtype": "set_permission_mode", "mode": mode})
}

// sendUser writes a user turn to the CLI in streaming-input mode.
func (c *claudeConn) sendUser(prompt string) error {
	return c.writeJSON(map[string]any{
		"type":               "user",
		"session_id":         "",
		"parent_tool_use_id": nil,
		"message":            map[string]any{"role": "user", "content": prompt},
	})
}

// approve answers a pending can_use_tool control_request. allow/allow_always
// echo the original tool input as updatedInput; deny carries a message.
func (c *claudeConn) approve(requestID, decision, note string) error {
	c.reqMu.Lock()
	input := c.approvals[requestID]
	delete(c.approvals, requestID)
	tool := c.tools[requestID]
	delete(c.tools, requestID)
	if decision == DecisionAllowAlways && tool != "" {
		c.always[tool] = true
	}
	c.reqMu.Unlock()

	var respData map[string]any
	if decision == DecisionDeny {
		msg := note
		if msg == "" {
			msg = "Denied by user"
		}
		respData = map[string]any{"behavior": "deny", "message": msg}
	} else {
		if len(input) == 0 {
			input = json.RawMessage("{}")
		}
		// allow and allow_always both allow the call; allow_always additionally
		// recorded a session-scoped standing rule above (see c.always).
		respData = map[string]any{"behavior": "allow", "updatedInput": input}
	}
	return c.writeJSON(map[string]any{
		"type": "control_response",
		"response": map[string]any{
			"subtype":    "success",
			"request_id": requestID,
			"response":   respData,
		},
	})
}

// ClaudeStructuredRuntime runs each session's `claude` CLI as a child process
// driven over the stream-json protocol. It implements Runtime for the
// structured transport (agent == "claude").
type ClaudeStructuredRuntime struct {
	ExtraPath string
	HomeDir   string
	Secrets   func(agent string) map[string]string

	mu    sync.Mutex
	procs map[string]*claudeProc
}

type claudeProc struct {
	conn     *claudeConn
	cancel   context.CancelFunc
	stdin    io.WriteCloser
	stopping atomic.Bool
}

func NewClaudeStructuredRuntime(extraPath, homeDir string, secrets func(string) map[string]string) *ClaudeStructuredRuntime {
	return &ClaudeStructuredRuntime{
		ExtraPath: extraPath,
		HomeDir:   homeDir,
		Secrets:   secrets,
		procs:     make(map[string]*claudeProc),
	}
}

func (r *ClaudeStructuredRuntime) get(sessionID string) *claudeProc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.procs[sessionID]
}

func (r *ClaudeStructuredRuntime) Start(ctx context.Context, spec RuntimeSpec) error {
	if spec.Agent != "claude" {
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
	claudeSessionID := spec.ClaudeSessionID
	args := []string{
		"--print",
		"--input-format", "stream-json",
		"--output-format", "stream-json",
		"--verbose",
		"--include-partial-messages",
	}
	switch {
	case spec.ResumeAgentSessionID != "" && spec.Fork:
		// Fork: branch a brand-new conversation (its own --session-id) off the
		// prior one. The original session id is left untouched.
		claudeSessionID = uuid.NewString()
		args = append(args, "--resume", spec.ResumeAgentSessionID, "--fork-session", "--session-id", claudeSessionID)
	case spec.ResumeAgentSessionID != "":
		// Resume: continue the same conversation id in place.
		claudeSessionID = spec.ResumeAgentSessionID
		args = append(args, "--resume", spec.ResumeAgentSessionID)
	default:
		if claudeSessionID == "" {
			claudeSessionID = uuid.NewString()
		}
		args = append(args, "--session-id", claudeSessionID)
	}
	args = append(args,
		"--permission-mode", claudePermissionForRunMode(spec.RunMode),
		"--permission-prompt-tool", "stdio",
	)
	if dir := claudeSkillsDir(r.HomeDir); dir != "" {
		args = append(args, "--add-dir", dir)
	}

	// Independent context so the child outlives Start's caller ctx; Stop cancels.
	pctx, cancel := context.WithCancel(context.Background())
	bin, err := resolveAgentBinary("claude", r.ExtraPath)
	if err != nil {
		cancel()
		return fmt.Errorf("locate claude: %w", err)
	}
	cmd := exec.CommandContext(pctx, bin, args...)
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
		return fmt.Errorf("start claude: %w", err)
	}

	sink := structuredSink{sessionID: spec.SessionID, emit: spec.Emit, ephemeral: spec.EmitEphemeral}
	conn := newClaudeConn(sink, stdin)
	proc := &claudeProc{conn: conn, cancel: cancel, stdin: stdin}
	r.mu.Lock()
	r.procs[spec.SessionID] = proc
	r.mu.Unlock()
	if spec.OnAgentSession != nil {
		spec.OnAgentSession(claudeSessionID)
	}

	go io.Copy(io.Discard, stderr) //nolint:errcheck // drain so the pipe never blocks the child
	go conn.run(stdout)
	go func() {
		_ = cmd.Wait()
		r.onExit(spec.SessionID, proc)
	}()

	// Streaming mode requires an initialize handshake before the first turn.
	// Non-fatal: a failure still lets result/error events flow to the client.
	if err := conn.initialize(pctx); err != nil {
		sink.publishError("initialize: "+err.Error(), false)
	}
	return nil
}

func (r *ClaudeStructuredRuntime) onExit(sessionID string, proc *claudeProc) {
	r.mu.Lock()
	if r.procs[sessionID] == proc {
		delete(r.procs, sessionID)
	}
	r.mu.Unlock()
	if !proc.stopping.Load() {
		proc.conn.sink.publishError("agent process exited", true)
	}
}

func (r *ClaudeStructuredRuntime) SendPrompt(_ context.Context, sessionID, prompt string) error {
	p := r.get(sessionID)
	if p == nil {
		return store.ErrNotFound
	}
	return p.conn.sendUser(prompt)
}

// SendInput is a no-op on the structured transport (there is no raw pty).
func (r *ClaudeStructuredRuntime) SendInput(context.Context, string, string) error { return nil }

func (r *ClaudeStructuredRuntime) Interrupt(ctx context.Context, sessionID string) error {
	p := r.get(sessionID)
	if p == nil {
		return store.ErrNotFound
	}
	return p.conn.interrupt(ctx)
}

// Resize is a no-op on the structured transport (there is no TUI grid).
func (r *ClaudeStructuredRuntime) Resize(context.Context, string, int, int) error { return nil }

func (r *ClaudeStructuredRuntime) Stop(_ context.Context, sessionID string) error {
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
func (r *ClaudeStructuredRuntime) Attach(context.Context, RuntimeSpec) error {
	return errors.New("structured sessions cannot be reattached")
}

// Capture has no meaning without a pane.
func (r *ClaudeStructuredRuntime) Capture(context.Context, string) (string, error) {
	return "", nil
}

func (r *ClaudeStructuredRuntime) Alive(_ context.Context, sessionID string) bool {
	return r.get(sessionID) != nil
}

func (r *ClaudeStructuredRuntime) SendApproval(_ context.Context, sessionID, requestID, decision, note string) error {
	p := r.get(sessionID)
	if p == nil {
		return store.ErrNotFound
	}
	return p.conn.approve(requestID, decision, note)
}

func (r *ClaudeStructuredRuntime) SetMode(ctx context.Context, sessionID, mode string) error {
	p := r.get(sessionID)
	if p == nil {
		return store.ErrNotFound
	}
	return p.conn.setMode(ctx, claudePermissionForMode(mode))
}

func (r *ClaudeStructuredRuntime) processEnv() []string {
	env := agentEnv(r.ExtraPath, r.HomeDir)
	if r.Secrets != nil {
		for k, v := range r.Secrets("claude") {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// resolveAgentBinary finds the agent CLI, preferring extraPath (the agent's
// managed bin dir, e.g. /var/lib/claver/bin) over the ambient PATH. This is
// required because exec resolves a bare command name against the parent PATH,
// ignoring cmd.Env, so without it the system-wide CLI would shadow the
// provisioned one.
func resolveAgentBinary(name, extraPath string) (string, error) {
	if extraPath != "" {
		cand := filepath.Join(extraPath, name)
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand, nil
		}
	}
	return exec.LookPath(name)
}

// claudePermissionForRunMode maps the session run mode to a claude --permission-mode.
func claudePermissionForRunMode(runMode string) string {
	if normalizeRunMode(runMode) == "yolo" {
		return "bypassPermissions"
	}
	return "default"
}

// claudePermissionForMode maps a normalized mode (set_mode) to a claude permission mode.
func claudePermissionForMode(mode string) string {
	switch mode {
	case ModeYolo:
		return "bypassPermissions"
	case ModePlan:
		return "plan"
	case ModeAcceptEdits:
		return "acceptEdits"
	default:
		return "default"
	}
}

// routingRuntime dispatches Runtime calls to the terminal (tmux) runtime or a
// per-agent structured runtime, based on each session's transport. It lets the
// Manager keep a single Runtime while two implementations coexist.
type routingRuntime struct {
	terminal   Runtime
	structured map[string]Runtime
	lookup     func(sessionID string) (agent, transport string)
}

// NewRoutingRuntime builds a Runtime that routes by session transport. lookup
// resolves a session id to its (agent, transport); structured maps an agent
// name to its structured Runtime.
func NewRoutingRuntime(terminal Runtime, structured map[string]Runtime, lookup func(string) (string, string)) Runtime {
	return &routingRuntime{terminal: terminal, structured: structured, lookup: lookup}
}

func (r *routingRuntime) pick(sessionID string) Runtime {
	if r.lookup != nil {
		agent, transport := r.lookup(sessionID)
		if transport == TransportStructured {
			if rt, ok := r.structured[agent]; ok {
				return rt
			}
		}
	}
	return r.terminal
}

func (r *routingRuntime) forSpec(spec RuntimeSpec) Runtime {
	if spec.Transport == TransportStructured {
		if rt, ok := r.structured[spec.Agent]; ok {
			return rt
		}
	}
	return r.terminal
}

func (r *routingRuntime) Start(ctx context.Context, spec RuntimeSpec) error {
	return r.forSpec(spec).Start(ctx, spec)
}
func (r *routingRuntime) Attach(ctx context.Context, spec RuntimeSpec) error {
	return r.forSpec(spec).Attach(ctx, spec)
}
func (r *routingRuntime) SendPrompt(ctx context.Context, sessionID, prompt string) error {
	return r.pick(sessionID).SendPrompt(ctx, sessionID, prompt)
}
func (r *routingRuntime) SendInput(ctx context.Context, sessionID, data string) error {
	return r.pick(sessionID).SendInput(ctx, sessionID, data)
}
func (r *routingRuntime) Interrupt(ctx context.Context, sessionID string) error {
	return r.pick(sessionID).Interrupt(ctx, sessionID)
}
func (r *routingRuntime) Resize(ctx context.Context, sessionID string, cols, rows int) error {
	return r.pick(sessionID).Resize(ctx, sessionID, cols, rows)
}
func (r *routingRuntime) Stop(ctx context.Context, sessionID string) error {
	return r.pick(sessionID).Stop(ctx, sessionID)
}
func (r *routingRuntime) Capture(ctx context.Context, sessionID string) (string, error) {
	return r.pick(sessionID).Capture(ctx, sessionID)
}
func (r *routingRuntime) Alive(ctx context.Context, sessionID string) bool {
	return r.pick(sessionID).Alive(ctx, sessionID)
}
func (r *routingRuntime) SendApproval(ctx context.Context, sessionID, requestID, decision, note string) error {
	return r.pick(sessionID).SendApproval(ctx, sessionID, requestID, decision, note)
}
func (r *routingRuntime) SetMode(ctx context.Context, sessionID, mode string) error {
	return r.pick(sessionID).SetMode(ctx, sessionID, mode)
}
