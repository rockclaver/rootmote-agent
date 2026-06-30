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

	"github.com/rockclaver/claver-agent/internal/store"
)

// codex_exec.go is the fallback structured runtime for environments where
// `codex app-server` is unavailable. It drives `codex exec --json`, whose JSONL
// event stream is a DISTINCT (flattened, snake_case) schema from the app-server
// protocol, and translates it into the same normalized events. Wire shapes are
// source-verified from codex-rs/exec/src/exec_events.rs (codex-cli 0.142.4).
// One `codex exec` process runs per turn; follow-ups resume by thread id.

// codexExecItem is one ThreadItem of the exec JSONL stream (snake_case).
type codexExecItem struct {
	Type             string `json:"type"`
	ID               string `json:"id"`
	Text             string `json:"text"`              // agent_message / reasoning
	Command          string `json:"command"`           // command_execution
	AggregatedOutput string `json:"aggregated_output"` // command_execution
	Status           string `json:"status"`            // *_execution / file_change / mcp_tool_call
	Changes          []struct {
		Path string `json:"path"`
		Kind string `json:"kind"`
	} `json:"changes"` // file_change
	Server    string          `json:"server"`    // mcp_tool_call
	Tool      string          `json:"tool"`      // mcp_tool_call / collab_tool_call
	Arguments json.RawMessage `json:"arguments"` // mcp_tool_call
	Query     string          `json:"query"`     // web_search
	Items     []struct {
		Text      string `json:"text"`
		Completed bool   `json:"completed"`
	} `json:"items"` // todo_list
	Message string `json:"message"` // error item
}

// translateCodexExecLine converts one `codex exec --json` event line into
// normalized events. Pure and table-tested against fixtures/codex-exec/*.jsonl.
func translateCodexExecLine(line []byte) ([]translated, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil, nil
	}
	var env struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, err
	}
	switch env.Type {
	case "turn.started":
		return []translated{{Type: EvTurn, Payload: Turn{State: TurnStarted}}}, nil
	case "turn.completed":
		return translateCodexExecTurnCompleted(line)
	case "turn.failed":
		return translateCodexExecTurnFailed(line)
	case "error":
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(line, &e)
		return []translated{{Type: EvError, Payload: ErrorEvent{Message: e.Message, Fatal: false}}}, nil
	case "item.started", "item.updated", "item.completed":
		return translateCodexExecItem(line, env.Type == "item.completed")
	default: // thread.started and any unknown event yield nothing
		return nil, nil
	}
}

func translateCodexExecTurnCompleted(line []byte) ([]translated, error) {
	var p struct {
		Usage struct {
			InputTokens       int `json:"input_tokens"`
			CachedInputTokens int `json:"cached_input_tokens"`
			OutputTokens      int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(line, &p); err != nil {
		return nil, err
	}
	var out []translated
	if p.Usage.InputTokens != 0 || p.Usage.OutputTokens != 0 || p.Usage.CachedInputTokens != 0 {
		out = append(out, translated{Type: EvUsage, Payload: Usage{
			Input: p.Usage.InputTokens, Output: p.Usage.OutputTokens, Cache: p.Usage.CachedInputTokens,
		}})
	}
	out = append(out, translated{Type: EvTurn, Payload: Turn{State: TurnComplete, StopReason: "completed"}})
	return out, nil
}

func translateCodexExecTurnFailed(line []byte) ([]translated, error) {
	var p struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &p); err != nil {
		return nil, err
	}
	msg := p.Error.Message
	if msg == "" {
		msg = "codex turn failed"
	}
	return []translated{
		{Type: EvError, Payload: ErrorEvent{Message: msg, Fatal: false}},
		{Type: EvTurn, Payload: Turn{State: TurnComplete, StopReason: "failed"}},
	}, nil
}

func translateCodexExecItem(line []byte, completed bool) ([]translated, error) {
	var p struct {
		Item codexExecItem `json:"item"`
	}
	if err := json.Unmarshal(line, &p); err != nil {
		return nil, err
	}
	it := p.Item
	switch it.Type {
	case "agent_message":
		if !completed || it.Text == "" {
			return nil, nil
		}
		return []translated{{Type: EvMessage, Payload: Message{
			Role: "assistant", Text: it.Text, Blocks: []MessageBlock{{Kind: "text", Text: it.Text}},
		}}}, nil
	case "reasoning":
		if !completed || it.Text == "" {
			return nil, nil
		}
		return []translated{{Type: EvReasoning, Payload: Reasoning{Text: it.Text}}}, nil
	case "command_execution":
		args, _ := json.Marshal(map[string]any{"command": it.Command})
		tc := ToolCall{CallID: it.ID, Name: "shell", Args: args, Status: codexToolStatus(it.Status)}
		if completed {
			tc.Result = it.AggregatedOutput
		}
		return []translated{{Type: EvToolCall, Payload: tc}}, nil
	case "file_change":
		// The exec stream omits the unified diff (only {path, kind}); render the
		// changed-file set as a tool call without diffs.
		paths := make([]string, 0, len(it.Changes))
		for _, ch := range it.Changes {
			paths = append(paths, ch.Path)
		}
		args, _ := json.Marshal(map[string]any{"paths": paths})
		return []translated{{Type: EvToolCall, Payload: ToolCall{
			CallID: it.ID, Name: "apply_patch", Args: args, Status: codexToolStatus(it.Status),
		}}}, nil
	case "mcp_tool_call":
		tc := ToolCall{CallID: it.ID, Name: codexExecMcpName(it), Args: it.Arguments, Status: codexToolStatus(it.Status)}
		return []translated{{Type: EvToolCall, Payload: tc}}, nil
	case "web_search":
		args, _ := json.Marshal(map[string]any{"query": it.Query})
		return []translated{{Type: EvToolCall, Payload: ToolCall{
			CallID: it.ID, Name: "web_search", Args: args, Status: codexToolStatus(it.Status),
		}}}, nil
	case "collab_tool_call":
		name := "collab"
		if it.Tool != "" {
			name = "collab." + it.Tool
		}
		return []translated{{Type: EvToolCall, Payload: ToolCall{
			CallID: it.ID, Name: name, Status: codexToolStatus(it.Status),
		}}}, nil
	case "todo_list":
		items := make([]PlanItem, 0, len(it.Items))
		for _, td := range it.Items {
			status := "pending"
			if td.Completed {
				status = "completed"
			}
			items = append(items, PlanItem{Title: td.Text, Status: status})
		}
		if len(items) == 0 {
			return nil, nil
		}
		return []translated{{Type: EvPlan, Payload: Plan{Items: items, Gating: false}}}, nil
	case "error":
		if !completed {
			return nil, nil
		}
		return []translated{{Type: EvError, Payload: ErrorEvent{Message: it.Message, Fatal: false}}}, nil
	default:
		return nil, nil
	}
}

func codexExecMcpName(it codexExecItem) string {
	if it.Server != "" && it.Tool != "" {
		return it.Server + "." + it.Tool
	}
	if it.Tool != "" {
		return it.Tool
	}
	return "mcp_tool"
}

// codexExecArgs builds the argv for one `codex exec` turn. The first turn sets
// the sandbox/approval policy; follow-ups resume the thread and inherit it.
func codexExecArgs(runMode, workDir, resume, prompt string) []string {
	if resume != "" {
		return []string{"exec", "resume", resume, "--json", "--color", "never", "--skip-git-repo-check", "-C", workDir, prompt}
	}
	args := []string{"exec", "--json", "--color", "never", "--skip-git-repo-check", "-C", workDir}
	if normalizeRunMode(runMode) == "yolo" {
		args = append(args, "--dangerously-bypass-approvals-and-sandbox")
	} else {
		args = append(args, "-s", "workspace-write")
	}
	return append(args, prompt)
}

// CodexExecRuntime is the fallback structured runtime: it spawns `codex exec
// --json` once per prompt rather than holding a long-lived app-server process.
// Approvals are not interactive in exec mode, so it runs sandboxed (manual) or
// bypassed (yolo); SendApproval/SetMode have no live turn to act on.
type CodexExecRuntime struct {
	ExtraPath string
	HomeDir   string
	Secrets   func(agent string) map[string]string

	mu       sync.Mutex
	sessions map[string]*codexExecSession
}

type codexExecSession struct {
	sink    structuredSink
	workDir string

	mu             sync.Mutex
	runMode        string
	threadID       string
	cancel         context.CancelFunc
	running        bool
	onAgentSession func(string)
}

func NewCodexExecRuntime(extraPath, homeDir string, secrets func(string) map[string]string) *CodexExecRuntime {
	return &CodexExecRuntime{
		ExtraPath: extraPath,
		HomeDir:   homeDir,
		Secrets:   secrets,
		sessions:  make(map[string]*codexExecSession),
	}
}

func (r *CodexExecRuntime) get(sessionID string) *codexExecSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[sessionID]
}

func (r *CodexExecRuntime) Start(_ context.Context, spec RuntimeSpec) error {
	if spec.Agent != "codex" {
		return ErrBadAgent
	}
	if spec.Emit == nil {
		return errors.New("structured runtime requires RuntimeSpec.Emit")
	}
	if spec.Fork {
		// `codex exec` has no fork primitive; resuming it would mutate the
		// original thread, so forking is refused on the exec fallback.
		return ErrForkUnsupported
	}
	if err := os.MkdirAll(spec.WorkDir, 0o700); err != nil {
		return err
	}
	if err := ensureAgentHomeDirs(r.HomeDir); err != nil {
		return err
	}
	r.mu.Lock()
	r.sessions[spec.SessionID] = &codexExecSession{
		sink:           structuredSink{sessionID: spec.SessionID, emit: spec.Emit, ephemeral: spec.EmitEphemeral},
		workDir:        spec.WorkDir,
		runMode:        spec.RunMode,
		threadID:       spec.ResumeAgentSessionID,
		onAgentSession: spec.OnAgentSession,
	}
	r.mu.Unlock()
	if spec.ResumeAgentSessionID != "" && spec.OnAgentSession != nil {
		spec.OnAgentSession(spec.ResumeAgentSessionID)
	}
	return nil
}

func (r *CodexExecRuntime) SendPrompt(_ context.Context, sessionID, prompt string) error {
	s := r.get(sessionID)
	if s == nil {
		return store.ErrNotFound
	}
	return s.runTurn(r, prompt)
}

func (s *codexExecSession) runTurn(r *CodexExecRuntime, prompt string) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("a turn is already running")
	}
	pctx, cancel := context.WithCancel(context.Background())
	bin, err := resolveAgentBinary("codex", r.ExtraPath)
	if err != nil {
		cancel()
		s.mu.Unlock()
		return fmt.Errorf("locate codex: %w", err)
	}
	args := codexExecArgs(s.runMode, s.workDir, s.threadID, prompt)
	cmd := exec.CommandContext(pctx, bin, args...)
	cmd.Dir = s.workDir
	cmd.Env = r.processEnv()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		s.mu.Unlock()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		s.mu.Unlock()
		return err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		s.mu.Unlock()
		return fmt.Errorf("start codex exec: %w", err)
	}
	s.cancel = cancel
	s.running = true
	s.mu.Unlock()

	go io.Copy(io.Discard, stderr) //nolint:errcheck // drain so the pipe never blocks the child
	go func() {
		s.readStream(stdout)
		_ = cmd.Wait()
		s.mu.Lock()
		s.running = false
		s.cancel = nil
		s.mu.Unlock()
	}()
	return nil
}

func (s *codexExecSession) readStream(r io.Reader) {
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			s.captureThread(line)
			if evs, e := translateCodexExecLine(line); e == nil {
				for _, tr := range evs {
					s.sink.publish(tr)
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// captureThread records the thread id from thread.started so the next prompt can
// resume the same session and keep context.
func (s *codexExecSession) captureThread(line []byte) {
	var p struct {
		Type     string `json:"type"`
		ThreadID string `json:"thread_id"`
	}
	if json.Unmarshal(line, &p) == nil && p.Type == "thread.started" && p.ThreadID != "" {
		s.mu.Lock()
		s.threadID = p.ThreadID
		cb := s.onAgentSession
		s.mu.Unlock()
		if cb != nil {
			cb(p.ThreadID)
		}
	}
}

// SendInput is a no-op on the structured transport (there is no raw pty).
func (r *CodexExecRuntime) SendInput(context.Context, string, string) error { return nil }

func (r *CodexExecRuntime) Interrupt(_ context.Context, sessionID string) error {
	s := r.get(sessionID)
	if s == nil {
		return store.ErrNotFound
	}
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// Resize is a no-op on the structured transport (there is no TUI grid).
func (r *CodexExecRuntime) Resize(context.Context, string, int, int) error { return nil }

func (r *CodexExecRuntime) Stop(_ context.Context, sessionID string) error {
	s := r.get(sessionID)
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	r.mu.Lock()
	delete(r.sessions, sessionID)
	r.mu.Unlock()
	return nil
}

// Attach cannot reattach: an exec turn is a transient child of the agent.
func (r *CodexExecRuntime) Attach(context.Context, RuntimeSpec) error {
	return errors.New("structured sessions cannot be reattached")
}

func (r *CodexExecRuntime) Capture(context.Context, string) (string, error) {
	return "", nil
}

func (r *CodexExecRuntime) Alive(_ context.Context, sessionID string) bool {
	return r.get(sessionID) != nil
}

// SendApproval is a no-op: exec mode runs non-interactively (no approval prompts
// are emitted), so there is no pending request to answer.
func (r *CodexExecRuntime) SendApproval(context.Context, string, string, string, string) error {
	return nil
}

// SetMode updates the policy applied to the next exec turn (yolo vs sandboxed).
func (r *CodexExecRuntime) SetMode(_ context.Context, sessionID, mode string) error {
	s := r.get(sessionID)
	if s == nil {
		return store.ErrNotFound
	}
	s.mu.Lock()
	if mode == ModeYolo {
		s.runMode = "yolo"
	} else {
		s.runMode = "manual"
	}
	s.mu.Unlock()
	return nil
}

func (r *CodexExecRuntime) processEnv() []string {
	env := agentEnv(r.ExtraPath, r.HomeDir)
	if r.Secrets != nil {
		for k, v := range r.Secrets("codex") {
			env = append(env, k+"="+v)
		}
	}
	return env
}
