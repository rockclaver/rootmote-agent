// Package sessions owns AI-agent panes, persisted stream replay, and the
// narrow command surface exposed to mobile clients.
package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/store"
)

var (
	ErrBadAgent     = errors.New("agent must be claude or codex")
	ErrBadMode      = errors.New("run mode must be manual or yolo")
	ErrAuthRequired = errors.New("agent cli is not authenticated")
	ErrNotFound     = store.ErrNotFound
)

type Runtime interface {
	Start(ctx context.Context, spec RuntimeSpec) error
	Attach(ctx context.Context, spec RuntimeSpec) error
	SendPrompt(ctx context.Context, sessionID, prompt string) error
	SendInput(ctx context.Context, sessionID, data string) error
	Interrupt(ctx context.Context, sessionID string) error
	Resize(ctx context.Context, sessionID string, cols, rows int) error
	Stop(ctx context.Context, sessionID string) error
	Capture(ctx context.Context, sessionID string) (string, error)
	Alive(ctx context.Context, sessionID string) bool
}

type RuntimeSpec struct {
	SessionID string
	Agent     string
	RunMode   string
	WorkDir   string
	Output    io.Writer
}

type Manager struct {
	Store    *store.Store
	Projects *projects.Manager
	Runtime  Runtime
	Now      func() time.Time
	IDGen    func() string
	AuthOK   func(context.Context, string) bool

	mu   sync.Mutex
	subs map[string]map[*subscriber]struct{}
}

// subscriber is one live consumer of a session's event stream. ch is never
// closed; teardown signals via done instead, which lets fanout deliver outside
// the manager lock without risking a send on a closed channel.
type subscriber struct {
	ch   chan store.SessionEvent
	done chan struct{}
}

func New(st *store.Store, projectMgr *projects.Manager, runtime Runtime) *Manager {
	return &Manager{
		Store: st, Projects: projectMgr, Runtime: runtime, Now: time.Now, IDGen: randomID,
		subs: make(map[string]map[*subscriber]struct{}),
	}
}

func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (m *Manager) Start(ctx context.Context, projectID, agent, runMode string) (store.Session, error) {
	if agent != "claude" && agent != "codex" {
		return store.Session{}, ErrBadAgent
	}
	runMode = normalizeRunMode(runMode)
	if runMode != "manual" && runMode != "yolo" {
		return store.Session{}, ErrBadMode
	}
	if m.AuthOK != nil && !m.AuthOK(ctx, agent) {
		return store.Session{}, ErrAuthRequired
	}
	if _, err := m.Projects.Get(projectID); err != nil {
		return store.Session{}, err
	}
	id := m.IDGen()
	sess := store.Session{ID: id, ProjectID: projectID, Agent: agent, StartedAt: m.Now()}
	if err := m.Store.CreateSession(sess); err != nil {
		return store.Session{}, err
	}
	w := &eventWriter{manager: m, sessionID: id, eventType: "stdout"}
	if err := m.Runtime.Start(ctx, RuntimeSpec{
		SessionID: id,
		Agent:     agent,
		RunMode:   runMode,
		WorkDir:   m.Projects.WorkspaceDir(projectID),
		Output:    w,
	}); err != nil {
		_ = m.Store.EndSession(id, m.Now())
		return store.Session{}, err
	}
	_, _ = m.Publish(store.SessionEvent{SessionID: id, Type: "lifecycle", Data: "started"})
	return sess, nil
}

func normalizeRunMode(mode string) string {
	if strings.TrimSpace(mode) == "" {
		return "manual"
	}
	return mode
}

func (m *Manager) SendPrompt(ctx context.Context, sessionID, prompt string) error {
	if strings.TrimSpace(prompt) == "" {
		return errors.New("prompt required")
	}
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return err
	}
	_, _ = m.Publish(store.SessionEvent{SessionID: sessionID, Type: "prompt", Data: prompt})
	return m.Runtime.SendPrompt(ctx, sessionID, prompt)
}

// SendInput forwards raw bytes (e.g. the arrow-key or mouse-wheel escape
// sequences the client's terminal emits when the user scrolls a full-screen
// TUI) straight into the pty. Unlike SendPrompt it neither appends Enter nor
// records a prompt event — it is a transparent keystroke channel.
func (m *Manager) SendInput(ctx context.Context, sessionID, data string) error {
	if data == "" {
		return nil
	}
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return err
	}
	return m.Runtime.SendInput(ctx, sessionID, data)
}

// Resize sets the session's pty grid so the agent TUI redraws for the client's
// actual viewport. Without this the pane stays at tmux's 80x24 default and
// cursor-addressed redraws land in the wrong cells on a narrower phone screen.
func (m *Manager) Resize(ctx context.Context, sessionID string, cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return err
	}
	return m.Runtime.Resize(ctx, sessionID, cols, rows)
}

func (m *Manager) Interrupt(ctx context.Context, sessionID string) error {
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return err
	}
	if err := m.Runtime.Interrupt(ctx, sessionID); err != nil {
		return err
	}
	_, _ = m.Publish(store.SessionEvent{SessionID: sessionID, Type: "lifecycle", Data: "interrupted"})
	return nil
}

func (m *Manager) Stop(ctx context.Context, sessionID string) error {
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return err
	}
	if err := m.Runtime.Stop(ctx, sessionID); err != nil {
		return err
	}
	if err := m.Store.EndSession(sessionID, m.Now()); err != nil {
		return err
	}
	_, _ = m.Publish(store.SessionEvent{SessionID: sessionID, Type: "lifecycle", Data: "stopped"})
	return nil
}

// Delete stops the runtime (if still alive) and removes the session row and
// its persisted event log. Live subscribers are dropped.
func (m *Manager) Delete(ctx context.Context, sessionID string) error {
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return err
	}
	// Best-effort stop — ignore errors so a wedged tmux session can still
	// be cleared from the UI.
	_ = m.Runtime.Stop(ctx, sessionID)
	if err := m.Store.DeleteSession(sessionID); err != nil {
		return err
	}
	m.mu.Lock()
	for sub := range m.subs[sessionID] {
		delete(m.subs[sessionID], sub)
		close(sub.done)
	}
	delete(m.subs, sessionID)
	m.mu.Unlock()
	return nil
}

// StartReaper periodically marks active sessions whose runtime has
// disappeared as ended. Returns immediately; the goroutine exits when ctx
// is cancelled.
func (m *Manager) StartReaper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.reapOnce(ctx)
			}
		}
	}()
}

func (m *Manager) reapOnce(ctx context.Context) {
	active, err := m.Store.ActiveSessions()
	if err != nil {
		return
	}
	for _, sess := range active {
		if m.Runtime.Alive(ctx, sess.ID) {
			continue
		}
		if err := m.Store.EndSession(sess.ID, m.Now()); err == nil {
			_, _ = m.Publish(store.SessionEvent{SessionID: sess.ID, Type: "lifecycle", Data: "dead"})
		}
	}
}

func (m *Manager) List(projectID string) ([]store.Session, error) {
	return m.Store.ListSessions(projectID)
}

func (m *Manager) Log(sessionID string) (string, error) {
	evs, err := m.Store.SessionEventsAfter(sessionID, 0)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, ev := range evs {
		if ev.Type == "stdout" || ev.Type == "stderr" || ev.Type == "prompt" {
			b.WriteString(ev.Data)
			if !strings.HasSuffix(ev.Data, "\n") {
				b.WriteByte('\n')
			}
		}
	}
	return b.String(), nil
}

func (m *Manager) Rehydrate(ctx context.Context) error {
	active, err := m.Store.ActiveSessions()
	if err != nil {
		return err
	}
	for _, sess := range active {
		data, err := m.Runtime.Capture(ctx, sess.ID)
		if err == nil && data != "" {
			_, _ = m.Publish(store.SessionEvent{SessionID: sess.ID, Type: "stdout", Data: data})
		}
		if err := m.Runtime.Attach(ctx, RuntimeSpec{
			SessionID: sess.ID,
			Agent:     sess.Agent,
			WorkDir:   m.Projects.WorkspaceDir(sess.ProjectID),
			Output:    &eventWriter{manager: m, sessionID: sess.ID, eventType: "stdout"},
		}); err != nil {
			continue
		}
	}
	return nil
}

// PublishExisting fans an event that has already been persisted (by another
// subsystem such as review) out to live subscribers without re-appending it.
func (m *Manager) PublishExisting(ev store.SessionEvent) {
	m.fanout(ev)
}

func (m *Manager) Publish(ev store.SessionEvent) (store.SessionEvent, error) {
	ev, err := m.Store.AppendSessionEvent(ev)
	if err != nil {
		return store.SessionEvent{}, err
	}
	if in, out, ok := parseUsage(ev.Data); ok {
		_ = m.Store.UpdateSessionUsage(ev.SessionID, in, out)
	}
	m.fanout(ev)
	return ev, nil
}

// fanout delivers ev to every live subscriber of the session. Terminal output
// is a stateful byte stream — a dropped ANSI redraw chunk corrupts the client's
// screen — so delivery must never drop. We snapshot the subscribers under the
// lock, then send outside it: this bounds backpressure to the one slow session
// (its writer waits for its consumer) instead of letting a held lock freeze
// every session's output. A torn-down subscriber unblocks via its done channel.
func (m *Manager) fanout(ev store.SessionEvent) {
	m.mu.Lock()
	subs := make([]*subscriber, 0, len(m.subs[ev.SessionID]))
	for sub := range m.subs[ev.SessionID] {
		subs = append(subs, sub)
	}
	m.mu.Unlock()
	for _, sub := range subs {
		select {
		case sub.ch <- ev:
		case <-sub.done:
		}
	}
}

func (m *Manager) Subscribe(ctx context.Context, sessionID string, afterSeq int64) (<-chan store.SessionEvent, func(), error) {
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return nil, nil, err
	}
	subCtx, cancelSub := context.WithCancel(ctx)
	sub := &subscriber{
		ch:   make(chan store.SessionEvent, 256),
		done: make(chan struct{}),
	}
	out := make(chan store.SessionEvent, 256)
	m.mu.Lock()
	if m.subs[sessionID] == nil {
		m.subs[sessionID] = make(map[*subscriber]struct{})
	}
	m.subs[sessionID][sub] = struct{}{}
	replay, err := m.Store.SessionEventsAfter(sessionID, afterSeq)
	if err != nil {
		delete(m.subs[sessionID], sub)
		m.mu.Unlock()
		close(out)
		cancelSub()
		return nil, nil, err
	}
	m.mu.Unlock()

	finished := make(chan struct{})
	go func() {
		defer close(out)
		defer close(finished)
		for _, ev := range replay {
			select {
			case out <- ev:
			case <-subCtx.Done():
				return
			}
		}
		for {
			select {
			case ev := <-sub.ch:
				select {
				case out <- ev:
				case <-subCtx.Done():
					return
				case <-sub.done:
					return
				}
			case <-subCtx.Done():
				return
			case <-sub.done:
				return
			}
		}
	}()
	cancel := func() {
		cancelSub()
		m.mu.Lock()
		if _, ok := m.subs[sessionID][sub]; ok {
			delete(m.subs[sessionID], sub)
			close(sub.done)
		}
		m.mu.Unlock()
		<-finished
	}
	return out, cancel, nil
}

type eventWriter struct {
	manager   *Manager
	sessionID string
	eventType string
}

func (w *eventWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		_, err := w.manager.Publish(store.SessionEvent{SessionID: w.sessionID, Type: w.eventType, Data: string(p)})
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

var usageRE = regexp.MustCompile(`(?i)(input|prompt)[^0-9]*(\d+).*?(output|completion)[^0-9]*(\d+)`)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)

func parseUsage(s string) (int, int, bool) {
	m := usageRE.FindStringSubmatch(s)
	if len(m) != 5 {
		return 0, 0, false
	}
	var in, out int
	_, _ = fmt.Sscanf(m[2], "%d", &in)
	_, _ = fmt.Sscanf(m[4], "%d", &out)
	return in, out, true
}

func cleanTerminalText(s string) string {
	s = ansiRE.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, s)
}

func claudeFirstRunSetupStep(s string) string {
	compact := strings.ToLower(strings.ReplaceAll(s, " ", ""))
	if strings.Contains(compact, "selectloginmethod") ||
		(strings.Contains(compact, "claudeaccountwithsubscription") &&
			strings.Contains(compact, "anthropicconsoleaccount")) {
		return "login_method"
	}
	if strings.Contains(compact, "choosethetextstyle") ||
		strings.Contains(compact, "syntaxtheme:") ||
		(strings.Contains(compact, "welcometoclaudecode") && strings.Contains(compact, "let'sgetstarted")) {
		return "theme"
	}
	return ""
}

func isClaudeFirstRunSetup(s string) bool {
	return claudeFirstRunSetupStep(s) != ""
}

// TmuxRuntime exec's tmux to host agent CLIs. ExtraPath, when set, is
// prepended to $PATH for the launched pane so per-user-installed CLIs
// (e.g. claude/codex under /var/lib/claver/bin) resolve. Secrets, when set,
// returns env-var assignments to inject into the new pane via `tmux -e` so
// the CLI inherits subscription credentials.
type TmuxRuntime struct {
	ExtraPath string
	HomeDir   string
	Secrets   func(agent string) map[string]string
}

func (r TmuxRuntime) Start(ctx context.Context, spec RuntimeSpec) error {
	if spec.Agent != "claude" && spec.Agent != "codex" {
		return ErrBadAgent
	}
	if normalizeRunMode(spec.RunMode) != "manual" && normalizeRunMode(spec.RunMode) != "yolo" {
		return ErrBadMode
	}
	if err := os.MkdirAll(spec.WorkDir, 0o700); err != nil {
		return err
	}
	name := tmuxName(spec.SessionID)
	args := []string{"new-session", "-d", "-s", name, "-n", spec.SessionID, "-c", spec.WorkDir}
	args = append(args, r.tmuxEnvFlags()...)
	if r.Secrets != nil {
		for k, v := range r.Secrets(spec.Agent) {
			args = append(args, "-e", k+"="+v)
		}
	}
	args = append(args, agentCommandArgs(spec.Agent, spec.RunMode)...)
	cmd := exec.CommandContext(ctx, "tmux", args...)
	cmd.Env = r.envWithPath()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tmux new-session: %w: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.CommandContext(ctx, "tmux", "select-pane", "-t", name+":0.0", "-T", spec.SessionID).Run()
	return r.Attach(ctx, spec)
}

func agentCommandArgs(agent, runMode string) []string {
	mode := normalizeRunMode(runMode)
	switch agent {
	case "claude":
		if mode == "yolo" {
			return []string{"claude", "--dangerously-skip-permissions"}
		}
		return []string{"claude", "--permission-mode", "default"}
	case "codex":
		if mode == "yolo" {
			return []string{"codex", "--dangerously-bypass-approvals-and-sandbox"}
		}
		return []string{"codex", "--ask-for-approval", "untrusted", "--sandbox", "workspace-write"}
	default:
		return []string{agent}
	}
}

func (r TmuxRuntime) envWithPath() []string {
	env := os.Environ()
	if r.ExtraPath == "" && r.HomeDir == "" {
		return env
	}
	cur := os.Getenv("PATH")
	newPath := cur
	if r.ExtraPath != "" && cur != "" {
		newPath = r.ExtraPath + ":" + cur
	} else if r.ExtraPath != "" {
		newPath = r.ExtraPath
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if shouldReplaceEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	if newPath != "" {
		out = append(out, "PATH="+newPath)
	}
	if r.HomeDir != "" {
		out = append(out, "HOME="+r.HomeDir)
		out = append(out, "CLAUDE_CONFIG_DIR="+r.claudeConfigDir())
	}
	return out
}

func (r TmuxRuntime) tmuxEnvFlags() []string {
	flags := []string{}
	if r.HomeDir != "" {
		flags = append(flags, "-e", "HOME="+r.HomeDir)
		flags = append(flags, "-e", "CLAUDE_CONFIG_DIR="+r.claudeConfigDir())
	}
	if path := pathWithPrefix(r.ExtraPath); path != "" {
		flags = append(flags, "-e", "PATH="+path)
	}
	return flags
}

func (r TmuxRuntime) claudeConfigDir() string {
	return filepath.Join(r.HomeDir, ".claude")
}

func shouldReplaceEnv(kv string) bool {
	for _, prefix := range []string{
		"PATH=",
		"HOME=",
		"CLAUDE_CONFIG_DIR=",
		"ANTHROPIC_API_KEY=",
		"ANTHROPIC_AUTH_TOKEN=",
		"CLAUDE_CODE_OAUTH_TOKEN=",
	} {
		if strings.HasPrefix(kv, prefix) {
			return true
		}
	}
	return false
}

func pathWithPrefix(prefix string) string {
	cur := os.Getenv("PATH")
	switch {
	case prefix != "" && cur != "":
		return prefix + ":" + cur
	case prefix != "":
		return prefix
	default:
		return cur
	}
}

func (r TmuxRuntime) Attach(ctx context.Context, spec RuntimeSpec) error {
	target := tmuxName(spec.SessionID) + ":0.0"
	fifo := filepath.Join(os.TempDir(), "claver-"+spec.SessionID+".pipe")
	_ = os.Remove(fifo)
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		return fmt.Errorf("create tmux pipe: %w", err)
	}
	go func() {
		defer os.Remove(fifo)
		f, err := os.OpenFile(fifo, os.O_RDONLY, 0)
		if err != nil {
			return
		}
		defer f.Close()
		output := spec.Output
		if spec.Agent == "claude" {
			output = newClaudeFirstRunAdvancer(spec.Output, spec.SessionID, sendTmuxEnter)
		}
		coalesced := newCoalescingWriter(output, 16*time.Millisecond, 32*1024)
		scanPipe(f, coalesced)
		coalesced.Close()
	}()
	pipeCmd := "cat > " + shellQuote(fifo)
	if out, err := exec.CommandContext(ctx, "tmux", "pipe-pane", "-t", target, "-o", pipeCmd).CombinedOutput(); err != nil {
		return fmt.Errorf("tmux pipe-pane: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if spec.Agent == "claude" {
		r.advanceClaudeFirstRunSetup(ctx, spec.SessionID)
	}
	return nil
}

func (r TmuxRuntime) advanceClaudeFirstRunSetup(ctx context.Context, sessionID string) {
	data, err := r.Capture(ctx, sessionID)
	if err != nil || data == "" {
		return
	}
	if claudeFirstRunSetupStep(cleanTerminalText(data)) != "" {
		_ = sendTmuxEnter(ctx, sessionID)
	}
}

type claudeFirstRunAdvancer struct {
	out       io.Writer
	sessionID string
	sendEnter func(context.Context, string) error

	mu       sync.Mutex
	advanced map[string]bool
	buffer   string
}

func newClaudeFirstRunAdvancer(out io.Writer, sessionID string, sendEnter func(context.Context, string) error) io.Writer {
	return &claudeFirstRunAdvancer{
		out:       out,
		sessionID: sessionID,
		sendEnter: sendEnter,
		advanced:  map[string]bool{},
	}
}

func (w *claudeFirstRunAdvancer) Write(p []byte) (int, error) {
	n, err := w.out.Write(p)
	if len(p) == 0 {
		return n, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	clean := cleanTerminalText(string(p))
	if clean == "" {
		return n, err
	}
	w.buffer += clean
	if len(w.buffer) > 4096 {
		w.buffer = w.buffer[len(w.buffer)-4096:]
	}
	if step := claudeFirstRunSetupStep(w.buffer); step != "" && !w.advanced[step] {
		w.advanced[step] = true
		_ = w.sendEnter(context.Background(), w.sessionID)
	}
	return n, err
}

// coalescingWriter batches pty bytes over a short window before forwarding
// them downstream. Full-screen TUIs emit many tiny reads per redraw; without
// batching each read became its own SQLite insert, websocket frame, and
// client stream event, which is the dominant source of churn and jitter.
// Bytes flush when the buffer reaches maxBytes or after window elapses,
// whichever comes first, so latency stays bounded while volume collapses.
type coalescingWriter struct {
	out      io.Writer
	window   time.Duration
	maxBytes int

	mu     sync.Mutex
	buf    []byte
	timer  *time.Timer
	closed bool
}

func newCoalescingWriter(out io.Writer, window time.Duration, maxBytes int) *coalescingWriter {
	return &coalescingWriter{out: out, window: window, maxBytes: maxBytes}
}

func (w *coalescingWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	if len(w.buf) >= w.maxBytes {
		w.flushLocked()
	} else if w.timer == nil {
		w.timer = time.AfterFunc(w.window, w.flush)
	}
	return len(p), nil
}

func (w *coalescingWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushLocked()
}

func (w *coalescingWriter) flushLocked() {
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	if len(w.buf) == 0 {
		return
	}
	_, _ = w.out.Write(w.buf)
	w.buf = nil
}

// Close flushes any buffered bytes and stops accepting new ones.
func (w *coalescingWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushLocked()
	w.closed = true
}

// scanPipe forwards pty bytes from the tmux pipe as soon as they arrive.
// Codex (and Claude) are full-screen TUIs that emit ANSI redraws with no
// newlines between frames, so a newline-gated reader would stall and the
// pane would appear frozen on the client.
func scanPipe(r io.Reader, w io.Writer) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func (TmuxRuntime) SendPrompt(ctx context.Context, sessionID, prompt string) error {
	target := tmuxName(sessionID) + ":0.0"
	if out, err := exec.CommandContext(ctx, "tmux", "send-keys", "-t", target, "-l", prompt).CombinedOutput(); err != nil {
		return fmt.Errorf("tmux send prompt: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "tmux", "send-keys", "-t", target, "Enter").CombinedOutput(); err != nil {
		return fmt.Errorf("tmux send enter: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SendInput writes raw bytes into the pane. We use send-keys -H (hex) so
// arbitrary control bytes — ESC, CSI, SGR mouse-wheel reports — reach the pty
// verbatim instead of being interpreted as tmux key names.
func (TmuxRuntime) SendInput(ctx context.Context, sessionID, data string) error {
	if data == "" {
		return nil
	}
	target := tmuxName(sessionID) + ":0.0"
	args := []string{"send-keys", "-t", target, "-H"}
	for _, b := range []byte(data) {
		args = append(args, fmt.Sprintf("%02x", b))
	}
	if out, err := exec.CommandContext(ctx, "tmux", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("tmux send input: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func sendTmuxEnter(ctx context.Context, sessionID string) error {
	target := tmuxName(sessionID) + ":0.0"
	if out, err := exec.CommandContext(ctx, "tmux", "send-keys", "-t", target, "Enter").CombinedOutput(); err != nil {
		return fmt.Errorf("tmux send enter: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (TmuxRuntime) Resize(ctx context.Context, sessionID string, cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	target := tmuxName(sessionID)
	out, err := exec.CommandContext(ctx, "tmux", "resize-window", "-t", target,
		"-x", strconv.Itoa(cols), "-y", strconv.Itoa(rows)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tmux resize: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (TmuxRuntime) Interrupt(ctx context.Context, sessionID string) error {
	out, err := exec.CommandContext(ctx, "tmux", "send-keys", "-t", tmuxName(sessionID)+":0.0", "C-c").CombinedOutput()
	if err != nil {
		return fmt.Errorf("tmux interrupt: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (TmuxRuntime) Stop(ctx context.Context, sessionID string) error {
	name := tmuxName(sessionID)
	// Snapshot pane PIDs *before* killing the tmux session so we can
	// force-kill any descendants that ignore SIGHUP (codex notably does).
	pids := tmuxPanePIDs(ctx, name)
	out, err := exec.CommandContext(ctx, "tmux", "kill-session", "-t", name).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "can't find session") {
		return fmt.Errorf("tmux stop: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// SIGTERM, then SIGKILL stragglers (including their child trees).
	for _, pid := range pids {
		killTree(pid, syscall.SIGTERM)
	}
	if len(pids) > 0 {
		time.Sleep(150 * time.Millisecond)
		for _, pid := range pids {
			killTree(pid, syscall.SIGKILL)
		}
	}
	return nil
}

func (TmuxRuntime) Alive(ctx context.Context, sessionID string) bool {
	err := exec.CommandContext(ctx, "tmux", "has-session", "-t", tmuxName(sessionID)).Run()
	return err == nil
}

func tmuxPanePIDs(ctx context.Context, name string) []int {
	out, err := exec.CommandContext(ctx, "tmux", "list-panes", "-t", name, "-F", "#{pane_pid}").Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(line, "%d", &pid); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// killTree signals pid and every descendant process. Errors are ignored —
// the process may already be gone, or we may lack permission, and the
// caller has already given up on graceful shutdown.
func killTree(pid int, sig syscall.Signal) {
	for _, p := range append([]int{pid}, descendantPIDs(pid)...) {
		_ = syscall.Kill(p, sig)
	}
}

func descendantPIDs(root int) []int {
	out, err := exec.Command("pgrep", "-P", fmt.Sprintf("%d", root)).Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(line, "%d", &pid); err == nil && pid > 0 {
			pids = append(pids, pid)
			pids = append(pids, descendantPIDs(pid)...)
		}
	}
	return pids
}

func (TmuxRuntime) Capture(ctx context.Context, sessionID string) (string, error) {
	out, err := exec.CommandContext(ctx, "tmux", "capture-pane", "-p", "-S", "-", "-t", tmuxName(sessionID)+":0.0").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tmux capture: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func tmuxName(sessionID string) string {
	return "claver-" + filepath.Base(sessionID)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
