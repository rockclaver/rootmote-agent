// Package sessions owns AI-agent panes, persisted stream replay, and the
// narrow command surface exposed to mobile clients.
package sessions

import (
	"bufio"
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/store"
)

var (
	ErrBadAgent = errors.New("agent must be claude or codex")
	ErrNotFound = store.ErrNotFound
)

type Runtime interface {
	Start(ctx context.Context, spec RuntimeSpec) error
	Attach(ctx context.Context, spec RuntimeSpec) error
	SendPrompt(ctx context.Context, sessionID, prompt string) error
	Interrupt(ctx context.Context, sessionID string) error
	Stop(ctx context.Context, sessionID string) error
	Capture(ctx context.Context, sessionID string) (string, error)
	Alive(ctx context.Context, sessionID string) bool
}

type RuntimeSpec struct {
	SessionID string
	Agent     string
	WorkDir   string
	Output    io.Writer
}

type Manager struct {
	Store    *store.Store
	Projects *projects.Manager
	Runtime  Runtime
	Now      func() time.Time
	IDGen    func() string

	mu   sync.Mutex
	subs map[string]map[chan store.SessionEvent]struct{}
}

func New(st *store.Store, projectMgr *projects.Manager, runtime Runtime) *Manager {
	return &Manager{
		Store: st, Projects: projectMgr, Runtime: runtime, Now: time.Now, IDGen: randomID,
		subs: make(map[string]map[chan store.SessionEvent]struct{}),
	}
}

func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (m *Manager) Start(ctx context.Context, projectID, agent string) (store.Session, error) {
	if agent != "claude" && agent != "codex" {
		return store.Session{}, ErrBadAgent
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
		WorkDir:   m.Projects.WorkspaceDir(projectID),
		Output:    w,
	}); err != nil {
		_ = m.Store.EndSession(id, m.Now())
		return store.Session{}, err
	}
	_, _ = m.Publish(store.SessionEvent{SessionID: id, Type: "lifecycle", Data: "started"})
	return sess, nil
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
	for ch := range m.subs[sessionID] {
		delete(m.subs[sessionID], ch)
		close(ch)
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
	m.mu.Lock()
	defer m.mu.Unlock()
	for ch := range m.subs[ev.SessionID] {
		ch <- ev
	}
}

func (m *Manager) Publish(ev store.SessionEvent) (store.SessionEvent, error) {
	ev, err := m.Store.AppendSessionEvent(ev)
	if err != nil {
		return store.SessionEvent{}, err
	}
	if in, out, ok := parseUsage(ev.Data); ok {
		_ = m.Store.UpdateSessionUsage(ev.SessionID, in, out)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for ch := range m.subs[ev.SessionID] {
		ch <- ev
	}
	return ev, nil
}

func (m *Manager) Subscribe(ctx context.Context, sessionID string, afterSeq int64) (<-chan store.SessionEvent, func(), error) {
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return nil, nil, err
	}
	subCtx, cancelSub := context.WithCancel(ctx)
	live := make(chan store.SessionEvent, 64)
	out := make(chan store.SessionEvent, 64)
	m.mu.Lock()
	if m.subs[sessionID] == nil {
		m.subs[sessionID] = make(map[chan store.SessionEvent]struct{})
	}
	m.subs[sessionID][live] = struct{}{}
	replay, err := m.Store.SessionEventsAfter(sessionID, afterSeq)
	if err != nil {
		delete(m.subs[sessionID], live)
		m.mu.Unlock()
		close(live)
		close(out)
		cancelSub()
		return nil, nil, err
	}
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(out)
		defer close(done)
		for _, ev := range replay {
			select {
			case out <- ev:
			case <-subCtx.Done():
				return
			}
		}
		for {
			select {
			case ev, ok := <-live:
				if !ok {
					return
				}
				select {
				case out <- ev:
				case <-subCtx.Done():
					return
				}
			case <-subCtx.Done():
				return
			}
		}
	}()
	cancel := func() {
		cancelSub()
		m.mu.Lock()
		if _, ok := m.subs[sessionID][live]; ok {
			delete(m.subs[sessionID], live)
			close(live)
		}
		m.mu.Unlock()
		<-done
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

// TmuxRuntime exec's tmux to host agent CLIs. ExtraPath, when set, is
// prepended to $PATH for the launched pane so per-user-installed CLIs
// (e.g. claude/codex under /var/lib/claver/bin) resolve. Secrets, when set,
// returns env-var assignments to inject into the new pane via `tmux -e` so
// the CLI inherits subscription credentials.
type TmuxRuntime struct {
	ExtraPath string
	Secrets   func(agent string) map[string]string
}

func (r TmuxRuntime) Start(ctx context.Context, spec RuntimeSpec) error {
	if spec.Agent != "claude" && spec.Agent != "codex" {
		return ErrBadAgent
	}
	if err := os.MkdirAll(spec.WorkDir, 0o700); err != nil {
		return err
	}
	name := tmuxName(spec.SessionID)
	args := []string{"new-session", "-d", "-s", name, "-n", spec.SessionID, "-c", spec.WorkDir}
	if r.Secrets != nil {
		for k, v := range r.Secrets(spec.Agent) {
			args = append(args, "-e", k+"="+v)
		}
	}
	args = append(args, spec.Agent)
	cmd := exec.CommandContext(ctx, "tmux", args...)
	cmd.Env = r.envWithPath()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tmux new-session: %w: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.CommandContext(ctx, "tmux", "select-pane", "-t", name+":0.0", "-T", spec.SessionID).Run()
	return r.Attach(ctx, spec)
}

func (r TmuxRuntime) envWithPath() []string {
	env := os.Environ()
	if r.ExtraPath == "" {
		return env
	}
	cur := os.Getenv("PATH")
	newPath := r.ExtraPath
	if cur != "" {
		newPath = r.ExtraPath + ":" + cur
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "PATH="+newPath)
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
		scanPipe(f, spec.Output)
	}()
	pipeCmd := "cat > " + shellQuote(fifo)
	if out, err := exec.CommandContext(ctx, "tmux", "pipe-pane", "-t", target, "-o", pipeCmd).CombinedOutput(); err != nil {
		return fmt.Errorf("tmux pipe-pane: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func scanPipe(r io.Reader, w io.Writer) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			_, _ = w.Write(line)
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
