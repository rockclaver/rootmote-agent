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
	SendPrompt(ctx context.Context, sessionID, prompt string) error
	Interrupt(ctx context.Context, sessionID string) error
	Stop(ctx context.Context, sessionID string) error
	Capture(ctx context.Context, sessionID string) (string, error)
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
		if err != nil || data == "" {
			continue
		}
		_, _ = m.Publish(store.SessionEvent{SessionID: sess.ID, Type: "stdout", Data: data})
	}
	return nil
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
	ch := make(chan store.SessionEvent, 64)
	m.mu.Lock()
	if m.subs[sessionID] == nil {
		m.subs[sessionID] = make(map[chan store.SessionEvent]struct{})
	}
	m.subs[sessionID][ch] = struct{}{}
	replay, err := m.Store.SessionEventsAfter(sessionID, afterSeq)
	if err != nil {
		delete(m.subs[sessionID], ch)
		m.mu.Unlock()
		close(ch)
		return nil, nil, err
	}
	for _, ev := range replay {
		select {
		case ch <- ev:
		case <-ctx.Done():
			delete(m.subs[sessionID], ch)
			m.mu.Unlock()
			close(ch)
			return nil, nil, ctx.Err()
		}
	}
	m.mu.Unlock()
	cancel := func() {
		m.mu.Lock()
		delete(m.subs[sessionID], ch)
		m.mu.Unlock()
		close(ch)
	}
	return ch, cancel, nil
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

type TmuxRuntime struct{}

func (TmuxRuntime) Start(ctx context.Context, spec RuntimeSpec) error {
	if spec.Agent != "claude" && spec.Agent != "codex" {
		return ErrBadAgent
	}
	if err := os.MkdirAll(spec.WorkDir, 0o700); err != nil {
		return err
	}
	name := tmuxName(spec.SessionID)
	if out, err := exec.CommandContext(ctx, "tmux", "new-session", "-d", "-s", name, "-n", spec.SessionID, "-c", spec.WorkDir, spec.Agent).CombinedOutput(); err != nil {
		return fmt.Errorf("tmux new-session: %w: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.CommandContext(ctx, "tmux", "select-pane", "-t", name+":0.0", "-T", spec.SessionID).Run()
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
	if out, err := exec.CommandContext(ctx, "tmux", "pipe-pane", "-t", name+":0.0", "-o", pipeCmd).CombinedOutput(); err != nil {
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
	out, err := exec.CommandContext(ctx, "tmux", "kill-session", "-t", tmuxName(sessionID)).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "can't find session") {
		return fmt.Errorf("tmux stop: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
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
