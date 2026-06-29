// Package sessions owns AI-agent panes, persisted stream replay, and the
// narrow command surface exposed to mobile clients.
package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

	"github.com/google/uuid"
	"github.com/rockclaver/claver-agent/internal/projects"
	"github.com/rockclaver/claver-agent/internal/store"
)

var (
	ErrBadAgent      = errors.New("agent must be claude or codex")
	ErrBadMode       = errors.New("run mode must be manual or yolo")
	ErrAuthRequired  = errors.New("agent cli is not authenticated")
	ErrNotFound      = store.ErrNotFound
	ErrNotStructured = errors.New("operation requires the structured transport")
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
	// CaptureVisible returns only the on-screen pane (no scrollback), used to
	// parse the live state of an interactive selector without picking up stale
	// earlier menus from history.
	CaptureVisible(ctx context.Context, sessionID string) (string, error)
	Alive(ctx context.Context, sessionID string) bool
	// SendApproval and SetMode are only meaningful on the structured transport;
	// the terminal (tmux) runtime returns ErrNotStructured.
	SendApproval(ctx context.Context, sessionID, requestID, decision, note string) error
	SetMode(ctx context.Context, sessionID, mode string) error
}

type RuntimeSpec struct {
	SessionID string
	Agent     string
	RunMode   string
	// Transport is "terminal" (tmux TUI) or "structured" (machine protocol).
	Transport string
	WorkDir   string
	Output    io.Writer
	// ClaudeSessionID, when set, is passed to the claude CLI via --session-id so
	// its transcript file is named deterministically and we can read real token
	// usage from it. Empty for non-claude agents.
	ClaudeSessionID string
}

type Manager struct {
	Store    *store.Store
	Projects *projects.Manager
	Runtime  Runtime
	Now      func() time.Time
	IDGen    func() string
	AuthOK   func(context.Context, string) bool
	// MemorySource, when set, returns a token-bounded block of project memory
	// to inject as the agent's first context turn on session start. An empty
	// string means "nothing to inject". Wired to memory.Manager.Render.
	MemorySource func(projectID string) string
	// OnEnd, when set, is invoked once after a session is marked ended (via
	// Stop or the reaper). Wired to the project-journal summarizer. It must
	// not block the caller for long; production wraps it in a goroutine.
	OnEnd func(ctx context.Context, sess store.Session)
	// ClaudeProjectsDir is the absolute path to the claude CLI's transcript
	// root (<home>/.claude/projects). When set, claude sessions get a
	// --session-id and a background poller reads real token usage from the
	// matching transcript. Empty disables usage polling.
	ClaudeProjectsDir string

	mu         sync.Mutex
	subs       map[string]map[*subscriber]struct{}
	usageStops map[string]chan struct{}

	// questionMu guards the interactive-menu detection state below. Detection
	// runs off the output pipeline (a debounce timer per session) so a slow
	// capture never stalls streaming.
	questionMu     sync.Mutex
	questionState  map[string]*questionTrack
	questionTimers map[string]*time.Timer
}

// questionTrack is per-session bookkeeping for the interactive-menu detector.
// hash dedups re-emission across redraws of the same screen; groupIndex tracks
// which question of a multi-question menu the user is currently answering.
type questionTrack struct {
	hash       string
	groupIndex int
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
		subs:           make(map[string]map[*subscriber]struct{}),
		usageStops:     make(map[string]chan struct{}),
		questionState:  make(map[string]*questionTrack),
		questionTimers: make(map[string]*time.Timer),
	}
}

func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (m *Manager) Start(ctx context.Context, projectID, agent, runMode, transport string) (store.Session, error) {
	if agent != "claude" && agent != "codex" {
		return store.Session{}, ErrBadAgent
	}
	runMode = normalizeRunMode(runMode)
	if runMode != "manual" && runMode != "yolo" {
		return store.Session{}, ErrBadMode
	}
	// Transport is persisted on the session row; structured runtime selection by
	// transport lands in Phase 1, so until then all sessions run on m.Runtime.
	transport = normalizeTransport(transport)
	if m.AuthOK != nil && !m.AuthOK(ctx, agent) {
		return store.Session{}, ErrAuthRequired
	}
	if _, err := m.Projects.Get(projectID); err != nil {
		return store.Session{}, err
	}
	id := m.IDGen()
	sess := store.Session{ID: id, ProjectID: projectID, Agent: agent, Transport: transport, StartedAt: m.Now()}
	if err := m.Store.CreateSession(sess); err != nil {
		return store.Session{}, err
	}
	// Claude transcripts are keyed by session UUID; minting one and passing it
	// to the CLI lets the usage poller find this session's transcript precisely.
	var claudeSessionID string
	if agent == "claude" && m.ClaudeProjectsDir != "" {
		claudeSessionID = uuid.NewString()
	}
	w := &eventWriter{manager: m, sessionID: id, eventType: "stdout"}
	if err := m.Runtime.Start(ctx, RuntimeSpec{
		SessionID:       id,
		Agent:           agent,
		RunMode:         runMode,
		Transport:       transport,
		WorkDir:         m.Projects.WorkspaceDir(projectID),
		Output:          w,
		ClaudeSessionID: claudeSessionID,
	}); err != nil {
		_ = m.Store.EndSession(id, m.Now())
		return store.Session{}, err
	}
	_, _ = m.Publish(store.SessionEvent{SessionID: id, Type: "lifecycle", Data: "started"})
	if claudeSessionID != "" {
		m.startUsagePoll(id, claudeSessionID)
	}
	m.injectMemory(ctx, id, projectID)
	return sess, nil
}

// injectMemory primes a freshly started session with the project's
// accumulated memory. It is best-effort: a missing or empty memory block is
// silently skipped, and a send failure is non-fatal to the start. The block is
// recorded as a "memory" event so the client transcript and the persisted log
// show what context the agent was given.
func (m *Manager) injectMemory(ctx context.Context, sessionID, projectID string) {
	if m.MemorySource == nil {
		return
	}
	block := m.MemorySource(projectID)
	if strings.TrimSpace(block) == "" {
		return
	}
	_, _ = m.Publish(store.SessionEvent{SessionID: sessionID, Type: "memory", Data: block})
	_ = m.Runtime.SendPrompt(ctx, sessionID, block)
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
	// A fresh prompt invalidates any pending interactive menu state.
	m.clearQuestion(sessionID)
	_, _ = m.Publish(store.SessionEvent{SessionID: sessionID, Type: "prompt", Data: prompt})
	return m.Runtime.SendPrompt(ctx, sessionID, prompt)
}

// SendApproval forwards the user's decision on a pending approval_request to the
// structured runtime. decision is one of DecisionAllow/DecisionAllowAlways/
// DecisionDeny; note is optional free text. The terminal runtime rejects this
// with ErrNotStructured.
func (m *Manager) SendApproval(ctx context.Context, sessionID, requestID, decision, note string) error {
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return err
	}
	return m.Runtime.SendApproval(ctx, sessionID, requestID, decision, note)
}

// SetMode switches the session's permission/run mode (ModePlan/ModeDefault/
// ModeAcceptEdits/ModeYolo) on the structured runtime. The terminal runtime
// rejects this with ErrNotStructured.
func (m *Manager) SetMode(ctx context.Context, sessionID, mode string) error {
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return err
	}
	return m.Runtime.SetMode(ctx, sessionID, mode)
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

// settleDelay is how long we wait for the TUI to repaint after a keystroke
// before re-reading the pane to verify the effect.
const settleDelay = 90 * time.Millisecond

// SendQuestionDecision drives the live interactive selector for one question
// group to match the user's choices made in the native sheet. Each step is
// closed-loop: send a key, re-capture the resolved pane, verify the change.
// These menus are numbered, so the primary strategy is to press the option's
// number key; arrow-navigation + Space/Enter is the fallback when a number key
// has no effect. action is one of "submit", "next" (advance to the next
// question of a multi-question menu), or "cancel".
//
// When a step can't be verified, a diagnostic is written to the session's
// output stream (visible in the terminal) instead of failing silently, so the
// real key semantics / capture format can be inspected.
func (m *Manager) SendQuestionDecision(ctx context.Context, sessionID string, groupIndex int, selectedIndices []int, freeText, action string) error {
	if _, err := m.Store.GetSession(sessionID); err != nil {
		return err
	}
	if action == "cancel" {
		m.clearQuestion(sessionID)
		return m.Runtime.SendInput(ctx, sessionID, keyEsc)
	}

	snap, rows := m.captureSettled(ctx, sessionID)
	multi := false
	for _, r := range rows {
		if r.hasBox {
			multi = true
			break
		}
	}
	want := make(map[int]bool, len(selectedIndices))
	for _, i := range selectedIndices {
		want[i] = true
	}

	var problems []string
	if multi {
		for _, r := range rows {
			if !r.hasBox {
				continue
			}
			desired := want[r.index]
			if r.checked == desired {
				continue
			}
			if !m.toggleRow(ctx, sessionID, r.index, desired) {
				problems = append(problems, fmt.Sprintf("could not set option %d=%v", r.index, desired))
			}
		}
	} else if len(selectedIndices) > 0 {
		if !m.chooseRow(ctx, sessionID, selectedIndices[0]) {
			problems = append(problems, fmt.Sprintf("could not select option %d", selectedIndices[0]))
		}
	}

	if strings.TrimSpace(freeText) != "" {
		if idx, ok := m.findRow(ctx, sessionID, func(r parsedRow) bool { return isFreeTextLabel(r.label) }); ok {
			_ = m.navigateTo(ctx, sessionID, idx)
			_ = m.Runtime.SendInput(ctx, sessionID, keyEnter)
			time.Sleep(settleDelay)
			_ = m.Runtime.SendInput(ctx, sessionID, freeText)
			_ = m.Runtime.SendInput(ctx, sessionID, keyEnter)
		}
	}

	if len(problems) > 0 {
		m.publishQuestionDiag(sessionID, snap, problems)
	}

	switch action {
	case "next":
		m.questionMu.Lock()
		if st := m.questionState[sessionID]; st != nil {
			st.groupIndex++
			st.hash = "" // allow the next group's screen to re-emit
		}
		m.questionMu.Unlock()
		return m.Runtime.SendInput(ctx, sessionID, keyTab)
	default: // submit
		m.clearQuestion(sessionID)
		// Multi-select needs an explicit confirm; single-select is confirmed by
		// the selection itself in chooseRow.
		if multi {
			return m.Runtime.SendInput(ctx, sessionID, keyEnter)
		}
		return nil
	}
}

// captureRows reads the live pane and parses its selector rows.
func (m *Manager) captureRows(ctx context.Context, sessionID string) ([]parsedRow, error) {
	capture, err := m.Runtime.CaptureVisible(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	return parseRows(capture), nil
}

// captureSettled retries the capture a few times until it yields selector rows,
// returning both the raw snapshot (for diagnostics) and the parsed rows.
func (m *Manager) captureSettled(ctx context.Context, sessionID string) (string, []parsedRow) {
	var snap string
	for i := 0; i < 3; i++ {
		s, err := m.Runtime.CaptureVisible(ctx, sessionID)
		if err == nil {
			snap = s
			if rows := parseRows(s); len(rows) > 0 {
				return s, rows
			}
		}
		time.Sleep(settleDelay)
	}
	return snap, parseRows(snap)
}

// findRow returns the index of the first row matching pred.
func (m *Manager) findRow(ctx context.Context, sessionID string, pred func(parsedRow) bool) (int, bool) {
	rows, err := m.captureRows(ctx, sessionID)
	if err != nil {
		return 0, false
	}
	for _, r := range rows {
		if pred(r) {
			return r.index, true
		}
	}
	return 0, false
}

// rowChecked reports the current checked state of the option with the given
// index, and whether that option is still on screen.
func (m *Manager) rowChecked(ctx context.Context, sessionID string, target int) (checked bool, exists bool) {
	rows, err := m.captureRows(ctx, sessionID)
	if err != nil {
		return false, false
	}
	for _, r := range rows {
		if r.index == target {
			return r.checked, true
		}
	}
	return false, false
}

// toggleRow sets the checkbox at target to desired, trying the number key first
// (these menus are numbered) and falling back to arrow-navigation + Space/Enter.
// Every attempt is verified against a fresh capture.
func (m *Manager) toggleRow(ctx context.Context, sessionID string, target int, desired bool) bool {
	if cur, ok := m.rowChecked(ctx, sessionID, target); ok && cur == desired {
		return true
	}
	// Strategy 1: press the option's number.
	if m.tryToggleKey(ctx, sessionID, strconv.Itoa(target), target, desired) {
		return true
	}
	// Strategy 2: navigate the caret onto the row, then Space, then Enter.
	if err := m.navigateTo(ctx, sessionID, target); err == nil {
		if m.tryToggleKey(ctx, sessionID, keySpace, target, desired) {
			return true
		}
		if m.tryToggleKey(ctx, sessionID, keyEnter, target, desired) {
			return true
		}
	}
	return false
}

// tryToggleKey sends key, waits for the repaint, and reports whether target
// reached the desired checked state.
func (m *Manager) tryToggleKey(ctx context.Context, sessionID string, key string, target int, desired bool) bool {
	if err := m.Runtime.SendInput(ctx, sessionID, key); err != nil {
		return false
	}
	time.Sleep(settleDelay)
	cur, ok := m.rowChecked(ctx, sessionID, target)
	return ok && cur == desired
}

// chooseRow picks a single-select option, pressing its number first (which on
// most numbered selectors selects and dismisses the menu) and falling back to
// arrow-navigation + Enter. Success is inferred from the menu closing.
func (m *Manager) chooseRow(ctx context.Context, sessionID string, target int) bool {
	if err := m.Runtime.SendInput(ctx, sessionID, strconv.Itoa(target)); err != nil {
		return false
	}
	time.Sleep(settleDelay)
	if !m.menuPresent(ctx, sessionID) {
		return true
	}
	if err := m.navigateTo(ctx, sessionID, target); err != nil {
		return false
	}
	if err := m.Runtime.SendInput(ctx, sessionID, keyEnter); err != nil {
		return false
	}
	time.Sleep(settleDelay)
	return true
}

// menuPresent reports whether a selector is still on screen.
func (m *Manager) menuPresent(ctx context.Context, sessionID string) bool {
	s, err := m.Runtime.CaptureVisible(ctx, sessionID)
	if err != nil {
		return false
	}
	return questionFooterRE.MatchString(s)
}

// navigateTo moves the selector caret onto the row with the given index,
// verifying after every keystroke. It aborts if the caret can't be located
// (e.g. the TUI marks selection by colour only) so the caller can fall back to
// another strategy instead of looping blindly.
func (m *Manager) navigateTo(ctx context.Context, sessionID string, target int) error {
	const maxSteps = 32
	caretMisses := 0
	for step := 0; step < maxSteps; step++ {
		rows, err := m.captureRows(ctx, sessionID)
		if err != nil {
			return err
		}
		cursorIdx := -1
		targetExists := false
		for _, r := range rows {
			if r.cursor {
				cursorIdx = r.index
			}
			if r.index == target {
				targetExists = true
			}
		}
		if !targetExists {
			return fmt.Errorf("option %d not on screen", target)
		}
		if cursorIdx == target {
			return nil
		}
		if cursorIdx == -1 {
			if caretMisses++; caretMisses > 3 {
				return fmt.Errorf("caret not detectable")
			}
		}
		key := keyDown
		if cursorIdx != -1 && target < cursorIdx {
			key = keyUp
		}
		if err := m.Runtime.SendInput(ctx, sessionID, key); err != nil {
			return err
		}
		time.Sleep(settleDelay)
	}
	return fmt.Errorf("could not reach option %d", target)
}

// publishQuestionDiag surfaces a driving failure in the session's output stream
// so it is visible in the terminal and the raw selector rendering can be
// inspected, rather than failing silently after the sheet has closed.
func (m *Manager) publishQuestionDiag(sessionID, snapshot string, problems []string) {
	var b strings.Builder
	b.WriteString("\r\n[devdeck] could not drive the menu selection:\r\n")
	for _, p := range problems {
		b.WriteString("  - " + p + "\r\n")
	}
	b.WriteString("[devdeck] captured screen was:\r\n")
	b.WriteString(snapshot)
	b.WriteString("\r\n")
	_, _ = m.Publish(store.SessionEvent{SessionID: sessionID, Type: "stderr", Data: b.String()})
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
	m.stopUsagePoll(sessionID)
	_, _ = m.Publish(store.SessionEvent{SessionID: sessionID, Type: "lifecycle", Data: "stopped"})
	m.notifyEnded(ctx, sessionID)
	return nil
}

// notifyEnded invokes the OnEnd hook with the freshly-ended session row. The
// row is reloaded so EndedAt is populated for the journal timestamp.
func (m *Manager) notifyEnded(ctx context.Context, sessionID string) {
	if m.OnEnd == nil {
		return
	}
	sess, err := m.Store.GetSession(sessionID)
	if err != nil {
		return
	}
	m.OnEnd(ctx, sess)
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
	m.stopUsagePoll(sessionID)
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
			m.stopUsagePoll(sess.ID)
			_, _ = m.Publish(store.SessionEvent{SessionID: sess.ID, Type: "lifecycle", Data: "dead"})
			m.notifyEnded(ctx, sess.ID)
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
	m.accountUsage(ev)
	m.detectQuestion(ev)
	m.fanout(ev)
	return ev, nil
}

// accountUsage extracts token usage and tool-call counts from a freshly
// persisted event and folds them into the session's per-project usage row.
// Both are best-effort: usage lines and tool-call markers only appear in
// stdout from the agent CLI, and a malformed line simply yields no update.
func (m *Manager) accountUsage(ev store.SessionEvent) {
	if ev.Type != "stdout" && ev.Type != "stderr" {
		return
	}
	if in, out, cache, ok := parseUsage(ev.Data); ok {
		_ = m.Store.UpdateSessionUsage(ev.SessionID, in, out, cache)
	}
	if n := countToolCalls(ev.Data); n > 0 {
		_ = m.Store.IncrSessionToolCalls(ev.SessionID, n)
	}
}

// detectQuestion notices when an interactive selector (AskUserQuestion /
// ExitPlanMode) is on screen and schedules a debounced capture+parse so the
// client can render a native sheet. The full-screen TUI is drawn with
// cursor-addressed redraws across many coalesced chunks, so a single stdout
// chunk never contains an intact menu — we trigger on the content-independent
// footer signature, then read the *resolved* pane via capture-pane.
func (m *Manager) detectQuestion(ev store.SessionEvent) {
	if ev.Type != "stdout" {
		return
	}
	if !questionFooterRE.MatchString(cleanTerminalText(ev.Data)) {
		return
	}
	sid := ev.SessionID
	m.questionMu.Lock()
	if t := m.questionTimers[sid]; t != nil {
		t.Stop()
	}
	// Debounce so we capture once the screen has settled, off the output path.
	m.questionTimers[sid] = time.AfterFunc(150*time.Millisecond, func() {
		m.captureAndEmitQuestion(sid)
	})
	m.questionMu.Unlock()
}

// captureAndEmitQuestion reads the resolved pane, parses the visible question
// group, and emits an "ask_question" event unless it duplicates the last screen
// already sent for this session.
func (m *Manager) captureAndEmitQuestion(sessionID string) {
	capture, err := m.Runtime.CaptureVisible(context.Background(), sessionID)
	if err != nil {
		return
	}
	q, ok := parseAskQuestion(capture)
	if !ok {
		return
	}

	m.questionMu.Lock()
	st := m.questionState[sessionID]
	if st == nil {
		st = &questionTrack{}
		m.questionState[sessionID] = st
	}
	if st.hash == q.ID {
		m.questionMu.Unlock()
		return
	}
	st.hash = q.ID
	q.GroupIndex = st.groupIndex
	m.questionMu.Unlock()

	payload, _ := json.Marshal(q)
	m.publishEphemeral(store.SessionEvent{
		SessionID: sessionID,
		Type:      "ask_question",
		Data:      string(payload),
	})
}

// publishEphemeral delivers a transient event to live subscribers only. Unlike
// Publish, it does not append to the event log, so the event is never replayed
// to a reconnecting client. Interactive-menu prompts (ask_question) reflect the
// live on-screen TUI: once answered, the menu is gone, so resurfacing it from a
// replay would pop a sheet the user already dismissed. The zero Seq marks the
// event as ephemeral for the client (see session_repo's seq filter).
func (m *Manager) publishEphemeral(ev store.SessionEvent) {
	m.fanout(ev)
}

// currentQuestionEvent returns an ephemeral ask_question for the menu on screen
// right now, or false if none is present. Used on subscribe so a client that
// (re)attaches while a question is still pending re-renders it; an answered
// menu has left the pane, so this yields nothing and no stale sheet appears.
func (m *Manager) currentQuestionEvent(sessionID string) (store.SessionEvent, bool) {
	capture, err := m.Runtime.CaptureVisible(context.Background(), sessionID)
	if err != nil {
		return store.SessionEvent{}, false
	}
	q, ok := parseAskQuestion(capture)
	if !ok {
		return store.SessionEvent{}, false
	}
	m.questionMu.Lock()
	if st := m.questionState[sessionID]; st != nil {
		q.GroupIndex = st.groupIndex
	}
	m.questionMu.Unlock()
	payload, _ := json.Marshal(q)
	return store.SessionEvent{
		SessionID: sessionID,
		Type:      "ask_question",
		Data:      string(payload),
	}, true
}

// clearQuestion resets a session's interactive-menu tracking so the next menu
// (a brand-new question, or one after a prompt/submit/cancel) starts fresh.
func (m *Manager) clearQuestion(sessionID string) {
	m.questionMu.Lock()
	if t := m.questionTimers[sessionID]; t != nil {
		t.Stop()
		delete(m.questionTimers, sessionID)
	}
	delete(m.questionState, sessionID)
	m.questionMu.Unlock()
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
			// Never replay interactive-menu prompts. New ones are ephemeral, but
			// sessions created before that change still have ask_question rows
			// persisted in the store; replaying them re-pops sheets the user
			// already answered. The live menu (if any) is re-emitted below.
			if ev.Type == "ask_question" {
				continue
			}
			select {
			case out <- ev:
			case <-subCtx.Done():
				return
			}
		}
		// Re-surface a menu that is still pending on screen (replay no longer
		// carries ask_question events, so a genuinely-open question would
		// otherwise be lost on reattach). Answered menus are gone from the pane
		// and yield nothing here.
		if ev, ok := m.currentQuestionEvent(sessionID); ok {
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

// cacheRE pulls a cache-hit token count out of the same usage line. Agent CLIs
// report it as "cache read", "cache hit", or "cached" followed by a number; we
// accept any of those so a cache hit is priced separately from a fresh input
// token. It is optional — a usage line without it yields zero cache tokens.
var cacheRE = regexp.MustCompile(`(?i)cach(?:e|ed)[^0-9]*(?:read|hit|tokens)?[^0-9]*(\d+)`)

// toolCallRE matches one rendered tool invocation in the agent transcript: a
// bullet glyph (Claude/Codex render tool steps as "⏺ Bash(…)" / "● Read(…)")
// followed by a CapitalCased tool name and an opening paren. It is a heuristic
// over terminal output, so it is intentionally conservative — it counts clear
// tool steps and ignores prose.
var toolCallRE = regexp.MustCompile(`(?:^|\n)\s*(?:⏺|●|•|\*|>)\s*([A-Z][A-Za-z0-9_]+)\(`)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)

func parseUsage(s string) (in, out, cache int, ok bool) {
	m := usageRE.FindStringSubmatch(s)
	if len(m) != 5 {
		return 0, 0, 0, false
	}
	_, _ = fmt.Sscanf(m[2], "%d", &in)
	_, _ = fmt.Sscanf(m[4], "%d", &out)
	if cm := cacheRE.FindStringSubmatch(s); len(cm) == 2 {
		_, _ = fmt.Sscanf(cm[1], "%d", &cache)
	}
	return in, out, cache, true
}

// countToolCalls returns how many rendered tool invocations appear in s. The
// terminal output is cleaned of ANSI control sequences first so a redraw does
// not split a marker.
func countToolCalls(s string) int {
	return len(toolCallRE.FindAllStringIndex(cleanTerminalText(s), -1))
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
	if err := r.ensurePersistentAgentDirs(); err != nil {
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
	args = append(args, agentCommandArgs(spec.Agent, spec.RunMode, r.HomeDir)...)
	if spec.Agent == "claude" && spec.ClaudeSessionID != "" {
		args = append(args, "--session-id", spec.ClaudeSessionID)
	}
	cmd := exec.CommandContext(ctx, "tmux", args...)
	cmd.Env = r.envWithPath()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tmux new-session: %w: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.CommandContext(ctx, "tmux", "select-pane", "-t", name+":0.0", "-T", spec.SessionID).Run()
	return r.Attach(ctx, spec)
}

func agentCommandArgs(agent, runMode, homeDir string) []string {
	mode := normalizeRunMode(runMode)
	switch agent {
	case "claude":
		args := []string{"claude"}
		if mode == "yolo" {
			args = append(args, "--dangerously-skip-permissions")
		} else {
			args = append(args, "--permission-mode", "default")
		}
		if dir := claudeSkillsDir(homeDir); dir != "" {
			args = append(args, "--add-dir", dir)
		}
		return args
	case "codex":
		if mode == "yolo" {
			return []string{"codex", "--dangerously-bypass-approvals-and-sandbox"}
		}
		args := []string{"codex", "--ask-for-approval", "untrusted", "--sandbox", "workspace-write"}
		if dir := codexSkillsDir(homeDir); dir != "" {
			args = append(args, "--add-dir", dir)
		}
		return args
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
		out = append(out, "CODEX_HOME="+r.codexHomeDir())
	}
	return out
}

func (r TmuxRuntime) tmuxEnvFlags() []string {
	flags := []string{}
	if r.HomeDir != "" {
		flags = append(flags, "-e", "HOME="+r.HomeDir)
		flags = append(flags, "-e", "CLAUDE_CONFIG_DIR="+r.claudeConfigDir())
		flags = append(flags, "-e", "CODEX_HOME="+r.codexHomeDir())
	}
	if path := pathWithPrefix(r.ExtraPath); path != "" {
		flags = append(flags, "-e", "PATH="+path)
	}
	return flags
}

func (r TmuxRuntime) claudeConfigDir() string {
	return filepath.Join(r.HomeDir, ".claude")
}

func (r TmuxRuntime) codexHomeDir() string {
	return filepath.Join(r.HomeDir, ".codex")
}

func (r TmuxRuntime) ensurePersistentAgentDirs() error {
	if r.HomeDir == "" {
		return nil
	}
	for _, dir := range []string{
		r.claudeConfigDir(),
		r.codexHomeDir(),
		claudeSkillsDir(r.HomeDir),
		codexSkillsDir(r.HomeDir),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create agent home dir %s: %w", dir, err)
		}
	}
	return nil
}

func claudeSkillsDir(homeDir string) string {
	if homeDir == "" {
		return ""
	}
	return filepath.Join(homeDir, ".claude", "skills")
}

func codexSkillsDir(homeDir string) string {
	if homeDir == "" {
		return ""
	}
	return filepath.Join(homeDir, ".codex", "skills")
}

func shouldReplaceEnv(kv string) bool {
	for _, prefix := range []string{
		"PATH=",
		"HOME=",
		"CLAUDE_CONFIG_DIR=",
		"CODEX_HOME=",
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

// SendApproval is unsupported on the terminal transport: approvals are driven
// in-pane via SendInput. Returns ErrNotStructured.
func (TmuxRuntime) SendApproval(context.Context, string, string, string, string) error {
	return ErrNotStructured
}

// SetMode is unsupported on the terminal transport: the mode is fixed at launch
// via the CLI args. Returns ErrNotStructured.
func (TmuxRuntime) SetMode(context.Context, string, string) error {
	return ErrNotStructured
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

// CaptureVisible snapshots only the on-screen pane (no scrollback), so selector
// parsing reflects the current frame and never picks up a stale earlier menu.
func (TmuxRuntime) CaptureVisible(ctx context.Context, sessionID string) (string, error) {
	out, err := exec.CommandContext(ctx, "tmux", "capture-pane", "-p", "-t", tmuxName(sessionID)+":0.0").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tmux capture visible: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func tmuxName(sessionID string) string {
	return "claver-" + filepath.Base(sessionID)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
