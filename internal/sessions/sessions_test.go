package sessions

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/claver-agent/internal/projects"
	"github.com/rockclaver/claver-agent/internal/store"
)

type fakeRuntime struct {
	started     []RuntimeSpec
	attached    []RuntimeSpec
	prompts     []string
	inputs      []string
	interrupts  int
	resizes     [][2]int
	stops       int
	captureText string
	dead        bool
	approvals   []string
	modes       []string
}

func (f *fakeRuntime) Start(_ context.Context, spec RuntimeSpec) error {
	f.started = append(f.started, spec)
	_, _ = io.WriteString(spec.Output, "ready\n")
	return nil
}
func (f *fakeRuntime) Attach(_ context.Context, spec RuntimeSpec) error {
	f.attached = append(f.attached, spec)
	_, _ = io.WriteString(spec.Output, "attached\n")
	return nil
}
func (f *fakeRuntime) SendPrompt(_ context.Context, sessionID, prompt string) error {
	f.prompts = append(f.prompts, sessionID+":"+prompt)
	return nil
}
func (f *fakeRuntime) SendInput(_ context.Context, sessionID, data string) error {
	f.inputs = append(f.inputs, sessionID+":"+data)
	return nil
}
func (f *fakeRuntime) Interrupt(context.Context, string) error {
	f.interrupts++
	return nil
}
func (f *fakeRuntime) Resize(_ context.Context, _ string, cols, rows int) error {
	f.resizes = append(f.resizes, [2]int{cols, rows})
	return nil
}
func (f *fakeRuntime) Stop(context.Context, string) error {
	f.stops++
	return nil
}
func (f *fakeRuntime) Capture(context.Context, string) (string, error) {
	return f.captureText, nil
}
func (f *fakeRuntime) CaptureVisible(context.Context, string) (string, error) {
	return f.captureText, nil
}
func (f *fakeRuntime) Alive(context.Context, string) bool {
	return !f.dead
}
func (f *fakeRuntime) SendApproval(_ context.Context, sessionID, requestID, decision, note string) error {
	f.approvals = append(f.approvals, sessionID+":"+requestID+":"+decision+":"+note)
	return nil
}
func (f *fakeRuntime) SetMode(_ context.Context, sessionID, mode string) error {
	f.modes = append(f.modes, sessionID+":"+mode)
	return nil
}

func newTestManager(t *testing.T) (*Manager, *fakeRuntime) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pm, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "p1" }
	if _, err := pm.CreateEmpty("demo"); err != nil {
		t.Fatal(err)
	}
	rt := &fakeRuntime{}
	m := New(st, pm, rt)
	m.IDGen = func() string { return "s1" }
	m.Now = func() time.Time { return time.Unix(100, 0) }
	return m, rt
}

// AC: "Starting a session creates a tmux pane named by session ID; tmux
// pipe-pane streams output into Stream Hub."
func TestStartSession_CreatesRuntimePaneAndStreamsOutput(t *testing.T) {
	m, rt := newTestManager(t)
	sess, err := m.Start(context.Background(), "p1", "codex", "manual", "")
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID != "s1" || len(rt.started) != 1 || rt.started[0].SessionID != "s1" {
		t.Fatalf("runtime start mismatch: sess=%+v started=%+v", sess, rt.started)
	}
	if rt.started[0].RunMode != "manual" {
		t.Fatalf("run mode = %q want manual", rt.started[0].RunMode)
	}
	evs, err := m.Store.SessionEventsAfter("s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) < 2 || evs[0].Type != "stdout" || !strings.Contains(evs[0].Data, "ready") {
		t.Fatalf("stream events missing: %+v", evs)
	}
}

// AC: "Stream Hub multiplexes events to subscribed mobile clients with
// backpressure; no event loss observed under simulated slow client."
func TestStreamHub_NoEventLossWithSlowClient(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", ""); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, cleanup, err := m.Subscribe(ctx, "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, data := range []string{"a", "b", "c"} {
		if _, err := m.Publish(store.SessionEvent{SessionID: "s1", Type: "stdout", Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"ready\n", "started", "a", "b", "c"}
	for _, w := range want {
		select {
		case ev := <-ch:
			if ev.Data != w {
				t.Fatalf("got %q want %q", ev.Data, w)
			}
			time.Sleep(5 * time.Millisecond)
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %q", w)
		}
	}
}

// Issue #57 AC: "Every started session loads relevant memory into the agent
// prompt context." Start injects the MemorySource block as the agent's first
// prompt and records it as a "memory" event.
func TestStartSession_InjectsProjectMemory(t *testing.T) {
	m, rt := newTestManager(t)
	m.MemorySource = func(projectID string) string {
		if projectID != "p1" {
			t.Fatalf("memory requested for wrong project: %q", projectID)
		}
		return "# Project memory\nUse tabs.\n"
	}
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", ""); err != nil {
		t.Fatal(err)
	}
	if len(rt.prompts) != 1 || !strings.Contains(rt.prompts[0], "Use tabs") {
		t.Fatalf("memory not injected as prompt: %+v", rt.prompts)
	}
	evs, _ := m.Store.SessionEventsAfter("s1", 0)
	var sawMemory bool
	for _, ev := range evs {
		if ev.Type == "memory" && strings.Contains(ev.Data, "Use tabs") {
			sawMemory = true
		}
	}
	if !sawMemory {
		t.Fatalf("memory event not recorded: %+v", evs)
	}
}

// Empty memory must not inject any prompt.
func TestStartSession_NoMemoryNoPrompt(t *testing.T) {
	m, rt := newTestManager(t)
	m.MemorySource = func(string) string { return "  " }
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", ""); err != nil {
		t.Fatal(err)
	}
	if len(rt.prompts) != 0 {
		t.Fatalf("expected no injected prompt, got %+v", rt.prompts)
	}
}

// Stop fires the OnEnd hook with the ended session row (EndedAt populated).
func TestStop_FiresOnEndHook(t *testing.T) {
	m, _ := newTestManager(t)
	var got store.Session
	called := 0
	m.OnEnd = func(_ context.Context, sess store.Session) {
		called++
		got = sess
	}
	if _, err := m.Start(context.Background(), "p1", "codex", "manual", ""); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if called != 1 || got.ID != "s1" || got.EndedAt == nil {
		t.Fatalf("OnEnd not fired correctly: called=%d sess=%+v", called, got)
	}
}

// Review comment #3323370015: replaying more events than the subscriber buffer
// must not block Subscribe before the caller can start reading.
func TestSubscribe_ReplaysMoreThanBufferWithoutDeadlock(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 80; i++ {
		if _, err := m.Publish(store.SessionEvent{SessionID: "s1", Type: "stdout", Data: "x"}); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type result struct {
		ch      <-chan store.SessionEvent
		cleanup func()
		err     error
	}
	done := make(chan result, 1)
	go func() {
		ch, cleanup, err := m.Subscribe(ctx, "s1", 0)
		done <- result{ch: ch, cleanup: cleanup, err: err}
	}()

	var got result
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatal("Subscribe deadlocked on replay backlog")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	defer got.cleanup()

	count := 0
	for count < 82 {
		select {
		case <-got.ch:
			count++
		case <-ctx.Done():
			t.Fatalf("timed out after %d replay events", count)
		}
	}
}

func TestSubscribe_CleanupDoesNotRequireParentContextCancel(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 80; i++ {
		if _, err := m.Publish(store.SessionEvent{SessionID: "s1", Type: "stdout", Data: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	_, cleanup, err := m.Subscribe(context.Background(), "s1", 0)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup waited for parent context cancellation")
	}
}

// AC: "Prompts sent from mobile reach the agent in the pane and produce
// streamed output within the NFR latency budget."
func TestPrompt_ReachesRuntimePaneAndCanStreamOutput(t *testing.T) {
	m, rt := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "codex", "manual", ""); err != nil {
		t.Fatal(err)
	}
	if err := m.SendPrompt(context.Background(), "s1", "explain"); err != nil {
		t.Fatal(err)
	}
	if len(rt.prompts) != 1 || rt.prompts[0] != "s1:explain" {
		t.Fatalf("prompt not delivered: %+v", rt.prompts)
	}
}

func TestSendInput_ForwardsRawBytesAndSkipsEmpty(t *testing.T) {
	m, rt := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "codex", "manual", ""); err != nil {
		t.Fatal(err)
	}
	// An empty payload is a no-op and must not reach the runtime.
	if err := m.SendInput(context.Background(), "s1", ""); err != nil {
		t.Fatal(err)
	}
	// A scroll escape sequence (arrow-down) is forwarded verbatim.
	if err := m.SendInput(context.Background(), "s1", "\x1b[B"); err != nil {
		t.Fatal(err)
	}
	if len(rt.inputs) != 1 || rt.inputs[0] != "s1:\x1b[B" {
		t.Fatalf("input not delivered verbatim: %+v", rt.inputs)
	}
	if err := m.SendInput(context.Background(), "missing", "x"); err == nil {
		t.Fatal("expected error for unknown session")
	}
}

func TestClaudeFirstRunAdvancer_SelectsDefaultThemeOnce(t *testing.T) {
	var out bytes.Buffer
	var sends []string
	w := newClaudeFirstRunAdvancer(&out, "s1", func(_ context.Context, sessionID string) error {
		sends = append(sends, sessionID)
		return nil
	})

	if _, err := w.Write([]byte("\x1b[2mChoose the text ")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("style that looks best with your terminal\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("Syntax theme: Monokai Extended\n")); err != nil {
		t.Fatal(err)
	}

	if got := out.String(); !strings.Contains(got, "Choose the text style") {
		t.Fatalf("output was not forwarded: %q", got)
	}
	if len(sends) != 1 || sends[0] != "s1" {
		t.Fatalf("enter sends mismatch: %+v", sends)
	}

	if _, err := w.Write([]byte("Syntax theme: Monokai Extended\n")); err != nil {
		t.Fatal(err)
	}
	if len(sends) != 1 {
		t.Fatalf("theme enter repeated: %+v", sends)
	}
}

func TestClaudeFirstRunAdvancer_AdvancesLoginMethodAfterTheme(t *testing.T) {
	var out bytes.Buffer
	var sends []string
	w := newClaudeFirstRunAdvancer(&out, "s1", func(_ context.Context, sessionID string) error {
		sends = append(sends, sessionID)
		return nil
	})

	if _, err := w.Write([]byte("Choose the text style that looks best with your terminal\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("Select login method:\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("1. Claude account with subscription - Pro, Max, Team, or Enterprise\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("2. Anthropic Console account - API usage billing\n")); err != nil {
		t.Fatal(err)
	}

	if len(sends) != 2 {
		t.Fatalf("enter sends mismatch: %+v", sends)
	}
}

// AC: "Interrupt sends a signal that stops generation without killing the
// pane; the session can receive another prompt afterward."
func TestInterrupt_LeavesSessionPromptable(t *testing.T) {
	m, rt := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "codex", "manual", ""); err != nil {
		t.Fatal(err)
	}
	if err := m.Interrupt(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if err := m.SendPrompt(context.Background(), "s1", "continue"); err != nil {
		t.Fatal(err)
	}
	if rt.interrupts != 1 || len(rt.prompts) != 1 {
		t.Fatalf("interrupt/prompt mismatch: %+v", rt)
	}
}

// AC: "Killing and restarting the agent process rehydrates the in-flight
// session; the user sees no data loss beyond what tmux itself drops."
func TestRehydrate_CapturesActiveTmuxPane(t *testing.T) {
	m, rt := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", ""); err != nil {
		t.Fatal(err)
	}
	rt.captureText = "still running\n"
	if err := m.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	log, err := m.Log("s1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log, "still running") {
		t.Fatalf("rehydrated log missing: %q", log)
	}
}

// Review comment #3323370019: restart rehydration must reinstall streaming for
// existing tmux panes, not only capture a one-time snapshot.
func TestRehydrate_AttachesStreamingToActiveTmuxPane(t *testing.T) {
	m, rt := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", ""); err != nil {
		t.Fatal(err)
	}
	rt.captureText = "still running\n"

	if err := m.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rt.attached) != 1 || rt.attached[0].SessionID != "s1" || rt.attached[0].Agent != "claude" {
		t.Fatalf("reattach mismatch: %+v", rt.attached)
	}
	log, err := m.Log("s1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log, "still running") || !strings.Contains(log, "attached") {
		t.Fatalf("rehydrated stream missing: %q", log)
	}
}

// Phase 9 AC2: "Killing the agent during a streaming session and restarting
// it loses no committed event beyond the in-flight tmux buffer."
//
// We model agent restart by spinning up a Manager, publishing events, then
// throwing the Manager away and creating a brand-new Manager pointing at the
// same Store + Projects. After Rehydrate(), a subscriber from afterSeq=0
// receives every committed event plus continues to see new live events.
func TestRehydrate_AcrossAgentRestart_LosesNoCommittedEvent(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pm, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "p1" }
	if _, err := pm.CreateEmpty("demo"); err != nil {
		t.Fatal(err)
	}

	rt1 := &fakeRuntime{}
	m1 := New(st, pm, rt1)
	m1.IDGen = func() string { return "s1" }
	m1.Now = func() time.Time { return time.Unix(100, 0) }
	if _, err := m1.Start(context.Background(), "p1", "codex", "manual", ""); err != nil {
		t.Fatal(err)
	}
	// Publish committed events that should survive the crash.
	for _, line := range []string{"committed-1\n", "committed-2\n", "committed-3\n"} {
		if _, err := m1.Publish(store.SessionEvent{SessionID: "s1", Type: "stdout", Data: line}); err != nil {
			t.Fatal(err)
		}
	}

	// "Crash" m1: drop the reference, build a fresh manager from the same store.
	rt2 := &fakeRuntime{captureText: "tmux-buffer-still-running\n"}
	m2 := New(st, pm, rt2)
	m2.IDGen = func() string { return "s1" }
	m2.Now = func() time.Time { return time.Unix(200, 0) }
	if err := m2.Rehydrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Subscribe from seq=0 and verify every committed event is replayed before
	// any new live events.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, done, err := m2.Subscribe(ctx, "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer done()

	got := make([]string, 0, 8)
	deadline := time.After(2 * time.Second)
collect:
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				break collect
			}
			if ev.Type == "stdout" {
				got = append(got, strings.TrimSpace(ev.Data))
			}
			if len(got) >= 6 {
				break collect
			}
		case <-deadline:
			t.Fatalf("timed out waiting for replay; got %v", got)
		}
	}

	for _, want := range []string{"committed-1", "committed-2", "committed-3"} {
		if !contains(got, want) {
			t.Fatalf("committed event %q lost after restart; got %v", want, got)
		}
	}
	// tmux buffer snapshot also makes it into the stream.
	if !contains(got, "tmux-buffer-still-running") {
		t.Fatalf("rehydrated tmux buffer missing from stream: %v", got)
	}
	// Reattach should have been called once on restart.
	if len(rt2.attached) != 1 || rt2.attached[0].SessionID != "s1" {
		t.Fatalf("reattach mismatch: %+v", rt2.attached)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// AC: "Session list shows started/ended timestamps and per-session token usage
// (parsed from the agent's own usage output)."
func TestUsageOutput_UpdatesSessionList(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Publish(store.SessionEvent{SessionID: "s1", Type: "stdout", Data: "input tokens: 12 output tokens: 34"}); err != nil {
		t.Fatal(err)
	}
	got, err := m.List("p1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].InputTokens != 12 || got[0].OutputTokens != 34 {
		t.Fatalf("usage mismatch: %+v", got)
	}
}

// AC (#60): per-session usage accounting parses cache-hit tokens alongside
// input/output, and counts rendered tool calls. These are pure-function tests
// over the parsers so they stay fast (no tmux).
func TestParseUsage_WithCacheTokens(t *testing.T) {
	in, out, cache, ok := parseUsage("input tokens: 120  output tokens: 45  cache read: 900")
	if !ok || in != 120 || out != 45 || cache != 900 {
		t.Fatalf("parse = %d/%d/%d ok=%v", in, out, cache, ok)
	}
	// No cache term → cache is zero but the line still parses.
	in, out, cache, ok = parseUsage("input tokens: 12 output tokens: 34")
	if !ok || in != 12 || out != 34 || cache != 0 {
		t.Fatalf("parse w/o cache = %d/%d/%d ok=%v", in, out, cache, ok)
	}
	if _, _, _, ok := parseUsage("no usage here"); ok {
		t.Fatal("expected no match for prose")
	}
}

func TestCountToolCalls(t *testing.T) {
	transcript := "⏺ Bash(ls -la)\nsome output\n● Read(main.go)\n> Edit(x.go)\njust prose Foo(bar) inline\n"
	if n := countToolCalls(transcript); n != 3 {
		t.Fatalf("tool calls = %d, want 3", n)
	}
	if n := countToolCalls("plain text, no tools"); n != 0 {
		t.Fatalf("expected 0 tool calls, got %d", n)
	}
}

// AC (#60): folding a stdout event accumulates usage and tool calls onto the
// session row keyed by project.
func TestAccountUsage_PersistsViaPublish(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Publish(store.SessionEvent{SessionID: "s1", Type: "stdout",
		Data: "input tokens: 200 output tokens: 80 cache read: 1000\n⏺ Bash(go test)\n● Read(x)"}); err != nil {
		t.Fatal(err)
	}
	got, err := m.List("p1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("sessions = %d", len(got))
	}
	s := got[0]
	if s.InputTokens != 200 || s.OutputTokens != 80 || s.CacheTokens != 1000 {
		t.Fatalf("usage not accounted: %+v", s)
	}
	if s.ToolCalls != 2 {
		t.Fatalf("tool calls = %d, want 2", s.ToolCalls)
	}
}

// AC: "No code path exposes an arbitrary shell command to the mobile UI."
func TestStartSession_RejectsArbitraryAgentCommand(t *testing.T) {
	m, _ := newTestManager(t)
	_, err := m.Start(context.Background(), "p1", "sh -c rm -rf /", "manual", "")
	if err == nil {
		t.Fatal("expected bad agent error")
	}
}

func TestStartSession_RejectsUnknownRunMode(t *testing.T) {
	m, _ := newTestManager(t)
	_, err := m.Start(context.Background(), "p1", "codex", "custom", "")
	if !errors.Is(err, ErrBadMode) {
		t.Fatalf("err = %v want ErrBadMode", err)
	}
}

func TestStartSession_RejectsUnauthenticatedAgent(t *testing.T) {
	m, rt := newTestManager(t)
	m.AuthOK = func(context.Context, string) bool { return false }
	_, err := m.Start(context.Background(), "p1", "claude", "manual", "")
	if !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("err = %v want ErrAuthRequired", err)
	}
	if len(rt.started) != 0 {
		t.Fatalf("runtime should not start unauthenticated agent: %+v", rt.started)
	}
}

func TestAgentCommandArgs_MapRunModesToCliFlags(t *testing.T) {
	cases := []struct {
		name    string
		agent   string
		mode    string
		wantArg string
	}{
		{"codex manual", "codex", "manual", "--ask-for-approval"},
		{"codex yolo", "codex", "yolo", "--dangerously-bypass-approvals-and-sandbox"},
		{"claude manual", "claude", "manual", "--permission-mode"},
		{"claude yolo", "claude", "yolo", "--dangerously-skip-permissions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := agentCommandArgs(tc.agent, tc.mode, "/var/lib/claver")
			if !contains(got, tc.wantArg) {
				t.Fatalf("args = %#v want %q", got, tc.wantArg)
			}
		})
	}
}

func TestAgentCommandArgs_AddPersistentSkillDirs(t *testing.T) {
	home := "/var/lib/claver"
	codexArgs := agentCommandArgs("codex", "manual", home)
	if !contains(codexArgs, "--add-dir") || !contains(codexArgs, filepath.Join(home, ".codex", "skills")) {
		t.Fatalf("codex args missing persistent skills dir: %#v", codexArgs)
	}
	claudeArgs := agentCommandArgs("claude", "manual", home)
	if !contains(claudeArgs, "--add-dir") || !contains(claudeArgs, filepath.Join(home, ".claude", "skills")) {
		t.Fatalf("claude args missing persistent skills dir: %#v", claudeArgs)
	}
}

func TestTmuxRuntimeEnvUsesConfiguredHome(t *testing.T) {
	rt := TmuxRuntime{ExtraPath: "/opt/claver/bin", HomeDir: "/var/lib/claver"}
	env := rt.envWithPath()
	if !contains(env, "HOME=/var/lib/claver") {
		t.Fatalf("env missing configured HOME: %#v", env)
	}
	if !contains(env, "CLAUDE_CONFIG_DIR=/var/lib/claver/.claude") {
		t.Fatalf("env missing configured CLAUDE_CONFIG_DIR: %#v", env)
	}
	if !contains(env, "CODEX_HOME=/var/lib/claver/.codex") {
		t.Fatalf("env missing configured CODEX_HOME: %#v", env)
	}
	foundPath := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=/opt/claver/bin:") || kv == "PATH=/opt/claver/bin" {
			foundPath = true
			break
		}
	}
	if !foundPath {
		t.Fatalf("env missing configured PATH prefix: %#v", env)
	}
	flags := strings.Join(rt.tmuxEnvFlags(), "\n")
	if !strings.Contains(flags, "HOME=/var/lib/claver") {
		t.Fatalf("tmux flags missing HOME: %q", flags)
	}
	if !strings.Contains(flags, "CLAUDE_CONFIG_DIR=/var/lib/claver/.claude") {
		t.Fatalf("tmux flags missing CLAUDE_CONFIG_DIR: %q", flags)
	}
	if !strings.Contains(flags, "CODEX_HOME=/var/lib/claver/.codex") {
		t.Fatalf("tmux flags missing CODEX_HOME: %q", flags)
	}
	if !strings.Contains(flags, "PATH=/opt/claver/bin") {
		t.Fatalf("tmux flags missing PATH prefix: %q", flags)
	}
}

func TestTmuxRuntimeCreatesPersistentSkillDirs(t *testing.T) {
	home := t.TempDir()
	rt := TmuxRuntime{HomeDir: home}
	if err := rt.ensurePersistentAgentDirs(); err != nil {
		t.Fatalf("ensurePersistentAgentDirs: %v", err)
	}
	for _, dir := range []string{
		filepath.Join(home, ".codex", "skills"),
		filepath.Join(home, ".claude", "skills"),
	} {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			t.Fatalf("expected persistent skills dir %s, stat=%v info=%+v", dir, err, fi)
		}
	}
}

func TestTmuxRuntimeEnvStripsAmbientAnthropicCredentials(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "bad")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "bad")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "bad")
	t.Setenv("CODEX_HOME", "/tmp/wrong-codex-home")
	rt := TmuxRuntime{ExtraPath: "/opt/claver/bin", HomeDir: "/var/lib/claver"}
	env := strings.Join(rt.envWithPath(), "\n")
	for _, forbidden := range []string{
		"ANTHROPIC_API_KEY=bad",
		"ANTHROPIC_AUTH_TOKEN=bad",
		"CLAUDE_CODE_OAUTH_TOKEN=bad",
		"CODEX_HOME=/tmp/wrong-codex-home",
	} {
		if strings.Contains(env, forbidden) {
			t.Fatalf("env leaked %s: %q", forbidden, env)
		}
	}
}
