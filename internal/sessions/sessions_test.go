package sessions

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/store"
)

type fakeRuntime struct {
	started     []RuntimeSpec
	attached    []RuntimeSpec
	prompts     []string
	interrupts  int
	stops       int
	captureText string
	dead        bool
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
func (f *fakeRuntime) Interrupt(context.Context, string) error {
	f.interrupts++
	return nil
}
func (f *fakeRuntime) Stop(context.Context, string) error {
	f.stops++
	return nil
}
func (f *fakeRuntime) Capture(context.Context, string) (string, error) {
	return f.captureText, nil
}
func (f *fakeRuntime) Alive(context.Context, string) bool {
	return !f.dead
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
	sess, err := m.Start(context.Background(), "p1", "codex")
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID != "s1" || len(rt.started) != 1 || rt.started[0].SessionID != "s1" {
		t.Fatalf("runtime start mismatch: sess=%+v started=%+v", sess, rt.started)
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
	if _, err := m.Start(context.Background(), "p1", "claude"); err != nil {
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

// Review comment #3323370015: replaying more events than the subscriber buffer
// must not block Subscribe before the caller can start reading.
func TestSubscribe_ReplaysMoreThanBufferWithoutDeadlock(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude"); err != nil {
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
	if _, err := m.Start(context.Background(), "p1", "claude"); err != nil {
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
	if _, err := m.Start(context.Background(), "p1", "codex"); err != nil {
		t.Fatal(err)
	}
	if err := m.SendPrompt(context.Background(), "s1", "explain"); err != nil {
		t.Fatal(err)
	}
	if len(rt.prompts) != 1 || rt.prompts[0] != "s1:explain" {
		t.Fatalf("prompt not delivered: %+v", rt.prompts)
	}
}

// AC: "Interrupt sends a signal that stops generation without killing the
// pane; the session can receive another prompt afterward."
func TestInterrupt_LeavesSessionPromptable(t *testing.T) {
	m, rt := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "codex"); err != nil {
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
	if _, err := m.Start(context.Background(), "p1", "claude"); err != nil {
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
	if _, err := m.Start(context.Background(), "p1", "claude"); err != nil {
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
	if _, err := m1.Start(context.Background(), "p1", "codex"); err != nil {
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
	if _, err := m.Start(context.Background(), "p1", "claude"); err != nil {
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

// AC: "No code path exposes an arbitrary shell command to the mobile UI."
func TestStartSession_RejectsArbitraryAgentCommand(t *testing.T) {
	m, _ := newTestManager(t)
	_, err := m.Start(context.Background(), "p1", "sh -c rm -rf /")
	if err == nil {
		t.Fatal("expected bad agent error")
	}
}
