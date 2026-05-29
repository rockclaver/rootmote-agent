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
	prompts     []string
	interrupts  int
	stops       int
	captureText string
}

func (f *fakeRuntime) Start(_ context.Context, spec RuntimeSpec) error {
	f.started = append(f.started, spec)
	_, _ = io.WriteString(spec.Output, "ready\n")
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
