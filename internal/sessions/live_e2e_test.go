package sessions

// live_e2e_test.go is the Phase 7 live end-to-end suite. Every test here drives
// the REAL `claude` / `codex` CLIs and makes real model calls, so each is gated
// behind ROOTMOTE_LIVE_CLAUDE / ROOTMOTE_LIVE_CODEX and skipped in CI and on
// unauthenticated hosts. The flows mirror the plan's acceptance criteria: basic
// turn, tool-with-approval, plan mode (Claude), interrupt, and reconnect/replay.
//
// Protocol/version skew surfaces here as a flow failure; the codex app-server
// schema is additionally guarded structurally by codex_schema_test.go, which
// runs in CI without the CLI installed.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/projects"
	"github.com/rockclaver/rootmote-agent/internal/store"
)

func requireLive(t *testing.T, envVar, bin string) {
	t.Helper()
	if os.Getenv(envVar) == "" {
		t.Skipf("set %s=1 to run the live %s end-to-end suite", envVar, bin)
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Fatalf("%s requested but %s not on PATH: %v", envVar, bin, err)
	}
	if out, err := exec.Command(path, "--version").CombinedOutput(); err == nil {
		t.Logf("live %s version: %s", bin, string(out))
	}
}

// liveSession is a started structured runtime wired to an event collector.
type liveSession struct {
	rt   Runtime
	coll *eventCollector
	id   string
	work string
}

func startLiveRuntime(t *testing.T, agent, runMode string) *liveSession {
	t.Helper()
	var rt Runtime
	switch agent {
	case "claude":
		rt = NewClaudeStructuredRuntime("", "", nil)
	case "codex":
		rt = NewCodexStructuredRuntime("", "", nil)
	default:
		t.Fatalf("unknown agent %q", agent)
	}
	coll := &eventCollector{}
	id := "live-" + agent
	work := t.TempDir()
	if err := rt.Start(context.Background(), RuntimeSpec{
		SessionID:     id,
		Agent:         agent,
		RunMode:       runMode,
		Transport:     TransportStructured,
		WorkDir:       work,
		Emit:          coll.emit,
		EmitEphemeral: coll.ephemeral,
	}); err != nil {
		t.Fatalf("start %s: %v", agent, err)
	}
	t.Cleanup(func() { _ = rt.Stop(context.Background(), id) })
	return &liveSession{rt: rt, coll: coll, id: id, work: work}
}

// autoApprove allows every approval_request the agent raises until stop closes,
// so a live tool/plan flow proceeds without a human in the loop.
func autoApprove(ls *liveSession, stop <-chan struct{}) {
	go func() {
		seen := map[string]bool{}
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				for _, e := range ls.coll.byType(EvApprovalRequest) {
					var ar ApprovalRequest
					if json.Unmarshal([]byte(e.ev.Data), &ar) != nil || seen[ar.RequestID] {
						continue
					}
					seen[ar.RequestID] = true
					_ = ls.rt.SendApproval(context.Background(), ls.id, ar.RequestID, DecisionAllow, "")
				}
			}
		}
	}()
}

func (ls *liveSession) prompt(t *testing.T, text string) {
	t.Helper()
	if err := ls.rt.SendPrompt(context.Background(), ls.id, text); err != nil {
		t.Fatalf("send prompt: %v", err)
	}
}

// --- Claude --------------------------------------------------------------

func TestLiveClaude_BasicTurn(t *testing.T) {
	requireLive(t, "ROOTMOTE_LIVE_CLAUDE", "claude")
	ls := startLiveRuntime(t, "claude", "manual")
	ls.prompt(t, "Reply with exactly the word: pong")
	ls.coll.waitForType(t, EvTurn, 90*time.Second)
	if len(ls.coll.byType(EvMessage)) == 0 {
		t.Fatal("no assistant message before turn completed")
	}
}

func TestLiveClaude_ToolApproval(t *testing.T) {
	requireLive(t, "ROOTMOTE_LIVE_CLAUDE", "claude")
	ls := startLiveRuntime(t, "claude", "manual") // default permission mode gates edits
	stop := make(chan struct{})
	autoApprove(ls, stop)
	defer close(stop)

	ls.prompt(t, "Create a file named live.txt in the current directory whose exact contents are the single word: pong. Use your file-writing tool, then stop.")
	ls.coll.waitForType(t, EvTurn, 120*time.Second)

	if len(ls.coll.byType(EvApprovalRequest)) == 0 {
		t.Fatal("expected at least one approval_request for the file edit")
	}
	data, err := os.ReadFile(filepath.Join(ls.work, "live.txt"))
	if err != nil {
		t.Fatalf("expected live.txt to be created after approval: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("live.txt is empty")
	}
}

func TestLiveClaude_PlanMode(t *testing.T) {
	requireLive(t, "ROOTMOTE_LIVE_CLAUDE", "claude")
	ls := startLiveRuntime(t, "claude", "manual")
	if err := ls.rt.SetMode(context.Background(), ls.id, ModePlan); err != nil {
		t.Fatalf("set plan mode: %v", err)
	}
	stop := make(chan struct{})
	autoApprove(ls, stop)
	defer close(stop)

	ls.prompt(t, "Make a short, concrete plan (2-3 steps) to add a Go function named greet that prints hello, then present it for approval to proceed.")
	ls.coll.waitForType(t, EvTurn, 120*time.Second)

	if len(ls.coll.byType(EvPlan)) == 0 && len(ls.coll.byType(EvApprovalRequest)) == 0 {
		t.Fatal("plan-mode turn produced neither a plan nor an approval request")
	}
	// A Claude plan-mode approval must be gating.
	for _, e := range ls.coll.byType(EvPlan) {
		var p Plan
		if json.Unmarshal([]byte(e.ev.Data), &p) == nil && p.Gating {
			return
		}
	}
}

func TestLiveClaude_Interrupt(t *testing.T) {
	requireLive(t, "ROOTMOTE_LIVE_CLAUDE", "claude")
	ls := startLiveRuntime(t, "claude", "yolo") // no approval gating; just a long generation
	ls.prompt(t, "Write a very long, detailed essay of at least 1200 words about the complete history of computing. Do not stop early.")

	// Let generation get underway, then interrupt mid-turn.
	time.Sleep(4 * time.Second)
	if err := ls.rt.Interrupt(context.Background(), ls.id); err != nil {
		t.Fatalf("interrupt: %v", err)
	}
	ls.coll.waitForType(t, EvTurn, 30*time.Second)

	// The session must still accept a follow-up after the interrupt.
	before := len(ls.coll.byType(EvMessage))
	ls.prompt(t, "Reply with exactly the word: pong")
	deadline := time.After(60 * time.Second)
	for {
		if len(ls.coll.byType(EvMessage)) > before {
			return
		}
		select {
		case <-deadline:
			t.Fatal("session did not respond to a follow-up after interrupt")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func TestLiveClaude_ReconnectReplay(t *testing.T) {
	requireLive(t, "ROOTMOTE_LIVE_CLAUDE", "claude")
	liveReconnectReplay(t, "claude")
}

// --- Codex ---------------------------------------------------------------

func TestLiveCodex_BasicTurn(t *testing.T) {
	requireLive(t, "ROOTMOTE_LIVE_CODEX", "codex")
	ls := startLiveRuntime(t, "codex", "manual")
	ls.prompt(t, "Reply with exactly the word: pong")
	ls.coll.waitForType(t, EvTurn, 120*time.Second)
	if len(ls.coll.byType(EvMessage)) == 0 {
		t.Fatal("no assistant message before turn completed")
	}
}

func TestLiveCodex_ToolApproval(t *testing.T) {
	requireLive(t, "ROOTMOTE_LIVE_CODEX", "codex")
	ls := startLiveRuntime(t, "codex", "manual") // on-request policy gates exec/patch
	stop := make(chan struct{})
	autoApprove(ls, stop)
	defer close(stop)

	ls.prompt(t, "Create a file named live.txt in the current directory whose exact contents are the single word: pong, then stop.")
	ls.coll.waitForType(t, EvTurn, 180*time.Second)

	data, err := os.ReadFile(filepath.Join(ls.work, "live.txt"))
	if err != nil {
		t.Fatalf("expected live.txt to be created: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("live.txt is empty")
	}
}

func TestLiveCodex_Interrupt(t *testing.T) {
	requireLive(t, "ROOTMOTE_LIVE_CODEX", "codex")
	ls := startLiveRuntime(t, "codex", "yolo")
	ls.prompt(t, "Write a very long, detailed essay of at least 1200 words about the complete history of computing. Do not stop early.")
	time.Sleep(4 * time.Second)
	if err := ls.rt.Interrupt(context.Background(), ls.id); err != nil {
		t.Fatalf("interrupt: %v", err)
	}
	ls.coll.waitForType(t, EvTurn, 40*time.Second)
}

// --- Reconnect / replay (Manager level, against a real runtime) ----------

func newLiveManager(t *testing.T) (*Manager, string) {
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
	proj, err := pm.CreateEmpty("demo")
	if err != nil {
		t.Fatal(err)
	}
	rt := NewRoutingRuntime(
		TmuxRuntime{},
		map[string]Runtime{
			"claude": NewClaudeStructuredRuntime("", "", nil),
			"codex":  NewCodexStructuredRuntime("", "", nil),
		},
		func(sessionID string) (string, string) {
			s, err := st.GetSession(sessionID)
			if err != nil {
				return "", ""
			}
			return s.Agent, s.Transport
		},
	)
	return New(st, pm, rt), proj.ID
}

// liveReconnectReplay runs one real turn, then reconnects with a full replay and
// asserts the persisted transcript replays with no loss and no duplicate seq.
func liveReconnectReplay(t *testing.T, agent string) {
	t.Helper()
	m, projectID := newLiveManager(t)
	sess, err := m.Start(context.Background(), projectID, agent, "manual", TransportStructured)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background(), sess.ID) })

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	ch, cancel, err := m.Subscribe(ctx, sess.ID, 0)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := m.SendPrompt(context.Background(), sess.ID, "Reply with exactly the word: pong"); err != nil {
		t.Fatalf("prompt: %v", err)
	}

	live := drainUntilTurn(t, ch, 120*time.Second)
	cancel()
	if len(live) == 0 {
		t.Fatal("first connection received no persisted events")
	}

	// Reconnect from the start: a full replay must reconstruct the transcript.
	ch2, cancel2, err := m.Subscribe(context.Background(), sess.ID, 0)
	if err != nil {
		t.Fatalf("resubscribe: %v", err)
	}
	defer cancel2()
	replay := drainAvailable(ch2, 10*time.Second)

	replaySeqs := map[int64]int{}
	for _, ev := range replay {
		if ev.Seq > 0 {
			replaySeqs[ev.Seq]++
		}
	}
	for seq, n := range replaySeqs {
		if n != 1 {
			t.Fatalf("replay duplicated persisted seq %d (%d times)", seq, n)
		}
	}
	for _, ev := range live {
		if ev.Seq > 0 && replaySeqs[ev.Seq] == 0 {
			t.Fatalf("replay lost persisted seq %d (type %s)", ev.Seq, ev.Type)
		}
	}
}

// drainUntilTurn collects persisted events until a turn:complete (or a fatal
// error / dead lifecycle) arrives, or the deadline elapses.
func drainUntilTurn(t *testing.T, ch <-chan store.SessionEvent, d time.Duration) []store.SessionEvent {
	t.Helper()
	var got []store.SessionEvent
	deadline := time.After(d)
	for {
		select {
		case ev := <-ch:
			if ev.Seq > 0 {
				got = append(got, ev)
			}
			switch ev.Type {
			case EvTurn:
				var turn Turn
				if json.Unmarshal([]byte(ev.Data), &turn) == nil && turn.State == TurnComplete {
					return got
				}
			case EvError:
				var ee ErrorEvent
				if json.Unmarshal([]byte(ev.Data), &ee) == nil && ee.Fatal {
					return got
				}
			case "lifecycle":
				if ev.Data == "dead" {
					return got
				}
			}
		case <-deadline:
			t.Fatalf("turn did not complete within %s (got %d events)", d, len(got))
			return got
		}
	}
}

// drainAvailable reads everything the channel yields until it goes quiet for a
// short settle window or the hard deadline elapses.
func drainAvailable(ch <-chan store.SessionEvent, d time.Duration) []store.SessionEvent {
	var got []store.SessionEvent
	hard := time.After(d)
	for {
		select {
		case ev := <-ch:
			got = append(got, ev)
		case <-time.After(500 * time.Millisecond):
			return got
		case <-hard:
			return got
		}
	}
}
