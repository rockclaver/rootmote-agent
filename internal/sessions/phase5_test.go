package sessions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rockclaver/claver-agent/internal/store"
)

// publishNormalized appends a normalized structured event through the Manager's
// Publish path (which runs accountUsage), mirroring what a structured runtime
// emits via spec.Emit.
func publishNormalized(t *testing.T, m *Manager, sessionID, evType string, payload any) {
	t.Helper()
	ev, err := normalizedEvent(sessionID, evType, payload)
	if err != nil {
		t.Fatalf("normalize %s: %v", evType, err)
	}
	if _, err := m.Publish(ev); err != nil {
		t.Fatalf("publish %s: %v", evType, err)
	}
}

// AC (Phase 5 #1): structured usage events feed the per-project cost columns.
// Per-turn usage deltas accumulate; each tool call counts once at its started
// transition; no regex/transcript scrape is involved.
func TestStructuredUsage_AccumulatesIntoSessionRow(t *testing.T) {
	m, _ := newTestManager(t)
	sess, err := m.Start(context.Background(), "p1", "claude", "manual", TransportStructured)
	if err != nil {
		t.Fatal(err)
	}

	publishNormalized(t, m, sess.ID, EvUsage, Usage{Input: 100, Output: 20, Cache: 5, CostUSD: 0.01})
	publishNormalized(t, m, sess.ID, EvUsage, Usage{Input: 200, Output: 30, Cache: 7, CostUSD: 0.02})
	publishNormalized(t, m, sess.ID, EvToolCall, ToolCall{CallID: "a", Name: "Bash", Status: ToolStarted})
	publishNormalized(t, m, sess.ID, EvToolCall, ToolCall{CallID: "a", Name: "Bash", Status: ToolCompleted})
	publishNormalized(t, m, sess.ID, EvToolCall, ToolCall{CallID: "b", Name: "Read", Status: ToolStarted})

	got, err := m.Store.GetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.InputTokens != 300 || got.OutputTokens != 50 || got.CacheTokens != 12 {
		t.Fatalf("tokens = %d/%d/%d, want 300/50/12", got.InputTokens, got.OutputTokens, got.CacheTokens)
	}
	// Only the two "started" transitions count; "completed" must not double-count.
	if got.ToolCalls != 2 {
		t.Fatalf("tool_calls = %d, want 2", got.ToolCalls)
	}
}

// The terminal stdout regex path must stay intact for the terminal transport
// and must not be reached by structured (typed) events.
func TestTerminalUsage_StillScrapesStdout(t *testing.T) {
	m, _ := newTestManager(t)
	sess, err := m.Start(context.Background(), "p1", "claude", "manual", TransportTerminal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Publish(store.SessionEvent{SessionID: sess.ID, Type: "stdout", Data: "input tokens: 42 output tokens: 7"}); err != nil {
		t.Fatal(err)
	}
	got, err := m.Store.GetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.InputTokens != 42 || got.OutputTokens != 7 {
		t.Fatalf("scraped tokens = %d/%d, want 42/7", got.InputTokens, got.OutputTokens)
	}
}

// AC (Phase 5 #2): resume reattaches to a prior structured session in place,
// continuing the same row/event log and reloading the agent conversation.
func TestResume_ReattachesSameSession(t *testing.T) {
	m, rt := newTestManager(t)
	sess, err := m.Start(context.Background(), "p1", "claude", "manual", TransportStructured)
	if err != nil {
		t.Fatal(err)
	}
	// The runtime reported its agent-native conversation handle on start.
	if got, _ := m.Store.GetSession(sess.ID); got.AgentSessionID != "agent-s1" {
		t.Fatalf("agent_session_id = %q, want agent-s1", got.AgentSessionID)
	}
	// Child exits; session ends.
	if err := m.Stop(context.Background(), sess.ID); err != nil {
		t.Fatal(err)
	}
	rt.dead = true // Alive() now reports the child is gone

	resumed, err := m.Resume(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.ID != sess.ID {
		t.Fatalf("resume created a new id %q, want same %q", resumed.ID, sess.ID)
	}
	if resumed.EndedAt != nil {
		t.Fatal("resume should have reopened the session (ended_at cleared)")
	}
	last := rt.started[len(rt.started)-1]
	if last.SessionID != sess.ID || last.ResumeAgentSessionID != "agent-s1" || last.Fork {
		t.Fatalf("respawn spec = %+v, want same id, resume agent-s1, no fork", last)
	}
}

// AC (Phase 5 #2): fork branches a new session off a prior one's conversation
// without mutating the original.
func TestFork_CreatesNewBranchLeavingParentUntouched(t *testing.T) {
	m, rt := newTestManager(t)
	parent, err := m.Start(context.Background(), "p1", "claude", "manual", TransportStructured)
	if err != nil {
		t.Fatal(err)
	}
	parentBefore, _ := m.Store.GetSession(parent.ID)

	m.IDGen = func() string { return "s2" }
	child, err := m.Fork(context.Background(), parent.ID)
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	if child.ID == parent.ID {
		t.Fatal("fork must create a distinct session id")
	}
	last := rt.started[len(rt.started)-1]
	if last.SessionID != child.ID || last.ResumeAgentSessionID != "agent-s1" || !last.Fork {
		t.Fatalf("fork spec = %+v, want new id, resume agent-s1, fork=true", last)
	}
	// New row carries its own agent conversation handle.
	if got, _ := m.Store.GetSession(child.ID); got.AgentSessionID != "agent-s2" {
		t.Fatalf("child agent_session_id = %q, want agent-s2", got.AgentSessionID)
	}
	// Parent row is untouched.
	parentAfter, _ := m.Store.GetSession(parent.ID)
	if parentAfter.AgentSessionID != parentBefore.AgentSessionID || parentAfter.EndedAt != nil {
		t.Fatalf("parent mutated: before=%+v after=%+v", parentBefore, parentAfter)
	}
}

func TestResume_RejectsTerminalAndUnresumable(t *testing.T) {
	m, _ := newTestManager(t)

	term, err := m.Start(context.Background(), "p1", "claude", "manual", TransportTerminal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resume(context.Background(), term.ID); !errors.Is(err, ErrNotStructured) {
		t.Fatalf("terminal resume err = %v, want ErrNotStructured", err)
	}

	// Structured row with no recorded agent handle (e.g. started before this
	// was persisted) cannot be resumed.
	if err := m.Store.CreateSession(store.Session{ID: "old", ProjectID: "p1", Agent: "claude", Transport: TransportStructured, StartedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resume(context.Background(), "old"); !errors.Is(err, ErrNotResumable) {
		t.Fatalf("unresumable resume err = %v, want ErrNotResumable", err)
	}
}

func TestCodexExecRuntime_ForkUnsupported(t *testing.T) {
	rt := NewCodexExecRuntime("", t.TempDir(), nil)
	err := rt.Start(context.Background(), RuntimeSpec{
		Agent:                "codex",
		Transport:            TransportStructured,
		WorkDir:              t.TempDir(),
		Emit:                 func(store.SessionEvent) {},
		ResumeAgentSessionID: "thread-1",
		Fork:                 true,
	})
	if !errors.Is(err, ErrForkUnsupported) {
		t.Fatalf("exec fork err = %v, want ErrForkUnsupported", err)
	}
}
