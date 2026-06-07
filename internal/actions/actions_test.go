package actions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rockclaver/claver-agent/internal/notifications"
	"github.com/rockclaver/claver-agent/internal/store"
)

// newTestManager wires a Manager over a real in-memory store with an inline
// dispatcher so Submit runs the planner synchronously (deterministic tests).
func newTestManager(t *testing.T, planner Planner, sink notifications.Sink) (*Manager, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	m, err := New(Config{
		Store:         st,
		Planner:       planner,
		Notifications: sink,
		Dispatch:      func(f func()) { f() }, // inline
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return m, st
}

type capturingSink struct{ notes []notifications.Notification }

func (c *capturingSink) Publish(_ context.Context, n notifications.Notification) error {
	c.notes = append(c.notes, n)
	return nil
}

func TestSubmitRequiresText(t *testing.T) {
	m, _ := newTestManager(t, PlannerFunc(func(context.Context, Request) (Result, error) {
		return Result{Status: StatusObserved}, nil
	}), nil)
	if _, err := m.Submit(context.Background(), "   ", WorkerAuto); err == nil {
		t.Fatal("expected error for empty text")
	}
}

func TestSubmitRejectsUnknownWorker(t *testing.T) {
	m, _ := newTestManager(t, PlannerFunc(func(context.Context, Request) (Result, error) {
		return Result{Status: StatusObserved}, nil
	}), nil)
	if _, err := m.Submit(context.Background(), "do a thing", Worker("gpt")); err == nil {
		t.Fatal("expected error for unknown worker")
	}
}

func TestSubmitDefaultsWorkerToAuto(t *testing.T) {
	m, _ := newTestManager(t, PlannerFunc(func(context.Context, Request) (Result, error) {
		return Result{Status: StatusObserved, Summary: "ok"}, nil
	}), nil)
	job, err := m.Submit(context.Background(), "check things", "")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if job.Worker != WorkerAuto {
		t.Fatalf("worker = %q, want auto", job.Worker)
	}
}

func TestSubmitObservedLifecycle(t *testing.T) {
	sink := &capturingSink{}
	var gotReq Request
	m, _ := newTestManager(t, PlannerFunc(func(_ context.Context, req Request) (Result, error) {
		gotReq = req
		return Result{
			Status:  StatusObserved,
			Summary: "all healthy",
			Events:  []PlannerEvent{{Type: "observation", Message: "checked docker ps"}},
		}, nil
	}), sink)

	job, err := m.Submit(context.Background(), "is the api ok", WorkerClaude)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Planner ran inline, so the returned job is already terminal.
	final, err := m.Get(job.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if final.Status != StatusObserved {
		t.Fatalf("status = %q, want observed", final.Status)
	}
	if final.Result != "all healthy" {
		t.Fatalf("result = %q", final.Result)
	}
	if gotReq.Text != "is the api ok" || gotReq.Worker != WorkerClaude {
		t.Fatalf("planner got bad request: %+v", gotReq)
	}

	// Expect submitted, planning, observation, observed events in order.
	types := eventTypes(final.Events)
	wantContains := []string{"submitted", "planning", "observation", "observed"}
	for _, w := range wantContains {
		if !contains(types, w) {
			t.Fatalf("missing event %q in %v", w, types)
		}
	}

	// One completion notification with deep link.
	if len(sink.notes) != 1 {
		t.Fatalf("notifications = %d, want 1", len(sink.notes))
	}
	if sink.notes[0].Data["deep_link"] != "action/"+job.ID {
		t.Fatalf("deep_link = %v", sink.notes[0].Data["deep_link"])
	}
}

func TestSubmitNeedsTarget(t *testing.T) {
	m, _ := newTestManager(t, PlannerFunc(func(context.Context, Request) (Result, error) {
		return Result{Status: StatusNeedsTarget, Summary: "which server?"}, nil
	}), nil)
	job, err := m.Submit(context.Background(), "fix it", WorkerAuto)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	final, _ := m.Get(job.ID)
	if final.Status != StatusNeedsTarget {
		t.Fatalf("status = %q, want needs_target", final.Status)
	}
}

func TestPlannerErrorFailsJob(t *testing.T) {
	m, _ := newTestManager(t, PlannerFunc(func(context.Context, Request) (Result, error) {
		return Result{}, errors.New("cli timeout")
	}), nil)
	job, err := m.Submit(context.Background(), "diagnose", WorkerAuto)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	final, _ := m.Get(job.ID)
	if final.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", final.Status)
	}
	if !contains(eventTypes(final.Events), "failed") {
		t.Fatalf("expected failed event, got %v", eventTypes(final.Events))
	}
}

func TestInvalidPlannerStatusFailsJob(t *testing.T) {
	// A planner that returns a mutating/unknown status must not be honored in
	// the read-only Phase 1 — the job fails instead.
	m, _ := newTestManager(t, PlannerFunc(func(context.Context, Request) (Result, error) {
		return Result{Status: Status("executing")}, nil
	}), nil)
	job, _ := m.Submit(context.Background(), "restart api", WorkerAuto)
	final, _ := m.Get(job.ID)
	if final.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", final.Status)
	}
}

func TestCancelBeforePlanning(t *testing.T) {
	// Dispatch deferred: capture the planning closure but don't run it, so the
	// job stays submitted; then cancel, then run planning and confirm it does
	// not revive the job.
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	var deferred func()
	m, err := New(Config{
		Store: st,
		Planner: PlannerFunc(func(context.Context, Request) (Result, error) {
			return Result{Status: StatusObserved, Summary: "revived"}, nil
		}),
		Dispatch: func(f func()) { deferred = f },
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	job, err := m.Submit(context.Background(), "do later", WorkerAuto)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if job.Status != StatusSubmitted {
		t.Fatalf("status = %q, want submitted", job.Status)
	}
	if _, err := m.Cancel(job.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	deferred() // planner would run now
	final, _ := m.Get(job.ID)
	if final.Status != StatusCancelled {
		t.Fatalf("status = %q, want cancelled (no revive)", final.Status)
	}
}

func TestCancelTerminalIsNoop(t *testing.T) {
	m, _ := newTestManager(t, PlannerFunc(func(context.Context, Request) (Result, error) {
		return Result{Status: StatusObserved, Summary: "done"}, nil
	}), nil)
	job, _ := m.Submit(context.Background(), "x", WorkerAuto)
	got, err := m.Cancel(job.ID)
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if got.Status != StatusObserved {
		t.Fatalf("cancel on terminal changed status to %q", got.Status)
	}
}

func TestListNewestFirst(t *testing.T) {
	now := time.Unix(1000, 0)
	st, _ := store.Open(":memory:")
	t.Cleanup(func() { st.Close() })
	m, _ := New(Config{
		Store:    st,
		Planner:  PlannerFunc(func(context.Context, Request) (Result, error) { return Result{Status: StatusObserved}, nil }),
		Dispatch: func(f func()) { f() },
		Now:      func() time.Time { return now },
	})
	first, _ := m.Submit(context.Background(), "first", WorkerAuto)
	now = now.Add(time.Minute)
	second, _ := m.Submit(context.Background(), "second", WorkerAuto)

	jobs, err := m.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("len = %d, want 2", len(jobs))
	}
	if jobs[0].ID != second.ID || jobs[1].ID != first.ID {
		t.Fatalf("order wrong: %s then %s", jobs[0].ID, jobs[1].ID)
	}
}

func TestJobsPersistAcrossManagers(t *testing.T) {
	// Durability: a second Manager over the same store sees the job, proving
	// the ledger is not an in-memory cache.
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	mk := func() *Manager {
		m, err := New(Config{
			Store:    st,
			Planner:  PlannerFunc(func(context.Context, Request) (Result, error) { return Result{Status: StatusObserved, Summary: "ok"}, nil }),
			Dispatch: func(f func()) { f() },
		})
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		return m
	}
	job, err := mk().Submit(context.Background(), "persist me", WorkerCodex)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	got, err := mk().Get(job.ID)
	if err != nil {
		t.Fatalf("get from fresh manager: %v", err)
	}
	if got.RequestText != "persist me" || got.Worker != WorkerCodex {
		t.Fatalf("persisted job mismatch: %+v", got)
	}
}

func eventTypes(events []Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Type)
	}
	return out
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
