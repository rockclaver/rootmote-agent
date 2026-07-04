package store

import (
	"path/filepath"
	"testing"
	"time"
)

// AC: "Project list survives `systemctl restart rootmote-agent` with no data loss."
// We simulate a restart by closing and reopening the database file.
func TestStore_ProjectsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rootmote.db")

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t0 := time.Unix(1_700_000_000, 0)
	p := Project{ID: "p1", Name: "alpha", RemoteURL: "https://example.com/r.git", CreatedAt: t0}
	if err := s.CreateProject(p); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	got, err := s2.GetProject("p1")
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got.Name != "alpha" || got.RemoteURL != "https://example.com/r.git" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if !got.CreatedAt.Equal(t0) {
		t.Errorf("created_at: got %v want %v", got.CreatedAt, t0)
	}
}

func TestStore_ListOrderedByCreatedAt(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.CreateProject(Project{ID: "b", Name: "b", CreatedAt: time.Unix(200, 0)})
	_ = s.CreateProject(Project{ID: "a", Name: "a", CreatedAt: time.Unix(100, 0)})
	_ = s.CreateProject(Project{ID: "c", Name: "c", CreatedAt: time.Unix(300, 0)})
	ps, err := s.ListProjects()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 3 || ps[0].ID != "a" || ps[1].ID != "b" || ps[2].ID != "c" {
		t.Errorf("order wrong: %+v", ps)
	}
}

func TestStore_DeleteRemovesRow(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.CreateProject(Project{ID: "p1", Name: "x", CreatedAt: time.Unix(1, 0)})
	if err := s.DeleteProject("p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetProject("p1"); err == nil {
		t.Fatal("expected not-found after delete")
	}
}

// AC: "Disconnecting and reopening the app reattaches to the live session and
// continues streaming from the correct sequence number."
func TestStore_SessionEventsReplayFromSequence(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.CreateProject(Project{ID: "p1", Name: "x"})
	if err := s.CreateSession(Session{ID: "s1", ProjectID: "p1", Agent: "codex"}); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{"one", "two", "three"} {
		if _, err := s.AppendSessionEvent(SessionEvent{SessionID: "s1", Type: "stdout", Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.SessionEventsAfter("s1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Seq != 2 || got[0].Data != "two" || got[1].Seq != 3 {
		t.Fatalf("replay mismatch: %+v", got)
	}
}

// AC: "Session list shows started/ended timestamps and per-session token usage."
func TestStore_SessionListIncludesTimestampsAndTokenUsage(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.CreateProject(Project{ID: "p1", Name: "x"})
	start := time.Unix(10, 0)
	end := time.Unix(20, 0)
	if err := s.CreateSession(Session{ID: "s1", ProjectID: "p1", Agent: "claude", StartedAt: start}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSessionUsage("s1", 123, 456, 78); err != nil {
		t.Fatal(err)
	}
	if err := s.IncrSessionToolCalls("s1", 3); err != nil {
		t.Fatal(err)
	}
	if err := s.IncrSessionToolCalls("s1", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.EndSession("s1", end); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListSessions("p1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d sessions", len(got))
	}
	if !got[0].StartedAt.Equal(start) || got[0].EndedAt == nil || !got[0].EndedAt.Equal(end) {
		t.Fatalf("timestamps not preserved: %+v", got[0])
	}
	if got[0].InputTokens != 123 || got[0].OutputTokens != 456 || got[0].CacheTokens != 78 {
		t.Fatalf("usage not preserved: %+v", got[0])
	}
	if got[0].ToolCalls != 5 {
		t.Fatalf("tool calls not accumulated: %+v", got[0])
	}
}

// AC: "Killing and restarting the agent process rehydrates the in-flight session."
func TestStore_ActiveSessionsSurviveReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.CreateProject(Project{ID: "p1", Name: "x"})
	if err := s.CreateSession(Session{ID: "s1", ProjectID: "p1", Agent: "codex"}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	active, err := s2.ActiveSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].ID != "s1" {
		t.Fatalf("active sessions mismatch: %+v", active)
	}
}

// AC (Phase 1): "Submitted jobs persist in agent storage with status, request
// text, worker choice, timestamps, and event log." We exercise the action job
// ledger CRUD and confirm it survives a close/reopen.
func TestStore_ActionJobsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rootmote.db")

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t0 := time.Unix(1_700_000_000, 0)
	job := ActionJob{
		ID:          "j1",
		RequestText: "the api is crashing",
		Worker:      "auto",
		Status:      "submitted",
		CreatedAt:   t0,
		UpdatedAt:   t0,
	}
	if err := s.CreateActionJob(job); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.AppendActionJobEvent(ActionJobEvent{JobID: "j1", Type: "submitted", Message: "queued", CreatedAt: t0}); err != nil {
		t.Fatalf("append event: %v", err)
	}
	if _, err := s.AppendActionJobEvent(ActionJobEvent{JobID: "j1", Type: "planning", CreatedAt: t0}); err != nil {
		t.Fatalf("append event 2: %v", err)
	}
	if err := s.UpdateActionJob("j1", "observed", "looks healthy", t0.Add(time.Minute)); err != nil {
		t.Fatalf("update: %v", err)
	}
	s.Close()

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	got, err := s2.GetActionJob("j1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "observed" || got.Result != "looks healthy" || got.RequestText != "the api is crashing" {
		t.Fatalf("job mismatch after reopen: %+v", got)
	}
	if !got.UpdatedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("updated_at = %v", got.UpdatedAt)
	}

	events, err := s2.ActionJobEvents("j1")
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 2 || events[0].Seq != 1 || events[1].Seq != 2 {
		t.Fatalf("events mismatch: %+v", events)
	}

	jobs, err := s2.ListActionJobs()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != "j1" {
		t.Fatalf("list mismatch: %+v", jobs)
	}
}

func TestStore_UpdateActionJobMissing(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.UpdateActionJob("nope", "observed", "", time.Now()); err == nil {
		t.Fatal("expected ErrNotFound for missing job")
	}
}

// AC: registering a device from the app persists both the FCM send token
// and the diagnostic APNs token, and re-registering the same FCM token
// updates the APNs token in place rather than creating a duplicate row.
func TestStore_PushDeviceRoundTripsAPNsToken(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.PutPushDevice(PushDevice{
		Token: "fcm-1", APNsToken: "apns-1", Platform: "ios",
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	devices, err := s.ListPushDevices()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 1 || devices[0].APNsToken != "apns-1" {
		t.Fatalf("apns_token not persisted: %+v", devices)
	}

	// Re-registering the same FCM token with a rotated APNs token updates
	// in place -- no duplicate row, and the stale APNs token is gone.
	if err := s.PutPushDevice(PushDevice{
		Token: "fcm-1", APNsToken: "apns-2", Platform: "ios",
	}); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	devices, err = s.ListPushDevices()
	if err != nil {
		t.Fatalf("list after re-put: %v", err)
	}
	if len(devices) != 1 || devices[0].APNsToken != "apns-2" {
		t.Fatalf("apns_token not updated: %+v", devices)
	}
}
