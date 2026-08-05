package store

import (
	"errors"
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

// AC (#74 Task 2): a runbook is written once and never updated -- insert
// then get round-trips the opaque JSON content and hash verbatim.
func TestStore_RunbookImmutableInsertGet(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	t0 := time.Unix(1_700_000_000, 0)
	rb := Runbook{
		ID:          "rb-1",
		IncidentID:  "inc-1",
		ContentHash: "deadbeef",
		Content:     `{"summary":"restart nginx"}`,
		CreatedAt:   t0,
	}
	if err := s.CreateRunbook(rb); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetRunbook("rb-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ContentHash != rb.ContentHash || got.Content != rb.Content || got.IncidentID != rb.IncidentID {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if !got.CreatedAt.Equal(t0) {
		t.Fatalf("created_at = %v", got.CreatedAt)
	}

	// Immutable: re-inserting the same ID -- even with identical content --
	// is a conflict, because runbook IDs are server-minted and a collision
	// always signals a bug, never a retry to absorb.
	if err := s.CreateRunbook(rb); !errors.Is(err, ErrConflict) {
		t.Fatalf("re-create: got %v, want ErrConflict", err)
	}

	if _, err := s.GetRunbook("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing: got %v, want ErrNotFound", err)
	}
}

// AC (#74 Task 2): a retried "execute" call with the same client-minted ID
// and identical (incident, runbook, hash) is idempotent -- it must not
// perform a second insert/mutation.
func TestStore_ExecutionIdempotentOnIdenticalReuse(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	t0 := time.Unix(1_700_000_000, 0)
	e := RemediationExecution{
		ID: "ex-1", IncidentID: "inc-1", RunbookID: "rb-1",
		RunbookHash: "hash-1", Status: RemediationProposed, CreatedAt: t0, UpdatedAt: t0,
	}
	first, created, err := s.CreateExecution(e)
	if err != nil || !created {
		t.Fatalf("create: %+v created=%v err=%v", first, created, err)
	}

	second, created, err := s.CreateExecution(e)
	if err != nil {
		t.Fatalf("idempotent create: %v", err)
	}
	if created {
		t.Fatalf("idempotent create reported a fresh insert")
	}
	if second.ID != first.ID || !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("idempotent reuse returned a different row: %+v vs %+v", second, first)
	}

	rows, err := s.db.Query(`SELECT COUNT(*) FROM remediation_executions WHERE id = ?`, "ex-1")
	if err != nil {
		t.Fatalf("count query: %v", err)
	}
	defer rows.Close()
	var n int
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan count: %v", err)
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly one stored row, got %d", n)
	}
}

// AC (#74 Task 2): reusing a client-minted execution ID against a different
// runbook/hash is a conflict, not an idempotent replay, and must not alter
// the row already on disk.
func TestStore_ExecutionConflictingReuseErrors(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	orig := RemediationExecution{
		ID: "ex-1", IncidentID: "inc-1", RunbookID: "rb-1",
		RunbookHash: "hash-1", Status: RemediationProposed,
	}
	if _, _, err := s.CreateExecution(orig); err != nil {
		t.Fatalf("create: %v", err)
	}

	conflicting := orig
	conflicting.RunbookHash = "hash-2"
	if _, _, err := s.CreateExecution(conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting reuse: got %v, want ErrConflict", err)
	}

	got, err := s.GetExecution("ex-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RunbookHash != "hash-1" {
		t.Fatalf("conflicting reuse mutated the stored row: %+v", got)
	}
}

// AC (#74 Task 3 follow-up): CreateExecution persists an explicit
// execute|rollback Kind (defaulting empty to "execute" for every existing
// caller that predates this classification) and ParentExecutionID, and
// GetExecution round-trips both -- the server must be able to determine
// whether an execution is a primary or a derived rollback from the durable
// row itself, never by inspecting the client-minted execution ID's shape.
func TestStore_ExecutionKindDefaultsAndPersists(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	primary, _, err := s.CreateExecution(RemediationExecution{
		ID: "ex-1", IncidentID: "inc-1", RunbookID: "rb-1", RunbookHash: "hash-1", Status: RemediationProposed,
	})
	if err != nil {
		t.Fatalf("create primary: %v", err)
	}
	if primary.Kind != RemediationKindExecute {
		t.Fatalf("primary Kind = %q, want default %q", primary.Kind, RemediationKindExecute)
	}
	if primary.ParentExecutionID != "" {
		t.Fatalf("primary ParentExecutionID = %q, want empty", primary.ParentExecutionID)
	}

	rollback, _, err := s.CreateExecution(RemediationExecution{
		ID: "ex-1-rollback", IncidentID: "inc-1", RunbookID: "rb-2", RunbookHash: "hash-2",
		Status: RemediationProposed, Kind: RemediationKindRollback, ParentExecutionID: "ex-1",
	})
	if err != nil {
		t.Fatalf("create rollback: %v", err)
	}
	if rollback.Kind != RemediationKindRollback || rollback.ParentExecutionID != "ex-1" {
		t.Fatalf("rollback row = %+v, want Kind=rollback ParentExecutionID=ex-1", rollback)
	}

	gotPrimary, err := s.GetExecution("ex-1")
	if err != nil {
		t.Fatalf("get primary: %v", err)
	}
	if gotPrimary.Kind != RemediationKindExecute || gotPrimary.ParentExecutionID != "" {
		t.Fatalf("get primary round-trip = %+v", gotPrimary)
	}
	gotRollback, err := s.GetExecution("ex-1-rollback")
	if err != nil {
		t.Fatalf("get rollback: %v", err)
	}
	if gotRollback.Kind != RemediationKindRollback || gotRollback.ParentExecutionID != "ex-1" {
		t.Fatalf("get rollback round-trip = %+v", gotRollback)
	}

	if _, _, err := s.CreateExecution(RemediationExecution{
		ID: "ex-bad", IncidentID: "inc-1", RunbookID: "rb-3", RunbookHash: "hash-3",
		Status: RemediationProposed, Kind: "not_a_kind",
	}); err == nil {
		t.Fatalf("expected error for unrecognized execution kind")
	}
}

// AC (#74 Task 2): TransitionExecution is a compare-and-swap on status -- a
// transition whose `from` matches the current row succeeds; one that
// doesn't (an invalid jump, or a stale/duplicate caller) fails with
// ErrConflict and leaves the row untouched. An unrecognized target status is
// also rejected.
func TestStore_TransitionExecutionValidAndInvalid(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	e := RemediationExecution{
		ID: "ex-1", IncidentID: "inc-1", RunbookID: "rb-1",
		RunbookHash: "hash-1", Status: RemediationProposed,
	}
	if _, _, err := s.CreateExecution(e); err != nil {
		t.Fatalf("create: %v", err)
	}

	at := time.Unix(1_700_000_100, 0)
	if err := s.TransitionExecution("ex-1", RemediationProposed, RemediationApproved, at); err != nil {
		t.Fatalf("valid transition: %v", err)
	}
	got, err := s.GetExecution("ex-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != RemediationApproved || !got.UpdatedAt.Equal(at) {
		t.Fatalf("transition not applied: %+v", got)
	}

	// Stale `from`: the row is already "approved", not "proposed".
	if err := s.TransitionExecution("ex-1", RemediationProposed, RemediationExecuting, at); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale transition: got %v, want ErrConflict", err)
	}
	// Unknown target status is rejected outright.
	if err := s.TransitionExecution("ex-1", RemediationApproved, "not_a_status", at); err == nil {
		t.Fatalf("expected error for unrecognized target status")
	}
	got, err = s.GetExecution("ex-1")
	if err != nil {
		t.Fatalf("get after rejected transitions: %v", err)
	}
	if got.Status != RemediationApproved {
		t.Fatalf("rejected transitions mutated status: %+v", got)
	}
}

// AC (#74 Task 2): events append with a monotonic per-execution sequence
// and EventsAfter resumes correctly from a mid-stream cursor.
func TestStore_RemediationEventsMonotonicAndEventsAfter(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if _, _, err := s.CreateExecution(RemediationExecution{
		ID: "ex-1", IncidentID: "inc-1", RunbookID: "rb-1", RunbookHash: "hash-1", Status: RemediationProposed,
	}); err != nil {
		t.Fatalf("create parent execution: %v", err)
	}

	for _, typ := range []string{"approved", "started", "step_result"} {
		if _, err := s.AppendRemediationEvent(RemediationEvent{ExecutionID: "ex-1", Type: typ}); err != nil {
			t.Fatalf("append %s: %v", typ, err)
		}
	}
	all, err := s.RemediationEventsAfter("ex-1", 0)
	if err != nil {
		t.Fatalf("events after 0: %v", err)
	}
	if len(all) != 3 || all[0].Seq != 1 || all[1].Seq != 2 || all[2].Seq != 3 {
		t.Fatalf("unexpected sequence: %+v", all)
	}
	if all[0].Type != "approved" || all[2].Type != "step_result" {
		t.Fatalf("unexpected types: %+v", all)
	}

	after, err := s.RemediationEventsAfter("ex-1", 1)
	if err != nil {
		t.Fatalf("events after 1: %v", err)
	}
	if len(after) != 2 || after[0].Seq != 2 || after[1].Seq != 3 {
		t.Fatalf("resume mismatch: %+v", after)
	}
}

// AC (#74 Task 2): audit rows for one execution -- scoped via ProjectID, the
// existing generic filter column -- come back newest-first, with the id
// tiebreak, exactly as ListAudit already promises for every other caller.
func TestStore_RemediationAuditOrdering(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	t0 := time.Unix(1_700_000_000, 0)
	types := []string{"remediation.approved", "remediation.execute.started", "remediation.step.result"}
	for _, typ := range types {
		if _, err := s.AppendAudit(AuditEntry{Type: typ, ProjectID: "ex-1", CreatedAt: t0}); err != nil {
			t.Fatalf("append audit %s: %v", typ, err)
		}
	}
	rows, err := s.ListAudit("", "ex-1", 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	// Equal timestamps -> newest id first.
	if rows[0].Type != "remediation.step.result" || rows[1].Type != "remediation.execute.started" || rows[2].Type != "remediation.approved" {
		t.Fatalf("unexpected order: %+v", rows)
	}
}

// AC (#74 Task 2): an execution left "executing" or "verifying" across a
// restart is recoverable -- InFlightExecutions surfaces it so the manager
// can fail it closed instead of silently resuming (and possibly replaying a
// command).
func TestStore_InFlightExecutionsSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rootmote.db")

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := s.CreateExecution(RemediationExecution{
		ID: "ex-done", IncidentID: "inc-1", RunbookID: "rb-1", RunbookHash: "h1", Status: RemediationResolved,
	}); err != nil {
		t.Fatalf("create resolved: %v", err)
	}
	if _, _, err := s.CreateExecution(RemediationExecution{
		ID: "ex-mid", IncidentID: "inc-1", RunbookID: "rb-1", RunbookHash: "h1", Status: RemediationExecuting,
	}); err != nil {
		t.Fatalf("create in-flight: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	inFlight, err := s2.InFlightExecutions()
	if err != nil {
		t.Fatalf("in-flight: %v", err)
	}
	if len(inFlight) != 1 || inFlight[0].ID != "ex-mid" {
		t.Fatalf("unexpected in-flight set: %+v", inFlight)
	}
}
