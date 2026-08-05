package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/store"
)

// fakeExecutor records every step it was asked to run, in order, and
// answers from per-index tables so a test can script "step 1 fails" without
// the manager ever touching a real host.
type fakeExecutor struct {
	results map[int]StepResult
	errs    map[int]error
	calls   []runbook.Step
}

func (f *fakeExecutor) ExecuteStep(ctx context.Context, step runbook.Step) (StepResult, error) {
	i := len(f.calls)
	f.calls = append(f.calls, step)
	if f.errs != nil {
		if err, ok := f.errs[i]; ok {
			return StepResult{}, err
		}
	}
	if f.results != nil {
		if res, ok := f.results[i]; ok {
			return res, nil
		}
	}
	return StepResult{ExitCode: 0, Output: "ok"}, nil
}

type fakeValidator struct {
	tokenID     string
	err         error
	calls       int
	token       string
	executionID string
	contentHash string
}

func (f *fakeValidator) Validate(ctx context.Context, token, executionID, contentHash string) (string, error) {
	f.calls++
	f.token = token
	f.executionID = executionID
	f.contentHash = contentHash
	if f.err != nil {
		return "", f.err
	}
	return f.tokenID, nil
}

type fakeVerifier struct {
	result VerificationResult
	err    error
	calls  int
}

func (f *fakeVerifier) Verify(ctx context.Context, rb runbook.Runbook) (VerificationResult, error) {
	f.calls++
	return f.result, f.err
}

type fakeProjector struct {
	events []store.RemediationEvent
	err    error
}

func (f *fakeProjector) Project(ctx context.Context, ev store.RemediationEvent) error {
	f.events = append(f.events, ev)
	return f.err
}

func fixedNow() func() time.Time {
	t := time.Unix(1_700_000_000, 0)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func newTestManager(t *testing.T, executor StepExecutor, validator ApprovalValidator, verifier InternalVerifier, projector Projector) (*Manager, *store.Store) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	m, err := New(Config{
		Store: s, Executor: executor, Validator: validator, Verifier: verifier,
		Projector: projector, Now: fixedNow(),
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return m, s
}

func twoStepRunbook(id string, blocked bool) runbook.Runbook {
	return runbook.Runbook{
		ID:            id,
		SchemaVersion: runbook.SchemaVersion,
		IncidentID:    "inc-1",
		ServerID:      "srv-1",
		Summary:       "restart nginx",
		Risk:          runbook.RiskL1,
		Blocked:       blocked,
		Steps: []runbook.Step{
			{Kind: aiproposal.KindServiceAction, Params: map[string]any{"service": "nginx", "action": "restart"}, Description: "restart nginx"},
			{Kind: aiproposal.KindServiceAction, Params: map[string]any{"service": "nginx", "action": "status"}, Description: "confirm nginx is up"},
		},
	}
}

// AC: sequential success -- every step runs in order, the execution reaches
// "verifying" (never "resolved", which requires the external stability
// window from issue #74 Task 3), and the internal verifier's initial result
// is persisted as an event.
func TestManager_Execute_SequentialSuccessReachesVerifyingWithInitialVerification(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok-1"}
	ver := &fakeVerifier{result: VerificationResult{Passed: true, Detail: "service active"}}
	m, s := newTestManager(t, exec, val, ver, nil)
	ctx := context.Background()

	rb := twoStepRunbook("rb-1", false)
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if e.Status != store.RemediationProposed {
		t.Fatalf("status after propose = %q", e.Status)
	}

	e, err = m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if e.Status != store.RemediationApproved {
		t.Fatalf("status after approve = %q", e.Status)
	}
	if val.calls != 1 || val.token != "raw-token" || val.executionID != "ex-1" || val.contentHash != e.RunbookHash {
		t.Fatalf("validator received (%q, %q, %q), want raw token, execution ID, and validated runbook hash",
			val.token, val.executionID, val.contentHash)
	}

	e, err = m.Execute(ctx, "ex-1", e.RunbookHash)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if e.Status != store.RemediationVerifying {
		t.Fatalf("status after execute = %q, want verifying (never resolved)", e.Status)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("expected both steps to run, got %d calls", len(exec.calls))
	}
	if ver.calls != 1 {
		t.Fatalf("expected exactly one internal verification pass, got %d", ver.calls)
	}

	events, err := s.RemediationEventsAfter("ex-1", 0)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	var sawVerification bool
	for _, ev := range events {
		if ev.Type == "internal_verification" {
			sawVerification = true
		}
	}
	if !sawVerification {
		t.Fatalf("initial internal verification result was not persisted: %+v", events)
	}
}

// AC: the first unexpected failure stops later steps -- step 2 must never
// run once step 1 exits non-zero -- and the execution lands in
// remediation_failed, not verifying.
func TestManager_Execute_FirstFailureStopsLaterSteps(t *testing.T) {
	exec := &fakeExecutor{results: map[int]StepResult{0: {ExitCode: 1, Output: "systemctl failed"}}}
	val := &fakeValidator{tokenID: "tok-1"}
	ver := &fakeVerifier{result: VerificationResult{Passed: true}}
	m, _ := newTestManager(t, exec, val, ver, nil)
	ctx := context.Background()

	rb := twoStepRunbook("rb-1", false)
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	e, err = m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	e, err = m.Execute(ctx, "ex-1", e.RunbookHash)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if e.Status != store.RemediationRemediationFailed {
		t.Fatalf("status = %q, want remediation_failed", e.Status)
	}
	if len(exec.calls) != 1 {
		t.Fatalf("expected exactly one step to run before stopping, got %d", len(exec.calls))
	}
	if ver.calls != 0 {
		t.Fatalf("internal verification must not run after a failed execution, got %d calls", ver.calls)
	}
}

// AC: a runbook classified Blocked (L3) is recorded as blocked_l3 straight
// from Propose, and neither Approve nor Execute can move it forward -- no
// approval token is ever consumed and no step is ever run.
func TestManager_L3BlockedNeverApprovedOrExecuted(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok-1"}
	ver := &fakeVerifier{}
	m, _ := newTestManager(t, exec, val, ver, nil)
	ctx := context.Background()

	rb := twoStepRunbook("rb-1", true)
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if e.Status != store.RemediationBlockedL3 {
		t.Fatalf("status after propose = %q, want blocked_l3", e.Status)
	}

	if _, err := m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token"); !errors.Is(err, ErrBlockedL3) {
		t.Fatalf("approve on blocked runbook: got %v, want ErrBlockedL3", err)
	}
	if val.calls != 0 {
		t.Fatalf("approval token must never be consumed for a blocked runbook, got %d calls", val.calls)
	}
	if _, err := m.Execute(ctx, "ex-1", e.RunbookHash); err == nil {
		t.Fatalf("expected execute on blocked runbook to fail")
	}
	if len(exec.calls) != 0 {
		t.Fatalf("no step may ever run for a blocked L3 runbook, got %d calls", len(exec.calls))
	}
}

// AC: a requested hash that does not match the stored/recomputed runbook
// content hash is rejected before approval -- no token is consumed and the
// execution stays "proposed".
func TestManager_Approve_HashMismatchRejectsWithoutMutation(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok-1"}
	ver := &fakeVerifier{}
	m, s := newTestManager(t, exec, val, ver, nil)
	ctx := context.Background()

	rb := twoStepRunbook("rb-1", false)
	_, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}

	if _, err := m.Approve(ctx, "ex-1", "not-the-real-hash", "raw-token"); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("approve with bad hash: got %v, want ErrHashMismatch", err)
	}
	if val.calls != 0 {
		t.Fatalf("token must not be consumed before the hash check passes, got %d calls", val.calls)
	}
	got, err := s.GetExecution("ex-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != store.RemediationProposed {
		t.Fatalf("hash mismatch mutated status to %q", got.Status)
	}
}

// AC: the same hash check applies again at execute time -- a stale/forged
// requested hash on an already-approved execution is rejected without
// running any step.
func TestManager_Execute_HashMismatchRejectsWithoutMutation(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok-1"}
	ver := &fakeVerifier{}
	m, s := newTestManager(t, exec, val, ver, nil)
	ctx := context.Background()

	rb := twoStepRunbook("rb-1", false)
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	e, err = m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	if _, err := m.Execute(ctx, "ex-1", "not-the-real-hash"); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("execute with bad hash: got %v, want ErrHashMismatch", err)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("no step may run when the hash check fails, got %d calls", len(exec.calls))
	}
	got, err := s.GetExecution("ex-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != store.RemediationApproved {
		t.Fatalf("hash mismatch mutated status to %q", got.Status)
	}
}

// AC: a Projector failure must never lose the local audit/execution record
// -- every event and audit row is already durable in the store before
// Project is (best-effort) invoked.
func TestManager_ProjectorFailureDoesNotLoseLocalAuditOrExecution(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok-1"}
	ver := &fakeVerifier{result: VerificationResult{Passed: true}}
	proj := &fakeProjector{err: errors.New("relay unreachable")}
	m, s := newTestManager(t, exec, val, ver, proj)
	ctx := context.Background()

	rb := twoStepRunbook("rb-1", false)
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	e, err = m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	e, err = m.Execute(ctx, "ex-1", e.RunbookHash)
	if err != nil {
		t.Fatalf("execute despite projector failure: %v", err)
	}
	if e.Status != store.RemediationVerifying {
		t.Fatalf("status = %q, want verifying", e.Status)
	}
	if len(proj.events) == 0 {
		t.Fatalf("projector was never invoked")
	}

	events, err := s.RemediationEventsAfter("ex-1", 0)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("execution events were lost despite the projector failing")
	}
	// Every event handed to a failing Project already carries a persisted
	// sequence number -- proof the store write landed before broadcast.
	for _, ev := range proj.events {
		if ev.Seq == 0 {
			t.Fatalf("projector observed an unpersisted event: %+v", ev)
		}
	}

	auditRows, err := s.ListAudit("", "ex-1", 50)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(auditRows) == 0 {
		t.Fatalf("audit trail was lost despite the projector failing")
	}
	for _, row := range auditRows {
		if row.Data != "" && (containsToken(row.Data, "raw-token")) {
			t.Fatalf("audit row retained the opaque token: %+v", row)
		}
	}
}

func containsToken(data, token string) bool {
	return len(data) > 0 && len(token) > 0 && (indexOf(data, token) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// AC: a retried "execute" call for the same execution ID and matching
// content hash is idempotent -- it returns the existing execution and never
// re-runs a single step.
func TestManager_Execute_DuplicateIdenticalCallDoesNotReplay(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok-1"}
	ver := &fakeVerifier{result: VerificationResult{Passed: true}}
	m, _ := newTestManager(t, exec, val, ver, nil)
	ctx := context.Background()

	rb := twoStepRunbook("rb-1", false)
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	e, err = m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	first, err := m.Execute(ctx, "ex-1", e.RunbookHash)
	if err != nil {
		t.Fatalf("first execute: %v", err)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("expected 2 step calls after first execute, got %d", len(exec.calls))
	}

	second, err := m.Execute(ctx, "ex-1", e.RunbookHash)
	if err != nil {
		t.Fatalf("duplicate execute: %v", err)
	}
	if second.Status != first.Status {
		t.Fatalf("duplicate execute changed status: %q vs %q", second.Status, first.Status)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("duplicate execute replayed a step: %d total calls", len(exec.calls))
	}
	if ver.calls != 1 {
		t.Fatalf("duplicate execute re-ran internal verification: %d calls", ver.calls)
	}
}

// AC: an execution left "executing" or "verifying" across a restart
// recovers as remediation_failed without ever invoking StepExecutor -- the
// agent must not replay a command it cannot prove already finished.
func TestManager_RecoverInterrupted_FailsClosedWithoutReplay(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok-1"}
	ver := &fakeVerifier{}
	m, s := newTestManager(t, exec, val, ver, nil)
	ctx := context.Background()

	rb := twoStepRunbook("rb-1", false)
	if err := s.CreateRunbook(store.Runbook{ID: "rb-1", IncidentID: "inc-1", ContentHash: "h1", Content: mustJSON(t, rb)}); err != nil {
		t.Fatalf("seed runbook: %v", err)
	}
	if _, _, err := s.CreateExecution(store.RemediationExecution{
		ID: "ex-mid", IncidentID: "inc-1", RunbookID: "rb-1", RunbookHash: "h1", Status: store.RemediationExecuting,
	}); err != nil {
		t.Fatalf("seed in-flight execution: %v", err)
	}

	recovered, err := m.RecoverInterrupted(ctx)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(recovered) != 1 || recovered[0].ID != "ex-mid" {
		t.Fatalf("unexpected recovered set: %+v", recovered)
	}
	if recovered[0].Status != store.RemediationRemediationFailed {
		t.Fatalf("recovered status = %q, want remediation_failed", recovered[0].Status)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("recovery must never invoke the step executor, got %d calls", len(exec.calls))
	}

	got, err := s.GetExecution("ex-mid")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != store.RemediationRemediationFailed {
		t.Fatalf("stored status = %q, want remediation_failed", got.Status)
	}

	auditRows, err := s.ListAudit("", "ex-mid", 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(auditRows) == 0 {
		t.Fatalf("recovery did not write an audit row")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// A real store error during approved -> executing is not a duplicate-execute
// race. It must reach the caller and must not run a host mutation. The
// transition seam is private production plumbing with the store method as
// its default, letting this test isolate the edge without a second database.
func TestManager_Execute_TransitionStoreErrorDoesNotExecute(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok-1"}
	ver := &fakeVerifier{}
	m, s := newTestManager(t, exec, val, ver, nil)
	ctx := context.Background()

	rb := twoStepRunbook("rb-1", false)
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	e, err = m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	transitionErr := errors.New("database is closed")
	m.transitionExecution = func(id, from, to string, at time.Time) error {
		if id == "ex-1" && from == store.RemediationApproved && to == store.RemediationExecuting {
			return transitionErr
		}
		return s.TransitionExecution(id, from, to, at)
	}
	if _, err := m.Execute(ctx, "ex-1", e.RunbookHash); !errors.Is(err, transitionErr) {
		t.Fatalf("execute error = %v, want transition storage error", err)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("store transition failure executed %d host steps", len(exec.calls))
	}
	got, err := s.GetExecution("ex-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != store.RemediationApproved {
		t.Fatalf("transition error changed status to %q", got.Status)
	}
}
