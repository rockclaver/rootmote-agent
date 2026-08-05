package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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
// window from issue #74 Task 4), and the internal verifier's initial result
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

// AC Task 3: a single step's output is bounded before it reaches the
// durable event log (and therefore before it can be replayed/broadcast).
func TestManager_Execute_BoundsPersistedStepOutput(t *testing.T) {
	oversized := strings.Repeat("x", maxStepOutputBytes+1)
	exec := &fakeExecutor{results: map[int]StepResult{0: {ExitCode: 1, Output: oversized}}}
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
	if _, err := m.Execute(ctx, "ex-1", e.RunbookHash); err != nil {
		t.Fatalf("execute: %v", err)
	}
	events, err := s.RemediationEventsAfter("ex-1", 0)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	// Select the step_result explicitly: Propose/Approve/Execute also emit
	// lifecycle milestone events (which the relay projection needs), so the
	// step output is not events[0].
	var data struct {
		Output string `json:"output"`
	}
	var found bool
	for _, ev := range events {
		if ev.Type != "step_result" {
			continue
		}
		if err := json.Unmarshal([]byte(ev.Data), &data); err != nil {
			t.Fatal(err)
		}
		found = true
		break
	}
	if !found {
		t.Fatal("no step_result event persisted")
	}
	if len(data.Output) > maxStepOutputBytes+len("...[truncated]") {
		t.Fatalf("persisted output length = %d, bound = %d", len(data.Output), maxStepOutputBytes+len("...[truncated]"))
	}
	if !strings.HasSuffix(data.Output, "...[truncated]") {
		t.Fatalf("persisted output lacks truncation marker")
	}
}

func TestManager_DeriveRollback_RejectsExecutingParent(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok"}
	m, s := newTestManager(t, exec, val, &fakeVerifier{}, nil)
	rb := twoStepRunbook("rb", false)
	rb.Rollback = []runbook.Command{{Command: "display"}}
	e, err := m.Propose(context.Background(), "parent", "inc-1", rb)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionExecution(e.ID, store.RemediationProposed, store.RemediationApproved, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionExecution(e.ID, store.RemediationApproved, store.RemediationExecuting, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DeriveRollback(context.Background(), e.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("DeriveRollback error = %v, want ErrInvalidState", err)
	}
}

// threeStepFirewallRunbook is a three-step L1 runbook, each step a distinct
// firewall add identified by port (so a test can tell exactly which of the
// original steps a derived rollback inverted), with a non-empty Rollback
// plan so DeriveRollback has something to reverse.
func threeStepFirewallRunbook(id string) runbook.Runbook {
	mkStep := func(port float64, desc string) runbook.Step {
		return runbook.Step{
			Kind:        aiproposal.KindFirewallAdd,
			Params:      map[string]any{"action": "deny", "protocol": "tcp", "port": port, "backend": "ufw", "zone": "public"},
			Description: desc,
		}
	}
	return runbook.Runbook{
		ID:            id,
		SchemaVersion: runbook.SchemaVersion,
		IncidentID:    "inc-1",
		ServerID:      "srv-1",
		Summary:       "block three ports",
		Risk:          runbook.RiskL1,
		Steps: []runbook.Step{
			mkStep(1000, "Deny port 1000"),
			mkStep(2000, "Deny port 2000"),
			mkStep(3000, "Deny port 3000"),
		},
		Rollback: []runbook.Command{{Command: "ufw delete deny 1000/tcp", RunAs: "root", Description: "Re-allow port 1000"}},
	}
}

// AC (#74 Task 3 follow-up): DeriveRollback must invert only the steps a
// durable step_result event actually recorded as successful (exit code 0,
// no executor error) -- never a step that failed or never ran, even though
// the parent runbook's own Steps slice still lists them. Step 1 succeeds,
// step 2 fails, step 3 is never attempted; the derived rollback must
// contain the inverse of step 1 alone.
func TestManager_DeriveRollback_OnlyInvertsDurableSuccessfulSteps(t *testing.T) {
	exec := &fakeExecutor{errs: map[int]error{1: errors.New("deny 2000 failed")}}
	val := &fakeValidator{tokenID: "tok"}
	m, _ := newTestManager(t, exec, val, &fakeVerifier{}, nil)
	ctx := context.Background()

	rb := threeStepFirewallRunbook("rb-3")
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	e, err = m.Execute(ctx, "ex-1", e.RunbookHash)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if e.Status != store.RemediationRemediationFailed {
		t.Fatalf("status = %s, want remediation_failed", e.Status)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("executor calls = %d, want 2 (step 3 must never run)", len(exec.calls))
	}

	rollback, err := m.DeriveRollback(ctx, "ex-1")
	if err != nil {
		t.Fatalf("derive rollback: %v", err)
	}
	rollbackRb, err := m.Runbook(rollback.RunbookID)
	if err != nil {
		t.Fatalf("load rollback runbook: %v", err)
	}
	if len(rollbackRb.Steps) != 1 {
		t.Fatalf("rollback steps = %+v, want exactly 1 (inverse of step 1 only)", rollbackRb.Steps)
	}
	if rollbackRb.Steps[0].Kind != aiproposal.KindFirewallRemove {
		t.Fatalf("rollback step kind = %s, want firewall_remove", rollbackRb.Steps[0].Kind)
	}
	if port, _ := rollbackRb.Steps[0].Params["port"].(float64); port != 1000 {
		t.Fatalf("rollback step port = %v, want 1000 (inverse of the only successful step)", rollbackRb.Steps[0].Params["port"])
	}
}

// AC (#74 Task 3 follow-up): once every step exits zero, DeriveRollback
// (run from "verifying" -- the state Execute leaves an all-success run in,
// even when internal verification itself fails, since a verification
// failure never removes the already-durable successful step results)
// recovers and inverts every one of them, undoing the last change first.
func TestManager_DeriveRollback_VerifyingInvertsAllSuccessfulSteps(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok"}
	m, _ := newTestManager(t, exec, val, &fakeVerifier{err: errors.New("verification unavailable")}, nil)
	ctx := context.Background()

	rb := threeStepFirewallRunbook("rb-3")
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	e, err = m.Execute(ctx, "ex-1", e.RunbookHash)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if e.Status != store.RemediationVerifying {
		t.Fatalf("status = %s, want verifying", e.Status)
	}

	rollback, err := m.DeriveRollback(ctx, "ex-1")
	if err != nil {
		t.Fatalf("derive rollback: %v", err)
	}
	rollbackRb, err := m.Runbook(rollback.RunbookID)
	if err != nil {
		t.Fatalf("load rollback runbook: %v", err)
	}
	if len(rollbackRb.Steps) != 3 {
		t.Fatalf("rollback steps = %+v, want all 3 inverted", rollbackRb.Steps)
	}
	wantPorts := []float64{3000, 2000, 1000} // undo last change first
	for i, want := range wantPorts {
		got, _ := rollbackRb.Steps[i].Params["port"].(float64)
		if got != want || rollbackRb.Steps[i].Kind != aiproposal.KindFirewallRemove {
			t.Fatalf("rollback step %d = %+v, want firewall_remove port %v", i, rollbackRb.Steps[i], want)
		}
	}
}

// AC (#74 Task 3): DeriveRollback must persist a "rollback" Kind and the
// parent execution ID so the server can classify a derived execution
// durably (see remediationTokenBinding), never by inspecting the
// client-visible execution ID's shape.
func TestManager_DeriveRollback_PersistsRollbackKindAndParent(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok"}
	m, _ := newTestManager(t, exec, val, &fakeVerifier{}, nil)
	ctx := context.Background()

	rb := threeStepFirewallRunbook("rb-3")
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := m.Execute(ctx, "ex-1", e.RunbookHash); err != nil {
		t.Fatalf("execute: %v", err)
	}

	rollback, err := m.DeriveRollback(ctx, "ex-1")
	if err != nil {
		t.Fatalf("derive rollback: %v", err)
	}
	if rollback.Kind != store.RemediationKindRollback {
		t.Fatalf("rollback Kind = %q, want %q", rollback.Kind, store.RemediationKindRollback)
	}
	if rollback.ParentExecutionID != "ex-1" {
		t.Fatalf("rollback ParentExecutionID = %q, want ex-1", rollback.ParentExecutionID)
	}

	primary, err := m.GetExecution("ex-1")
	if err != nil {
		t.Fatalf("get primary: %v", err)
	}
	if primary.Kind != store.RemediationKindExecute {
		t.Fatalf("primary Kind = %q, want %q", primary.Kind, store.RemediationKindExecute)
	}
}

// AC (#74 Task 3): Subscribe's replay-then-live handoff must never deliver
// the same persisted event twice, even when a live fanout races the replay
// snapshot and re-delivers an event already returned by the replay. This
// injects that exact race deterministically through the manager's own
// (unexported) fanout method -- the identical call Execute uses to publish
// a live event -- rather than relying on real timing or exposing any
// public test-only API.
func TestManager_Subscribe_ReplayLiveBoundaryExactlyOnce(t *testing.T) {
	m, s := newTestManager(t, &fakeExecutor{}, &fakeValidator{tokenID: "tok"}, &fakeVerifier{}, nil)
	ctx := context.Background()
	rb := twoStepRunbook("rb-1", false)
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}

	// A step_result event already durably persisted before Subscribe is
	// ever called -- Subscribe's replay snapshot will include it.
	persisted, err := s.AppendRemediationEvent(store.RemediationEvent{ExecutionID: e.ID, Type: "step_result", Data: `{"index":0}`})
	if err != nil {
		t.Fatalf("append persisted event: %v", err)
	}

	// Replay from just before the persisted event so this test still
	// exercises the replay/live boundary and nothing else: Propose emits
	// lifecycle milestones of its own ahead of it.
	ch, cancel, err := m.Subscribe(ctx, e.ID, persisted.Seq-1)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer cancel()

	// Simulate the exact race Subscribe's doc comment describes: a live
	// fanout for the same already-replayed seq, delivered through the
	// identical path Execute uses (appendEvent -> fanout).
	m.fanout(e.ID, persisted)

	// A genuine new live event, published the normal way, must still be
	// delivered -- the dedup must never swallow anything past the
	// high-water mark.
	live, err := m.appendEvent(ctx, e.ID, "step_result", map[string]any{"index": 1})
	if err != nil {
		t.Fatalf("append live event: %v", err)
	}

	first := recvRemediationEvent(t, ch)
	if first.Seq != persisted.Seq || first.Type != "step_result" {
		t.Fatalf("first event = %+v, want replayed seq %d", first, persisted.Seq)
	}
	second := recvRemediationEvent(t, ch)
	if second.Seq != live.Seq {
		t.Fatalf("second event = %+v, want live seq %d", second, live.Seq)
	}
	select {
	case ev, ok := <-ch:
		if ok {
			t.Fatalf("unexpected third delivery (duplicate not deduped): %+v", ev)
		}
	case <-time.After(200 * time.Millisecond):
	}
}

func recvRemediationEvent(t *testing.T, ch <-chan store.RemediationEvent) store.RemediationEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatalf("channel closed before expected event")
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event")
	}
	return store.RemediationEvent{}
}

// AC7 (issue #74): every step of a remediation is written to the audit
// trail, in order -- the diagnosis the runbook came from, the AI output
// version, the runbook content hash, the approval and its confirmation-token
// ID, each command result, and the verification outcome. The opaque token
// itself is NEVER recorded.
func TestManager_AuditTrailCoversEveryRemediationStep(t *testing.T) {
	exec := &fakeExecutor{}
	val := &fakeValidator{tokenID: "tok-audit-1"}
	ver := &fakeVerifier{result: VerificationResult{Passed: true, Detail: "service active"}}
	m, s := newTestManager(t, exec, val, ver, nil)
	ctx := context.Background()

	rb := twoStepRunbook("rb-audit", false)
	rb.DiagnosisID = "diag-audit-1"
	rb.ProviderVersion = "claude-v9"
	hash, err := runbook.ContentHash(rb)
	if err != nil {
		t.Fatalf("content hash: %v", err)
	}
	rb.ContentHash = hash

	if _, err := m.Propose(ctx, "ex-audit", "inc-1", rb); err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := m.Approve(ctx, "ex-audit", hash, "raw-secret-token"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := m.Execute(ctx, "ex-audit", hash); err != nil {
		t.Fatalf("execute: %v", err)
	}

	entries, err := s.ListAudit("", "ex-audit", 100)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	// ListAudit returns newest-first; read the trail in the order it happened.
	var types []string
	for i := len(entries) - 1; i >= 0; i-- {
		types = append(types, entries[i].Type)
	}

	for _, want := range []string{
		"remediation.proposed",
		"remediation.approved",
		"remediation.execute.started",
		"remediation.step.result",
		"remediation.verifying",
	} {
		if indexOfString(types, want) < 0 {
			t.Fatalf("audit trail missing %q: %v", want, types)
		}
	}
	// Ordering: proposed -> approved -> started -> results -> verifying.
	proposed := indexOfString(types, "remediation.proposed")
	approved := indexOfString(types, "remediation.approved")
	started := indexOfString(types, "remediation.execute.started")
	verifying := indexOfString(types, "remediation.verifying")
	if !(proposed < approved && approved < started && started < verifying) {
		t.Fatalf("audit trail out of order: %v", types)
	}

	// Two step results, one per command.
	var results int
	for _, ty := range types {
		if ty == "remediation.step.result" {
			results++
		}
	}
	if results != 2 {
		t.Fatalf("step result audit rows = %d, want 2", results)
	}

	// The diagnosis reference, provider version and content hash are all
	// recorded, and the raw token never is.
	joined := ""
	for _, e := range entries {
		joined += e.Type + "|" + e.Summary + "|" + e.Data + "\n"
	}
	for _, want := range []string{"diag-audit-1", "claude-v9", hash, "tok-audit-1"} {
		if indexOf(joined, want) < 0 {
			t.Fatalf("audit trail missing %q", want)
		}
	}
	if containsToken(joined, "raw-secret-token") {
		t.Fatal("audit trail recorded the opaque confirmation token")
	}
}

func indexOfString(haystack []string, needle string) int {
	for i, v := range haystack {
		if v == needle {
			return i
		}
	}
	return -1
}

// projectedKinds returns the event types the Projector observed, in order.
func projectedKinds(p *fakeProjector) []string {
	out := make([]string, 0, len(p.events))
	for _, ev := range p.events {
		out = append(out, ev.Type)
	}
	return out
}

// The relay builds its redacted runbook/execution projections purely from the
// lifecycle events the agent projects. Without runbook_proposed it never
// records what was approved, and without verification_started it never opens
// the external verification request -- which is what makes "a command exited
// zero" different from "the incident actually recovered", and what makes
// Watchtower's "resolved with a Rootmote runbook" metric attributable at all.
func TestManager_ProjectsFullLifecycleToRelay(t *testing.T) {
	proj := &fakeProjector{}
	m, _ := newTestManager(t, &fakeExecutor{}, &fakeValidator{tokenID: "tok-audit-1"}, &fakeVerifier{result: VerificationResult{Passed: true, Detail: "healthy"}}, proj)
	ctx := context.Background()

	rb := twoStepRunbook("rb-1", false)
	rb.ExternalMonitorIDs = []string{"mon_ext_1"}
	e, err := m.Propose(ctx, "ex-1", "inc-1", rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := m.Execute(ctx, "ex-1", e.RunbookHash); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := projectedKinds(proj)
	want := []string{
		"runbook_proposed", "runbook_approved", "execution_started",
		"step_result", "step_result", "verification_started", "internal_verification",
	}
	if len(got) != len(want) {
		t.Fatalf("projected kinds = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("projected kinds = %v, want %v", got, want)
		}
	}

	// The relay needs the approval facts on the projected proposal, and the
	// external monitor ids on verification start.
	var proposed struct {
		Risk        string `json:"risk"`
		ContentHash string `json:"content_hash"`
		Steps       int    `json:"steps"`
	}
	if err := json.Unmarshal([]byte(proj.events[0].Data), &proposed); err != nil {
		t.Fatal(err)
	}
	if proposed.Risk == "" || proposed.ContentHash != e.RunbookHash || proposed.Steps != len(rb.Steps) {
		t.Fatalf("runbook_proposed data = %+v, want risk + content hash %q + %d steps", proposed, e.RunbookHash, len(rb.Steps))
	}
	var approved struct {
		TokenID string `json:"token_id"`
	}
	if err := json.Unmarshal([]byte(proj.events[1].Data), &approved); err != nil {
		t.Fatal(err)
	}
	if approved.TokenID != "tok-audit-1" {
		t.Fatalf("runbook_approved token_id = %q, want the token's AUDIT id", approved.TokenID)
	}
	var verifying struct {
		MonitorIDs []string `json:"monitor_ids"`
	}
	if err := json.Unmarshal([]byte(proj.events[5].Data), &verifying); err != nil {
		t.Fatal(err)
	}
	if len(verifying.MonitorIDs) != 1 || verifying.MonitorIDs[0] != "mon_ext_1" {
		t.Fatalf("verification_started monitor_ids = %v, want [mon_ext_1]", verifying.MonitorIDs)
	}
}

// A declined proposal must project the decline, and never an execution.
func TestManager_ProjectsDeclineWithoutExecution(t *testing.T) {
	proj := &fakeProjector{}
	m, _ := newTestManager(t, &fakeExecutor{}, &fakeValidator{tokenID: "tok"}, &fakeVerifier{}, proj)
	ctx := context.Background()
	e, err := m.Propose(ctx, "ex-1", "inc-1", twoStepRunbook("rb-1", false))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := m.Decline(ctx, e.ID, "not now"); err != nil {
		t.Fatalf("decline: %v", err)
	}
	got := projectedKinds(proj)
	want := []string{"runbook_proposed", "runbook_declined"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("projected kinds = %v, want %v", got, want)
	}
}

// A destructive L3 runbook is blocked at proposal time; the relay must see
// that it was blocked, not that it silently never ran.
func TestManager_ProjectsBlockedL3(t *testing.T) {
	proj := &fakeProjector{}
	m, _ := newTestManager(t, &fakeExecutor{}, &fakeValidator{tokenID: "tok"}, &fakeVerifier{}, proj)
	if _, err := m.Propose(context.Background(), "ex-1", "inc-1", twoStepRunbook("rb-1", true)); err != nil {
		t.Fatalf("propose: %v", err)
	}
	got := projectedKinds(proj)
	want := []string{"runbook_proposed", "runbook_blocked"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("projected kinds = %v, want %v", got, want)
	}
}

// A failing step must project execution_started then remediation_failed, and
// must NOT project a verification start -- nothing recovered.
func TestManager_ProjectsFailedExecutionWithoutVerification(t *testing.T) {
	proj := &fakeProjector{}
	m, _ := newTestManager(t, &fakeExecutor{results: map[int]StepResult{0: {ExitCode: 1, Output: "boom"}}}, &fakeValidator{tokenID: "tok"}, &fakeVerifier{}, proj)
	ctx := context.Background()
	e, err := m.Propose(ctx, "ex-1", "inc-1", twoStepRunbook("rb-1", false))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := m.Approve(ctx, "ex-1", e.RunbookHash, "raw-token"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := m.Execute(ctx, "ex-1", e.RunbookHash); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := projectedKinds(proj)
	for _, kind := range got {
		if kind == "verification_started" || kind == "internal_verification" {
			t.Fatalf("failed execution projected %q: %v", kind, got)
		}
	}
	if got[len(got)-1] != "remediation_failed" {
		t.Fatalf("projected kinds = %v, want to end in remediation_failed", got)
	}
}
