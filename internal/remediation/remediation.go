// Package remediation owns the durable "approve, execute, verify" lifecycle
// for an approved runbook (issue #74 Phase 6). It persists the full
// immutable runbook and every execution/audit/event to the agent's SQLite
// state store (see internal/store) so the ledger survives a restart, and it
// mutates the host only through an injected, typed StepExecutor -- nothing
// in this package shells out directly.
//
// The lifecycle is: Propose (persist the runbook + a client-minted
// execution in status "proposed", or "blocked_l3" for a destructive L3
// runbook) -> Approve (validate the content hash and the biometric
// approval token, transition to "approved") -> Execute (run every step
// sequentially, stop on the first unexpected failure, transition to
// "verifying" on an all-exit-zero run and persist the internal verifier's
// initial result). This package never transitions an execution to
// "resolved" -- that requires the external stability window described in
// issue #74's Task 4.
//
// Task 3 adds: durable + live subscription (Subscribe, mirroring
// sessions.Manager's persist-then-fanout pattern), read accessors used by
// the server's incident.runbook.get / incident.verify handlers, and
// DeriveRollback, which builds and persists an immutable companion runbook
// that structurally reverses an executed runbook's typed steps -- never the
// executed runbook's opaque Rollback display commands, and never run
// automatically. The real ApprovalValidator (over review.Manager.ConsumeToken)
// and the typed StepExecutor/InternalVerifier adapters live in
// internal/server, which is the only package wired to every host-mutating
// manager.
package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/store"
)

// StepResult is the outcome of running one runbook step against the host.
type StepResult struct {
	Output   string
	ExitCode int
}

// StepExecutor runs one concrete runbook step through an injected, typed
// executor (systemd/process/firewall/security). A non-nil error means the
// executor itself failed to run the step (e.g. transport failure); a
// non-zero ExitCode means the command ran but reported failure. Either one
// counts as "the first unexpected failure" and stops later steps.
type StepExecutor interface {
	ExecuteStep(ctx context.Context, step runbook.Step) (StepResult, error)
}

// ApprovalValidator authorises one execution's biometric approval. It
// receives the raw, opaque confirmation token and must return a token
// identifier that is safe to persist -- Manager writes only the returned
// tokenID to the audit trail and never the raw token itself.
type ApprovalValidator interface {
	Validate(ctx context.Context, token, executionID, contentHash string) (tokenID string, err error)
}

// VerificationResult is one internal-verification outcome.
type VerificationResult struct {
	Passed bool
	Detail string
}

// InternalVerifier runs the agent's own bounded checks once execution
// completes exit-zero. Its initial result is persisted, but it does not by
// itself resolve the incident -- resolution also requires the external
// stability window (issue #74 Task 3).
type InternalVerifier interface {
	Verify(ctx context.Context, rb runbook.Runbook) (VerificationResult, error)
}

// Projector broadcasts an execution's lifecycle events to external
// observers (e.g. the relay). Projection is always best-effort: every event
// handed to Project has already been durably persisted
// (store.AppendRemediationEvent), so a Projector error never rolls back or
// loses that local record -- Manager logs the failure and moves on.
type Projector interface {
	Project(ctx context.Context, event store.RemediationEvent) error
}

// Sentinel errors returned by Manager. They wrap no lower-level cause
// because the whole point is "reject before any mutation" -- callers should
// not need to unwrap further.
var (
	// ErrMissingDependency is returned by New when a required Config field
	// is nil.
	ErrMissingDependency = errors.New("remediation: missing required dependency")
	// ErrHashMismatch is returned when the requested content hash does not
	// match the runbook hash recorded at proposal time and recomputed from
	// the stored runbook. No store mutation happens before this check.
	ErrHashMismatch = errors.New("remediation: content hash mismatch")
	// ErrBlockedL3 is returned by Approve/Execute for a runbook that was
	// classified destructive (L3) and recorded blocked_l3 at Propose time.
	ErrBlockedL3 = errors.New("remediation: blocked as L3")
	// ErrInvalidState is returned when the requested transition does not
	// apply to the execution's current status.
	ErrInvalidState = errors.New("remediation: invalid execution state")
	// ErrNoRollbackPlan is returned by DeriveRollback when the parent
	// runbook was authored with no Rollback plan at all.
	ErrNoRollbackPlan = errors.New("remediation: runbook has no rollback plan")
	// ErrRollbackUnsupported is returned by DeriveRollback when the parent
	// runbook's typed steps cannot be safely, structurally reversed (see
	// invertSteps).
	ErrRollbackUnsupported = errors.New("remediation: rollback steps cannot be safely reversed")
)

// Config wires Manager's dependencies. Store, Executor, Validator, and
// Verifier are required; Projector and Now have sensible zero-value
// behaviour (no external projection; real wall-clock time).
type Config struct {
	Store     *store.Store
	Executor  StepExecutor
	Validator ApprovalValidator
	Verifier  InternalVerifier
	Projector Projector
	Now       func() time.Time
}

// Manager owns the durable remediation execution lifecycle. Every mutation
// is persisted to the store before this package returns or projects it, so
// the ledger survives an agent restart -- see RecoverInterrupted.
type Manager struct {
	store               *store.Store
	executor            StepExecutor
	validator           ApprovalValidator
	verifier            InternalVerifier
	projector           Projector
	now                 func() time.Time
	transitionExecution func(id, from, to string, at time.Time) error

	mu   sync.Mutex
	subs map[string]map[*subscriber]struct{}
}

// subscriber is one live consumer of an execution's event stream. ch is
// never closed; teardown signals via done instead, which lets fanout
// deliver outside the manager lock without risking a send on a closed
// channel -- mirrors sessions.Manager's subscriber.
type subscriber struct {
	ch   chan store.RemediationEvent
	done chan struct{}
}

// New constructs a Manager. Store, Executor, Validator, and Verifier are
// required.
func New(cfg Config) (*Manager, error) {
	if cfg.Store == nil || cfg.Executor == nil || cfg.Validator == nil || cfg.Verifier == nil {
		return nil, ErrMissingDependency
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		store:               cfg.Store,
		executor:            cfg.Executor,
		validator:           cfg.Validator,
		verifier:            cfg.Verifier,
		projector:           cfg.Projector,
		now:                 now,
		transitionExecution: cfg.Store.TransitionExecution,
		subs:                make(map[string]map[*subscriber]struct{}),
	}, nil
}

// Propose persists rb as an immutable runbook (recomputing ContentHash from
// rb's own content -- the caller-supplied value, if any, is never trusted)
// and creates its execution record under the client-minted executionID, in
// status "proposed" -- or "blocked_l3" when rb was classified Blocked, so
// the operator sees the block immediately instead of a spurious
// approve/decline step. Propose is idempotent: retrying with the same
// executionID against identical (incidentID, rb.ID, hash) returns the
// existing execution; reusing the ID against different content returns
// store.ErrConflict (from CreateExecution).
func (m *Manager) Propose(ctx context.Context, executionID, incidentID string, rb runbook.Runbook) (store.RemediationExecution, error) {
	hash, err := runbook.ContentHash(rb)
	if err != nil {
		return store.RemediationExecution{}, fmt.Errorf("remediation: compute content hash: %w", err)
	}
	rb.ContentHash = hash
	content, err := json.Marshal(rb)
	if err != nil {
		return store.RemediationExecution{}, fmt.Errorf("remediation: marshal runbook: %w", err)
	}

	now := m.now()
	if _, err := m.store.GetRunbook(rb.ID); errors.Is(err, store.ErrNotFound) {
		if err := m.store.CreateRunbook(store.Runbook{
			ID: rb.ID, IncidentID: incidentID, ContentHash: hash, Content: string(content), CreatedAt: now,
		}); err != nil {
			return store.RemediationExecution{}, err
		}
	} else if err != nil {
		return store.RemediationExecution{}, err
	}

	status := store.RemediationProposed
	if rb.Blocked {
		status = store.RemediationBlockedL3
	}
	exec, created, err := m.store.CreateExecution(store.RemediationExecution{
		ID: executionID, IncidentID: incidentID, RunbookID: rb.ID, RunbookHash: hash,
		Status: status, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return store.RemediationExecution{}, err
	}
	if created {
		if err := m.appendAudit(exec, "remediation.proposed", map[string]any{
			"risk": string(rb.Risk), "blocked": rb.Blocked, "steps": len(rb.Steps),
		}); err != nil {
			return store.RemediationExecution{}, err
		}
		if rb.Blocked {
			if err := m.appendAudit(exec, "remediation.blocked_l3", map[string]any{"reason": rb.BlockedReason}); err != nil {
				return store.RemediationExecution{}, err
			}
		}
	}
	return exec, nil
}

// Approve validates requestedHash against the runbook hash recorded at
// proposal time and the hash recomputed from the stored runbook content,
// then validates the biometric approval token, before transitioning
// proposed -> approved. Any mismatch, an already-blocked/terminal
// execution, or an invalid token returns an error without transitioning the
// execution or consuming the token -- the hash check runs strictly before
// token consumption.
func (m *Manager) Approve(ctx context.Context, executionID, requestedHash, token string) (store.RemediationExecution, error) {
	exec, err := m.store.GetExecution(executionID)
	if err != nil {
		return store.RemediationExecution{}, err
	}
	if exec.Status == store.RemediationBlockedL3 {
		return store.RemediationExecution{}, ErrBlockedL3
	}
	if exec.Status != store.RemediationProposed {
		return store.RemediationExecution{}, fmt.Errorf("remediation: approve from %s: %w", exec.Status, ErrInvalidState)
	}
	if err := m.validateHash(exec, requestedHash); err != nil {
		return store.RemediationExecution{}, err
	}
	tokenID, err := m.validator.Validate(ctx, token, executionID, requestedHash)
	if err != nil {
		return store.RemediationExecution{}, err
	}

	now := m.now()
	if err := m.store.TransitionExecution(executionID, store.RemediationProposed, store.RemediationApproved, now); err != nil {
		return store.RemediationExecution{}, err
	}
	exec.Status = store.RemediationApproved
	exec.UpdatedAt = now
	if err := m.appendAudit(exec, "remediation.approved", map[string]any{"token_id": tokenID}); err != nil {
		return store.RemediationExecution{}, err
	}
	return exec, nil
}

// Decline transitions proposed -> declined and records reason on the audit
// trail. It rejects any other starting state.
func (m *Manager) Decline(ctx context.Context, executionID, reason string) (store.RemediationExecution, error) {
	exec, err := m.store.GetExecution(executionID)
	if err != nil {
		return store.RemediationExecution{}, err
	}
	if exec.Status != store.RemediationProposed {
		return store.RemediationExecution{}, fmt.Errorf("remediation: decline from %s: %w", exec.Status, ErrInvalidState)
	}
	now := m.now()
	if err := m.store.TransitionExecution(executionID, store.RemediationProposed, store.RemediationDeclined, now); err != nil {
		return store.RemediationExecution{}, err
	}
	exec.Status = store.RemediationDeclined
	exec.UpdatedAt = now
	if err := m.appendAudit(exec, "remediation.declined", map[string]any{"reason": reason}); err != nil {
		return store.RemediationExecution{}, err
	}
	return exec, nil
}

// Execute recomputes and checks the content hash again, then runs an
// approved runbook's steps sequentially through the injected StepExecutor,
// transitioning approved -> executing. On the first unexpected failure
// (executor error or non-zero exit) it stops running later steps and
// transitions executing -> remediation_failed. On every step exiting zero
// it transitions executing -> verifying and runs one internal verification
// pass, persisting its initial result -- Execute never transitions to
// resolved itself; that requires the external stability window (issue #74
// Task 3). A retried call with the same executionID and a matching
// requestedHash for an execution that has already left "approved" returns
// the existing execution unchanged and runs no step.
func (m *Manager) Execute(ctx context.Context, executionID, requestedHash string) (store.RemediationExecution, error) {
	exec, err := m.store.GetExecution(executionID)
	if err != nil {
		return store.RemediationExecution{}, err
	}
	if err := m.validateHash(exec, requestedHash); err != nil {
		return store.RemediationExecution{}, err
	}

	switch exec.Status {
	case store.RemediationExecuting, store.RemediationVerifying, store.RemediationResolved, store.RemediationRemediationFailed:
		// Duplicate identical execute: content matches (validateHash
		// above already proved it) and a prior call already owns this
		// execution -- return it unchanged, no host mutation.
		return exec, nil
	case store.RemediationApproved:
		// proceed
	default:
		return store.RemediationExecution{}, fmt.Errorf("remediation: execute from %s: %w", exec.Status, ErrInvalidState)
	}

	rbRow, err := m.store.GetRunbook(exec.RunbookID)
	if err != nil {
		return store.RemediationExecution{}, err
	}
	var rb runbook.Runbook
	if err := json.Unmarshal([]byte(rbRow.Content), &rb); err != nil {
		return store.RemediationExecution{}, fmt.Errorf("remediation: decode stored runbook: %w", err)
	}

	startAt := m.now()
	if err := m.transitionExecution(executionID, store.RemediationApproved, store.RemediationExecuting, startAt); err != nil {
		if !errors.Is(err, store.ErrConflict) {
			return store.RemediationExecution{}, err
		}
		// Lost the race to another caller (or a duplicate landed between
		// our GetExecution and here): reload and treat as idempotent.
		reloaded, gerr := m.store.GetExecution(executionID)
		if gerr != nil {
			return store.RemediationExecution{}, gerr
		}
		return reloaded, nil
	}
	exec.Status = store.RemediationExecuting
	exec.UpdatedAt = startAt
	if err := m.appendAudit(exec, "remediation.execute.started", map[string]any{"steps": len(rb.Steps)}); err != nil {
		return store.RemediationExecution{}, err
	}

	for i, step := range rb.Steps {
		res, execErr := m.executor.ExecuteStep(ctx, step)
		data := map[string]any{
			"index": i, "kind": string(step.Kind), "exit_code": res.ExitCode, "output": boundOutput(res.Output),
		}
		if execErr != nil {
			data["error"] = execErr.Error()
		}
		if _, err := m.appendEvent(ctx, executionID, "step_result", data); err != nil {
			return store.RemediationExecution{}, err
		}
		if err := m.appendAudit(exec, "remediation.step.result", data); err != nil {
			return store.RemediationExecution{}, err
		}

		if execErr != nil || res.ExitCode != 0 {
			failAt := m.now()
			if terr := m.store.TransitionExecution(executionID, store.RemediationExecuting, store.RemediationRemediationFailed, failAt); terr != nil {
				return store.RemediationExecution{}, terr
			}
			exec.Status = store.RemediationRemediationFailed
			exec.UpdatedAt = failAt
			if err := m.appendAudit(exec, "remediation.failed", map[string]any{"failed_step": i}); err != nil {
				return store.RemediationExecution{}, err
			}
			if _, err := m.appendEvent(ctx, executionID, "remediation_failed", map[string]any{"failed_step": i}); err != nil {
				return store.RemediationExecution{}, err
			}
			return exec, nil
		}
	}

	verifyAt := m.now()
	if err := m.store.TransitionExecution(executionID, store.RemediationExecuting, store.RemediationVerifying, verifyAt); err != nil {
		return store.RemediationExecution{}, err
	}
	exec.Status = store.RemediationVerifying
	exec.UpdatedAt = verifyAt
	if err := m.appendAudit(exec, "remediation.verifying", nil); err != nil {
		return store.RemediationExecution{}, err
	}

	result, verr := m.verifier.Verify(ctx, rb)
	verifyData := map[string]any{"passed": result.Passed, "detail": result.Detail}
	if verr != nil {
		verifyData["error"] = verr.Error()
	}
	if _, err := m.appendEvent(ctx, executionID, "internal_verification", verifyData); err != nil {
		return store.RemediationExecution{}, err
	}

	return exec, nil
}

// RecoverInterrupted marks every execution left "executing" or "verifying"
// -- a host command may have been mid-flight when the agent last stopped --
// as remediation_failed. It never invokes StepExecutor: there is no way to
// tell whether the last command already completed on the host, so this
// package always fails closed rather than replaying it. Call once at
// startup, before serving new Approve/Execute calls.
func (m *Manager) RecoverInterrupted(ctx context.Context) ([]store.RemediationExecution, error) {
	inFlight, err := m.store.InFlightExecutions()
	if err != nil {
		return nil, err
	}
	recovered := make([]store.RemediationExecution, 0, len(inFlight))
	for _, exec := range inFlight {
		now := m.now()
		if err := m.store.TransitionExecution(exec.ID, exec.Status, store.RemediationRemediationFailed, now); err != nil {
			return recovered, err
		}
		exec.Status = store.RemediationRemediationFailed
		exec.UpdatedAt = now
		if err := m.appendAudit(exec, "remediation.failed", map[string]any{"reason": "interrupted at restart"}); err != nil {
			return recovered, err
		}
		if _, err := m.appendEvent(ctx, exec.ID, "remediation_failed", map[string]any{"reason": "interrupted"}); err != nil {
			return recovered, err
		}
		recovered = append(recovered, exec)
	}
	return recovered, nil
}

// validateHash re-derives the runbook hash two independent ways -- the
// value recorded on the execution at proposal time, and a fresh
// runbook.ContentHash recomputed from the stored runbook JSON -- and checks
// both against requestedHash before any caller proceeds to approve or
// mutate a host. Any disagreement between the three is ErrHashMismatch.
func (m *Manager) validateHash(exec store.RemediationExecution, requestedHash string) error {
	rbRow, err := m.store.GetRunbook(exec.RunbookID)
	if err != nil {
		return err
	}
	var decoded runbook.Runbook
	if err := json.Unmarshal([]byte(rbRow.Content), &decoded); err != nil {
		return fmt.Errorf("remediation: decode stored runbook: %w", err)
	}
	recomputed, err := runbook.ContentHash(decoded)
	if err != nil {
		return fmt.Errorf("remediation: recompute content hash: %w", err)
	}
	if requestedHash == "" || requestedHash != exec.RunbookHash || requestedHash != rbRow.ContentHash || requestedHash != recomputed {
		return ErrHashMismatch
	}
	return nil
}

// appendAudit writes one audit row scoped to exec via the existing audit
// store (AuditEntry.ProjectID reuses the generic project-scope filter as
// the execution-scope filter, exactly as ListAudit already supports).
// data is JSON-encoded; callers must never put a raw confirmation token in
// data -- only Approve's tokenID (the ApprovalValidator's return value) is
// ever recorded.
func (m *Manager) appendAudit(exec store.RemediationExecution, typ string, data map[string]any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("remediation: marshal audit data: %w", err)
	}
	_, err = m.store.AppendAudit(store.AuditEntry{
		Type: typ, ProjectID: exec.ID, SessionID: exec.IncidentID, Actor: "remediation",
		Summary: typ, Data: string(raw), CreatedAt: m.now(),
	})
	return err
}

// appendEvent persists one execution event (assigning its monotonic
// sequence), fans it out to any live Subscribe callers, and only then,
// best-effort, hands it to the Projector -- so a Projector failure can
// never lose the local record, which is already durable and already
// delivered to live subscribers by the time Project is called.
func (m *Manager) appendEvent(ctx context.Context, executionID, typ string, data map[string]any) (store.RemediationEvent, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return store.RemediationEvent{}, fmt.Errorf("remediation: marshal event data: %w", err)
	}
	ev, err := m.store.AppendRemediationEvent(store.RemediationEvent{
		ExecutionID: executionID, Type: typ, Data: string(raw), CreatedAt: m.now(),
	})
	if err != nil {
		return store.RemediationEvent{}, err
	}
	m.fanout(executionID, ev)
	if m.projector != nil {
		_ = m.projector.Project(ctx, ev)
	}
	return ev, nil
}

// maxStepOutputBytes bounds one step_result event's persisted/broadcast
// "output" field so a runaway command can never balloon an execution's
// event trail (and every subscriber's frame) unboundedly.
const maxStepOutputBytes = 32 * 1024

// boundOutput truncates s to maxStepOutputBytes, appending a stable marker
// so a client can tell truncated output from output that just happened to
// end there.
func boundOutput(s string) string {
	if len(s) <= maxStepOutputBytes {
		return s
	}
	return s[:maxStepOutputBytes] + "...[truncated]"
}

// GetExecution loads one remediation execution by ID -- a thin read-only
// passthrough used by the server's incident.runbook.get / incident.verify /
// incident.runbook.execute handlers, which all need the execution's current
// status without mutating it.
func (m *Manager) GetExecution(id string) (store.RemediationExecution, error) {
	return m.store.GetExecution(id)
}

// Runbook loads and decodes one immutable runbook by ID.
func (m *Manager) Runbook(runbookID string) (runbook.Runbook, error) {
	row, err := m.store.GetRunbook(runbookID)
	if err != nil {
		return runbook.Runbook{}, err
	}
	var rb runbook.Runbook
	if err := json.Unmarshal([]byte(row.Content), &rb); err != nil {
		return runbook.Runbook{}, fmt.Errorf("remediation: decode stored runbook: %w", err)
	}
	return rb, nil
}

// EventsAfter returns an execution's persisted events with seq > afterSeq,
// in ascending order -- used by incident.verify to read the latest
// internal_verification event without a live subscription.
func (m *Manager) EventsAfter(executionID string, afterSeq int64) ([]store.RemediationEvent, error) {
	return m.store.RemediationEventsAfter(executionID, afterSeq)
}

// fanout delivers ev to every live Subscribe caller for executionID. It is
// always called after the event is durably persisted (see appendEvent), so
// a subscriber that misses a live delivery (slow consumer, or one that
// subscribes a moment later) still catches up via the persisted replay --
// fanout is a latency optimisation, never the record of truth.
func (m *Manager) fanout(executionID string, ev store.RemediationEvent) {
	m.mu.Lock()
	subs := make([]*subscriber, 0, len(m.subs[executionID]))
	for sub := range m.subs[executionID] {
		subs = append(subs, sub)
	}
	m.mu.Unlock()
	for _, sub := range subs {
		select {
		case sub.ch <- ev:
		case <-sub.done:
		}
	}
}

// Subscribe returns executionID's event stream starting after afterSeq: it
// first replays every persisted event with seq > afterSeq (so a
// reconnecting client never misses one), then streams new events live as
// Execute appends them -- with no duplicate delivery across the
// replay/live boundary, mirroring sessions.Manager.Subscribe. The returned
// channel is closed, and the subscriber cleanly deregistered, when either
// ctx is cancelled or the returned cancel func is called; cancel blocks
// until the forwarding goroutine has exited.
func (m *Manager) Subscribe(ctx context.Context, executionID string, afterSeq int64) (<-chan store.RemediationEvent, func(), error) {
	if _, err := m.store.GetExecution(executionID); err != nil {
		return nil, nil, err
	}
	subCtx, cancelSub := context.WithCancel(ctx)
	sub := &subscriber{ch: make(chan store.RemediationEvent, 256), done: make(chan struct{})}
	out := make(chan store.RemediationEvent, 256)

	m.mu.Lock()
	if m.subs[executionID] == nil {
		m.subs[executionID] = make(map[*subscriber]struct{})
	}
	m.subs[executionID][sub] = struct{}{}
	replay, err := m.store.RemediationEventsAfter(executionID, afterSeq)
	if err != nil {
		delete(m.subs[executionID], sub)
		m.mu.Unlock()
		close(out)
		cancelSub()
		return nil, nil, err
	}
	m.mu.Unlock()

	finished := make(chan struct{})
	go func() {
		defer close(out)
		defer close(finished)
		// maxReplayed is the highest persisted seq already delivered from
		// the replay snapshot. AppendRemediationEvent and fanout are not
		// atomic, so an event appended just before our snapshot but fanned
		// out just after we registered would arrive on sub.ch a second
		// time; skipping live events at or below the high-water mark
		// de-dupes that replay/live boundary without holding the manager
		// lock across a store write.
		maxReplayed := afterSeq
		for _, ev := range replay {
			if ev.Seq > maxReplayed {
				maxReplayed = ev.Seq
			}
			select {
			case out <- ev:
			case <-subCtx.Done():
				return
			}
		}
		for {
			select {
			case ev := <-sub.ch:
				if ev.Seq > 0 && ev.Seq <= maxReplayed {
					continue
				}
				select {
				case out <- ev:
				case <-subCtx.Done():
					return
				case <-sub.done:
					return
				}
			case <-subCtx.Done():
				return
			}
		}
	}()

	cancel := func() {
		cancelSub()
		m.mu.Lock()
		delete(m.subs[executionID], sub)
		if len(m.subs[executionID]) == 0 {
			delete(m.subs, executionID)
		}
		m.mu.Unlock()
		close(sub.done)
		<-finished
	}
	return out, cancel, nil
}

// rollbackIDSuffix marks a client-visible ID as belonging to a derived
// rollback runbook/execution rather than a primary one. It is exported via
// RollbackExecutionID so the server can compute and recognise rollback IDs
// without duplicating the convention.
const rollbackIDSuffix = "-rollback"

// RollbackExecutionID deterministically derives the rollback execution ID
// for parentExecutionID, so a repeated DeriveRollback call (phase A of
// incident.rollback) is naturally idempotent and the server can recognise a
// client-supplied execution id as "this is a rollback" without a store
// round trip.
func RollbackExecutionID(parentExecutionID string) string {
	return parentExecutionID + rollbackIDSuffix
}

// IsRollbackExecutionID reports whether id was derived by
// RollbackExecutionID.
func IsRollbackExecutionID(id string) bool {
	return len(id) > len(rollbackIDSuffix) && id[len(id)-len(rollbackIDSuffix):] == rollbackIDSuffix
}

// DeriveRollback builds and persists (via Propose, so it is fully
// idempotent and immutable) a companion runbook that structurally reverses
// parentExecutionID's approved runbook -- never the parent's opaque
// Rollback display commands, which have no typed executor binding and
// would be a raw-shell bypass to run directly. It never approves or
// executes the result: the caller must separately Approve/Execute the
// returned execution's ID with a token freshly minted for it, exactly like
// any other proposal.
//
// The parent must have reached at least "executing" (Execute must have run
// at least one step) -- rolling back an execution that never mutated
// anything makes no sense. The parent runbook must also declare a non-empty
// Rollback plan (ErrNoRollbackPlan otherwise): that field is the runbook
// author's signal that this remediation is meant to be reversible, even
// though the actual reversal here is computed structurally rather than by
// running the author's display commands. A step kind this package cannot
// safely invert (see invertStep) fails the whole derivation with
// ErrRollbackUnsupported rather than silently omitting it.
func (m *Manager) DeriveRollback(ctx context.Context, parentExecutionID string) (store.RemediationExecution, error) {
	parent, err := m.store.GetExecution(parentExecutionID)
	if err != nil {
		return store.RemediationExecution{}, err
	}
	switch parent.Status {
	case store.RemediationExecuting, store.RemediationVerifying, store.RemediationResolved, store.RemediationRemediationFailed:
	default:
		return store.RemediationExecution{}, fmt.Errorf("remediation: derive rollback from %s: %w", parent.Status, ErrInvalidState)
	}
	parentRb, err := m.Runbook(parent.RunbookID)
	if err != nil {
		return store.RemediationExecution{}, err
	}
	if len(parentRb.Rollback) == 0 {
		return store.RemediationExecution{}, ErrNoRollbackPlan
	}
	inverted, err := invertSteps(parentRb.Steps)
	if err != nil {
		return store.RemediationExecution{}, fmt.Errorf("%w: %v", ErrRollbackUnsupported, err)
	}
	rollbackRb := runbook.Runbook{
		ID:            parentRb.ID + rollbackIDSuffix,
		SchemaVersion: parentRb.SchemaVersion,
		IncidentID:    parentRb.IncidentID,
		Summary:       "Rollback of " + parentRb.ID,
		Risk:          parentRb.Risk,
		RunAs:         parentRb.RunAs,
		Steps:         inverted,
	}
	if rollbackForcesL3(inverted) {
		rollbackRb.Blocked = true
		rollbackRb.BlockedReason = runbook.BlockedL3Reason
	}
	return m.Propose(ctx, RollbackExecutionID(parentExecutionID), parent.IncidentID, rollbackRb)
}

// invertSteps structurally reverses steps in reverse order (undo the last
// change first), or returns an error naming the first step it cannot
// safely invert.
func invertSteps(steps []runbook.Step) ([]runbook.Step, error) {
	out := make([]runbook.Step, len(steps))
	for i, j := len(steps)-1, 0; i >= 0; i, j = i-1, j+1 {
		inv, err := invertStep(steps[i])
		if err != nil {
			return nil, err
		}
		out[j] = inv
	}
	return out, nil
}

// invertStep returns the typed, guarded step that undoes step, or an error
// if step's kind has no safe structural inverse (aiproposal.KindProcessKill
// and aiproposal.KindSecurityFix: killing a process or an ad hoc security
// fix cannot be mechanically undone).
func invertStep(step runbook.Step) (runbook.Step, error) {
	switch step.Kind {
	case aiproposal.KindFirewallAdd:
		return runbook.Step{Kind: aiproposal.KindFirewallRemove, Params: step.Params, Description: "Revert: " + step.Description}, nil
	case aiproposal.KindFirewallRemove:
		return runbook.Step{Kind: aiproposal.KindFirewallAdd, Params: step.Params, Description: "Revert: " + step.Description}, nil
	case aiproposal.KindServiceAction:
		action, _ := step.Params["action"].(string)
		inv, ok := invertServiceAction(action)
		if !ok {
			return runbook.Step{}, fmt.Errorf("service action %q has no safe inverse", action)
		}
		params := make(map[string]any, len(step.Params))
		for k, v := range step.Params {
			params[k] = v
		}
		params["action"] = inv
		return runbook.Step{Kind: step.Kind, Params: params, Description: "Revert: " + step.Description}, nil
	default:
		return runbook.Step{}, fmt.Errorf("step kind %q cannot be safely reversed", step.Kind)
	}
}

func invertServiceAction(action string) (string, bool) {
	switch action {
	case "start":
		return "stop", true
	case "stop":
		return "start", true
	case "enable":
		return "disable", true
	case "disable":
		return "enable", true
	default:
		return "", false
	}
}

// rollbackForcesL3 mirrors the runbook package's own SSH-lockout
// classifier (isFirewallLockoutStep), restricted to the firewall inversions
// this package can produce: a derived rollback that would remove any
// port-22 allow rule or add a port-22 deny/reject rule is always blocked,
// exactly like a primary runbook containing the same step.
func rollbackForcesL3(steps []runbook.Step) bool {
	for _, step := range steps {
		port, _ := step.Params["port"].(float64)
		if int(port) != 22 {
			continue
		}
		switch step.Kind {
		case aiproposal.KindFirewallRemove:
			return true
		case aiproposal.KindFirewallAdd:
			action, _ := step.Params["action"].(string)
			if action == "deny" || action == "reject" {
				return true
			}
		}
	}
	return false
}
