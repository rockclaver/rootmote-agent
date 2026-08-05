// Package remediation owns the durable "approve, execute, verify" lifecycle
// for an approved runbook (issue #74 Phase 6, Task 2). It persists the full
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
// issue #74's Task 3, which also wires the real ApprovalValidator over the
// existing review.Manager.ConsumeToken path; here it is only an interface,
// exercised by fakes.
package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
	store     *store.Store
	executor  StepExecutor
	validator ApprovalValidator
	verifier  InternalVerifier
	projector Projector
	now       func() time.Time
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
		store:     cfg.Store,
		executor:  cfg.Executor,
		validator: cfg.Validator,
		verifier:  cfg.Verifier,
		projector: cfg.Projector,
		now:       now,
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
	if err := m.store.TransitionExecution(executionID, store.RemediationApproved, store.RemediationExecuting, startAt); err != nil {
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
			"index": i, "kind": string(step.Kind), "exit_code": res.ExitCode, "output": res.Output,
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
// sequence) and only then, best-effort, hands it to the Projector -- so a
// Projector failure can never lose the local record, which is already
// durable by the time Project is called.
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
	if m.projector != nil {
		_ = m.projector.Project(ctx, ev)
	}
	return ev, nil
}
