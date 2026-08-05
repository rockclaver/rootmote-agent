package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/firewall"
	agentprocess "github.com/rockclaver/rootmote-agent/internal/process"
	"github.com/rockclaver/rootmote-agent/internal/remediation"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/security"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

// remediationExecuteAction and remediationRollbackAction are the exact
// action strings incident.runbook.execute and incident.rollback bind their
// confirmation tokens to (see reviewApprovalValidator.Validate). Distinct
// actions mean a token minted to approve execution can never authorise a
// rollback, or vice versa, even against the same content hash.
const (
	remediationExecuteAction  = "incident.runbook.execute"
	remediationRollbackAction = "incident.runbook.rollback"
)

// remediationTokenBinding computes the (action, project, files) tuple an
// incident.runbook.execute / incident.rollback confirmation token must be
// bound to for executionID + contentHash. It is the single source of truth
// shared by reviewApprovalValidator (which enforces the binding) and
// callers that need to mint a token for one of these actions.
func remediationTokenBinding(executionID, incidentID, contentHash string) (action, project string, files []string) {
	action = remediationExecuteAction
	if remediation.IsRollbackExecutionID(executionID) {
		action = remediationRollbackAction
	}
	return action, "watchtower:" + incidentID, []string{contentHash}
}

// reviewApprovalValidator adapts review.Manager's existing single-use
// confirmation-token consumer -- the same primitive every other guarded
// mutation in this server uses -- into remediation.ApprovalValidator.
// Validate returns the SHA-256 digest of the raw token as the "token ID"
// remediation.Manager is allowed to persist to the audit trail; the raw
// token itself is never written anywhere past ConsumeToken.
type reviewApprovalValidator struct {
	review *review.Manager
	store  *store.Store
}

// NewRemediationApprovalValidator builds the production ApprovalValidator
// wired in cmd/rootmote-agent/main.go.
func NewRemediationApprovalValidator(rm *review.Manager, st *store.Store) remediation.ApprovalValidator {
	return &reviewApprovalValidator{review: rm, store: st}
}

func (v *reviewApprovalValidator) Validate(_ context.Context, token, executionID, contentHash string) (string, error) {
	exec, err := v.store.GetExecution(executionID)
	if err != nil {
		return "", err
	}
	action, project, files := remediationTokenBinding(executionID, exec.IncidentID, contentHash)
	if err := v.review.ConsumeToken(token, action, project, files, ""); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), nil
}

// serverStepExecutor adapts the same typed managers human-initiated WS
// mutations use (systemd/process/firewall/security) into
// remediation.StepExecutor, so a runbook step is always a typed, guarded
// call -- never a raw shell command. Guards (protected unit, protected PID,
// anti-lockout) are enforced inside those managers exactly as they are for
// infra.service.action / infra.process.kill / infra.firewall.rule_* /
// security.fix; this adapter adds one remediation-specific guard of its
// own -- for a firewall or close_port step, the runbook's approved
// "backend" param must match the manager's live-detected backend before
// any mutation, so an approval minted against one backend's semantics can
// never mutate a different one.
type serverStepExecutor struct {
	systemd   *systemd.Manager
	processes *agentprocess.Manager
	firewall  *firewall.Manager
	security  *security.Manager
}

// NewRemediationStepExecutor builds the production StepExecutor wired in
// cmd/rootmote-agent/main.go. Any manager may be nil; a step requiring an
// unconfigured manager fails that step (stopping later steps) rather than
// panicking.
func NewRemediationStepExecutor(sys *systemd.Manager, proc *agentprocess.Manager, fw *firewall.Manager, sec *security.Manager) remediation.StepExecutor {
	return &serverStepExecutor{systemd: sys, processes: proc, firewall: fw, security: sec}
}

func (e *serverStepExecutor) ExecuteStep(ctx context.Context, step runbook.Step) (remediation.StepResult, error) {
	switch step.Kind {
	case aiproposal.KindServiceAction:
		if e.systemd == nil {
			return remediation.StepResult{Output: "systemd subsystem not configured", ExitCode: 1}, nil
		}
		name, _ := step.Params["name"].(string)
		act, _ := step.Params["action"].(string)
		return stepOutcome(e.systemd.Action(ctx, name, systemd.Action(act)))
	case aiproposal.KindProcessKill:
		if e.processes == nil {
			return remediation.StepResult{Output: "process subsystem not configured", ExitCode: 1}, nil
		}
		pid := intFromParams(step.Params["pid"])
		startTicks := uint64FromParams(step.Params["start_time_ticks"])
		signal, _ := step.Params["signal"].(string)
		return stepOutcome(e.processes.Kill(ctx, pid, startTicks, signal))
	case aiproposal.KindFirewallAdd, aiproposal.KindFirewallRemove:
		if e.firewall == nil {
			return remediation.StepResult{Output: "firewall subsystem not configured", ExitCode: 1}, nil
		}
		rule, err := ruleFromParams(step.Params)
		if err != nil {
			return remediation.StepResult{Output: err.Error(), ExitCode: 1}, nil
		}
		if err := e.checkFirewallBackend(ctx, step.Params); err != nil {
			return remediation.StepResult{Output: err.Error(), ExitCode: 1}, nil
		}
		if step.Kind == aiproposal.KindFirewallAdd {
			return stepOutcome(e.firewall.RuleAdd(ctx, rule))
		}
		return stepOutcome(e.firewall.RuleRemove(ctx, rule))
	case aiproposal.KindSecurityFix:
		if e.security == nil {
			return remediation.StepResult{Output: "security subsystem not configured", ExitCode: 1}, nil
		}
		req, err := securityFixRequestFromParams(step.Params)
		if err != nil {
			return remediation.StepResult{Output: err.Error(), ExitCode: 1}, nil
		}
		if req.Kind == security.FixClosePort {
			if err := e.checkFirewallBackend(ctx, step.Params); err != nil {
				return remediation.StepResult{Output: err.Error(), ExitCode: 1}, nil
			}
		}
		_, err = e.security.Fix(ctx, req)
		return stepOutcome(err)
	default:
		return remediation.StepResult{}, fmt.Errorf("remediation: unsupported step kind %q", step.Kind)
	}
}

// checkFirewallBackend enforces that a firewall or close_port step's
// approved "backend" param matches the manager's live-detected backend
// before any mutation -- see serverStepExecutor's doc comment.
func (e *serverStepExecutor) checkFirewallBackend(ctx context.Context, params map[string]any) error {
	if e.firewall == nil {
		return errors.New("firewall subsystem not configured")
	}
	approved, _ := params["backend"].(string)
	if approved == "" {
		return errors.New("step missing approved backend")
	}
	st, err := e.firewall.Status(ctx)
	if err != nil {
		return fmt.Errorf("resolve firewall backend: %w", err)
	}
	if string(st.Backend) != approved {
		return fmt.Errorf("approved backend %q does not match active backend %q", approved, st.Backend)
	}
	return nil
}

// stepOutcome maps a typed manager's error into remediation.StepResult:
// nil is exit 0; any error is a legitimate "the guarded call refused or
// failed" outcome (protected unit, anti-lockout, backend mismatch, host
// failure) -- never a StepExecutor transport failure -- so it is reported
// as a non-zero exit with the error text as output, and Execute stops
// later steps exactly as it does for a real nonzero exit code.
func stepOutcome(err error) (remediation.StepResult, error) {
	if err != nil {
		return remediation.StepResult{Output: err.Error(), ExitCode: 1}, nil
	}
	return remediation.StepResult{ExitCode: 0}, nil
}

// serverInternalVerifier runs a runbook's own bounded post-execution checks
// (runbook.VerificationCheck) against the same typed managers -- never a
// new host command. An empty Verification list is a deliberate "no
// automated check" runbook and passes trivially; an unsupported check Kind
// fails closed rather than silently skipping, so an author who wrote a
// check the agent cannot yet run sees verification fail rather than a
// false "resolved".
type serverInternalVerifier struct {
	systemd  *systemd.Manager
	firewall *firewall.Manager
}

// NewRemediationInternalVerifier builds the production InternalVerifier
// wired in cmd/rootmote-agent/main.go.
func NewRemediationInternalVerifier(sys *systemd.Manager, fw *firewall.Manager) remediation.InternalVerifier {
	return &serverInternalVerifier{systemd: sys, firewall: fw}
}

func (v *serverInternalVerifier) Verify(ctx context.Context, rb runbook.Runbook) (remediation.VerificationResult, error) {
	if len(rb.Verification) == 0 {
		return remediation.VerificationResult{Passed: true, Detail: "no verification checks configured"}, nil
	}
	var failures []string
	for _, chk := range rb.Verification {
		if err := v.runCheck(ctx, chk); err != nil {
			failures = append(failures, chk.ID+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return remediation.VerificationResult{Passed: false, Detail: strings.Join(failures, "; ")}, nil
	}
	return remediation.VerificationResult{Passed: true, Detail: fmt.Sprintf("%d check(s) passed", len(rb.Verification))}, nil
}

func (v *serverInternalVerifier) runCheck(ctx context.Context, chk runbook.VerificationCheck) error {
	switch chk.Kind {
	case "service_active":
		if v.systemd == nil {
			return errors.New("systemd subsystem not configured")
		}
		detail, err := v.systemd.Get(ctx, chk.Target)
		if err != nil {
			return err
		}
		if detail.ActiveState != "active" {
			return fmt.Errorf("active_state=%q", detail.ActiveState)
		}
		return nil
	case "service_inactive":
		if v.systemd == nil {
			return errors.New("systemd subsystem not configured")
		}
		detail, err := v.systemd.Get(ctx, chk.Target)
		if err != nil {
			return err
		}
		if detail.ActiveState == "active" {
			return fmt.Errorf("active_state=%q", detail.ActiveState)
		}
		return nil
	default:
		return fmt.Errorf("unsupported verification kind %q", chk.Kind)
	}
}

// RemediationEventDTO is the wire shape of one incident.execution.event
// frame, mirroring SessionEventDTO for session.event.
type RemediationEventDTO struct {
	ExecutionID string `json:"execution_id"`
	Seq         int64  `json:"seq"`
	Type        string `json:"type"`
	Data        string `json:"data"`
	CreatedAt   int64  `json:"created_at"`
}

func toRemediationEventDTO(ev store.RemediationEvent) RemediationEventDTO {
	return RemediationEventDTO{ExecutionID: ev.ExecutionID, Seq: ev.Seq, Type: ev.Type, Data: ev.Data, CreatedAt: ev.CreatedAt.Unix()}
}

// writeRemediationErr maps a remediation/review/store error to a stable
// error.* wire kind.
func (s *Server) writeRemediationErr(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id string, err error) {
	switch {
	case errors.Is(err, remediation.ErrHashMismatch):
		s.writeError(ctx, c, writeMu, id, "hash_mismatch", err.Error())
	case errors.Is(err, remediation.ErrBlockedL3):
		s.writeError(ctx, c, writeMu, id, "blocked_l3", err.Error())
	case errors.Is(err, remediation.ErrInvalidState):
		s.writeError(ctx, c, writeMu, id, "invalid_state", err.Error())
	case errors.Is(err, remediation.ErrNoRollbackPlan):
		s.writeError(ctx, c, writeMu, id, "no_rollback_plan", err.Error())
	case errors.Is(err, remediation.ErrRollbackUnsupported):
		s.writeError(ctx, c, writeMu, id, "rollback_unsupported", err.Error())
	case errors.Is(err, review.ErrTokenInvalid), errors.Is(err, review.ErrTokenUsed),
		errors.Is(err, review.ErrTokenExpired), errors.Is(err, review.ErrTokenMismatch):
		s.writeReviewErr(ctx, c, writeMu, id, err)
	case errors.Is(err, store.ErrNotFound):
		s.writeError(ctx, c, writeMu, id, "not_found", err.Error())
	case errors.Is(err, store.ErrConflict):
		s.writeError(ctx, c, writeMu, id, "conflict", err.Error())
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
}

// dispatchRemediation routes the incident.runbook.*, incident.execution.
// subscribe, incident.verify, and incident.rollback kinds -- the durable
// approve/execute/verify lifecycle for one approved runbook (issue #74
// Task 3). Runbook proposal (Propose) is not exposed here: it belongs to
// the diagnosis/runbook pipeline that decides what to propose in the first
// place; this surface only reads, declines, executes, and rolls back an
// already-proposed execution.
func (s *Server) dispatchRemediation(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Remediation == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "remediation subsystem not configured")
		return
	}
	switch f.Kind {
	case "incident.runbook.get":
		s.handleRemediationGet(ctx, c, writeMu, f)
	case "incident.runbook.decline":
		s.handleRemediationDecline(ctx, c, writeMu, f)
	case "incident.runbook.execute":
		s.handleRemediationExecute(ctx, c, writeMu, f)
	case "incident.execution.subscribe":
		s.handleRemediationSubscribe(ctx, c, writeMu, f)
	case "incident.verify":
		s.handleRemediationVerify(ctx, c, writeMu, f)
	case "incident.rollback":
		s.handleRemediationRollback(ctx, c, writeMu, f)
	}
}

// handleRemediationGet is a pure read: it fetches an already-persisted
// execution and its full immutable runbook JSON. It never proposes --
// error.not_found when either row does not exist.
func (s *Server) handleRemediationGet(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	var in struct {
		ExecutionID string `json:"execution_id"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.ExecutionID == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "execution_id required")
		return
	}
	exec, err := s.cfg.Remediation.GetExecution(in.ExecutionID)
	if err != nil {
		s.writeRemediationErr(ctx, c, writeMu, f.ID, err)
		return
	}
	rb, err := s.cfg.Remediation.Runbook(exec.RunbookID)
	if err != nil {
		s.writeRemediationErr(ctx, c, writeMu, f.ID, err)
		return
	}
	s.writeOK(ctx, c, writeMu, f.ID, "incident.runbook.get", map[string]any{
		"execution": exec,
		"runbook":   rb,
	})
}

func (s *Server) handleRemediationDecline(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	var in struct {
		ExecutionID string `json:"execution_id"`
		Reason      string `json:"reason"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.ExecutionID == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "execution_id required")
		return
	}
	exec, err := s.cfg.Remediation.Decline(ctx, in.ExecutionID, in.Reason)
	if err != nil {
		s.writeRemediationErr(ctx, c, writeMu, f.ID, err)
		return
	}
	s.writeOK(ctx, c, writeMu, f.ID, "incident.runbook.decline", map[string]any{"execution": exec})
}

func (s *Server) handleRemediationExecute(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	var in struct {
		ExecutionID       string `json:"execution_id"`
		IncidentID        string `json:"incident_id"`
		RunbookID         string `json:"runbook_id"`
		ContentHash       string `json:"content_hash"`
		ConfirmationToken string `json:"confirmation_token"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.ExecutionID == "" || in.ContentHash == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "execution_id and content_hash required")
		return
	}
	s.approveAndAckExecute(ctx, c, writeMu, f, in.ExecutionID, in.IncidentID, in.RunbookID, in.ContentHash, in.ConfirmationToken, "incident.runbook.execute")
}

// approveAndAckExecute is the combined Approve+ack+background-Execute path
// shared by incident.runbook.execute and phase B of incident.rollback.
//
// It validates requested/stored/recomputed hash, the L3 block, and the
// single-use confirmation token (all inside Approve, strictly before any
// mutation) only when the execution is still "proposed"; an execution that
// has already left "proposed" (a duplicate/retried call, or a reconnect
// after the ack was lost) skips straight to acking the current state and
// re-issuing Execute, which is itself fully idempotent and performs no
// second host mutation -- see remediation.Manager.Execute. The ack is sent
// before Execute runs, and Execute runs on the server's lifecycle context
// (never the request context), so the run outlives the requesting
// WebSocket disconnecting.
func (s *Server) approveAndAckExecute(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame, executionID, incidentID, runbookID, contentHash, token, ackKind string) {
	exec, err := s.cfg.Remediation.GetExecution(executionID)
	if err != nil {
		s.writeRemediationErr(ctx, c, writeMu, f.ID, err)
		return
	}
	if (incidentID != "" && incidentID != exec.IncidentID) || (runbookID != "" && runbookID != exec.RunbookID) {
		s.writeError(ctx, c, writeMu, f.ID, "execution_mismatch", "incident_id or runbook_id does not match execution")
		return
	}
	switch exec.Status {
	case store.RemediationProposed:
		exec, err = s.cfg.Remediation.Approve(ctx, executionID, contentHash, token)
		if err != nil {
			s.writeRemediationErr(ctx, c, writeMu, f.ID, err)
			return
		}
	case store.RemediationExecuting, store.RemediationVerifying, store.RemediationResolved, store.RemediationRemediationFailed:
		// Exact retries are acknowledged and Execute remains idempotent.
	case store.RemediationBlockedL3:
		s.writeRemediationErr(ctx, c, writeMu, f.ID, remediation.ErrBlockedL3)
		return
	default:
		s.writeRemediationErr(ctx, c, writeMu, f.ID, remediation.ErrInvalidState)
		return
	}
	s.writeOK(ctx, c, writeMu, f.ID, ackKind, map[string]any{"execution": exec})
	s.runRemediationExecute(executionID, contentHash)
}

// runRemediationExecute runs Manager.Execute on the server's own lifecycle
// context (set from Serve's ctx, cancelled on agent shutdown) instead of
// the per-request context, so the run survives the requesting WebSocket
// disconnecting, and instead of context.Background(), which would never
// observe an intentional shutdown. Errors are only logged: any
// transitional state Execute leaves behind is durable and visible to
// incident.runbook.get / incident.verify / incident.execution.subscribe,
// which are the source of truth for the client.
func (s *Server) runRemediationExecute(executionID, contentHash string) {
	lifeCtx := s.lifeCtx
	if lifeCtx == nil {
		log.Printf("remediation: execute %s refused: server lifecycle is not running", executionID)
		return
	}
	go func() {
		if _, err := s.cfg.Remediation.Execute(lifeCtx, executionID, contentHash); err != nil {
			log.Printf("remediation: execute %s: %v", executionID, err)
		}
	}()
}

// handleRemediationSubscribe mirrors dispatchSession's session.subscribe:
// ack immediately, then forward the durable-replay-then-live channel as
// unsolicited incident.execution.event frames until the client disconnects
// or the execution's stream ends.
func (s *Server) handleRemediationSubscribe(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	var in struct {
		ExecutionID string `json:"execution_id"`
		AfterSeq    int64  `json:"after_seq"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.ExecutionID == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "execution_id required")
		return
	}
	ch, cleanup, err := s.cfg.Remediation.Subscribe(ctx, in.ExecutionID, in.AfterSeq)
	if err != nil {
		s.writeRemediationErr(ctx, c, writeMu, f.ID, err)
		return
	}
	s.writeOK(ctx, c, writeMu, f.ID, "incident.execution.subscribe", map[string]any{"execution_id": in.ExecutionID})
	go func() {
		defer cleanup()
		for {
			select {
			case ev, ok := <-ch:
				if !ok {
					return
				}
				s.writeOK(ctx, c, writeMu, "", "incident.execution.event", toRemediationEventDTO(ev))
			case <-ctx.Done():
				return
			}
		}
	}()
}

// handleRemediationVerify is a pure read of the latest persisted
// internal_verification event -- it never re-runs verification.
func (s *Server) handleRemediationVerify(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	var in struct {
		ExecutionID string `json:"execution_id"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.ExecutionID == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "execution_id required")
		return
	}
	exec, err := s.cfg.Remediation.GetExecution(in.ExecutionID)
	if err != nil {
		s.writeRemediationErr(ctx, c, writeMu, f.ID, err)
		return
	}
	events, err := s.cfg.Remediation.EventsAfter(in.ExecutionID, 0)
	if err != nil {
		s.writeRemediationErr(ctx, c, writeMu, f.ID, err)
		return
	}
	var verification map[string]any
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == "internal_verification" {
			_ = json.Unmarshal([]byte(events[i].Data), &verification)
			break
		}
	}
	s.writeOK(ctx, c, writeMu, f.ID, "incident.verify", map[string]any{
		"execution":    exec,
		"verification": verification,
	})
}

// handleRemediationRollback is two-phase under one kind. Phase A (no
// confirmation_token): derive and persist -- via DeriveRollback, which
// reuses Propose -- an immutable rollback runbook from the already-executed
// parent's Rollback plan, and return its own id/hash for review. No host
// mutation happens in phase A. Phase B (content_hash + confirmation_token):
// execution_id must be the rollback execution id phase A returned; the
// token must be freshly minted for "incident.runbook.rollback" against
// that id's own separate content hash (see remediationTokenBinding) --
// approve and execute it exactly like incident.runbook.execute, and never
// automatically: only this explicit, separately-authorised call can ever
// run it.
func (s *Server) handleRemediationRollback(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	var in struct {
		ExecutionID       string `json:"execution_id"`
		IncidentID        string `json:"incident_id"`
		RunbookID         string `json:"runbook_id"`
		ContentHash       string `json:"content_hash"`
		ConfirmationToken string `json:"confirmation_token"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.ExecutionID == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "execution_id required")
		return
	}
	if in.ConfirmationToken == "" {
		rollbackExec, err := s.cfg.Remediation.DeriveRollback(ctx, in.ExecutionID)
		if err != nil {
			s.writeRemediationErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "incident.rollback", map[string]any{
			"rollback_execution_id": rollbackExec.ID,
			"rollback_runbook_id":   rollbackExec.RunbookID,
			"rollback_content_hash": rollbackExec.RunbookHash,
			"execution":             rollbackExec,
		})
		return
	}
	if in.ContentHash == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "content_hash required")
		return
	}
	if !remediation.IsRollbackExecutionID(in.ExecutionID) {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "execution_id must be a rollback execution id from phase A")
		return
	}
	s.approveAndAckExecute(ctx, c, writeMu, f, in.ExecutionID, in.IncidentID, in.RunbookID, in.ContentHash, in.ConfirmationToken, "incident.rollback")
}
