package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	agentprocess "github.com/rockclaver/rootmote-agent/internal/process"
	"github.com/rockclaver/rootmote-agent/internal/remediation"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/security"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

// --- issue #74 Task 3: incident.runbook.* / incident.execution.subscribe /
// incident.verify / incident.rollback over WS ---
//
// These tests exercise the real server-side adapters (approval validator
// over review.Manager.ConsumeToken, typed StepExecutor over the same
// firewall/systemd managers infra.firewall.*/infra.service.* use,
// InternalVerifier) that cmd/rootmote-agent/main.go wires in production --
// never a test-only fake mutation path -- so a bug in the adapters
// themselves fails these tests.

const (
	testRemediationExecuteAction  = "incident.runbook.execute"
	testRemediationRollbackAction = "incident.runbook.rollback"
)

// remediationTestEnv bundles everything a test needs to seed executions at
// the remediation.Manager level (Propose is not a WS kind -- runbook
// generation belongs to the diagnosis/runbook pipeline, out of scope here)
// and then exercise incident.* over the real WebSocket dispatcher.
type remediationTestEnv struct {
	st       *store.Store
	review   *review.Manager
	remed    *remediation.Manager
	firewall *fakeFWBackend
	systemd  *fakeSystemdClient
	cfg      Config
}

func newRemediationTestEnv(t *testing.T) *remediationTestEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	rm := review.New(nil, st, review.HeuristicSummarizer{})

	fwBackend := &fakeFWBackend{kind: "ufw"}
	fwMgr := newFirewallTestMgr(t, fwBackend, nil, nil)

	sysClient := &fakeSystemdClient{details: map[string]systemd.UnitDetail{}}
	sysMgr, err := systemd.New(systemd.Config{Client: sysClient})
	if err != nil {
		t.Fatal(err)
	}

	remed, err := remediation.New(remediation.Config{
		Store:     st,
		Executor:  NewRemediationStepExecutor(sysMgr, (*agentprocess.Manager)(nil), fwMgr, (*security.Manager)(nil)),
		Validator: NewRemediationApprovalValidator(rm, st),
		Verifier:  NewRemediationInternalVerifier(sysMgr, fwMgr),
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{Addr: "127.0.0.1:0", Review: rm, Remediation: remed, Firewall: fwMgr, Systemd: sysMgr}
	return &remediationTestEnv{st: st, review: rm, remed: remed, firewall: fwBackend, systemd: sysClient, cfg: cfg}
}

// firewallDenyRunbook is a one-step L1 runbook that denies port 9999 on the
// ufw backend, with a non-empty Rollback plan (so DeriveRollback has
// something to reverse).
func firewallDenyRunbook(id, incidentID string) runbook.Runbook {
	return runbook.Runbook{
		ID:         id,
		IncidentID: incidentID,
		Summary:    "Block port 9999",
		Risk:       runbook.RiskL1,
		Steps: []runbook.Step{{
			Kind:        aiproposal.KindFirewallAdd,
			Params:      map[string]any{"action": "deny", "protocol": "tcp", "port": float64(9999), "backend": "ufw", "zone": "public"},
			Description: "Deny port 9999",
		}},
		Rollback: []runbook.Command{{Command: "ufw delete deny 9999/tcp", RunAs: "root", Description: "Re-allow port 9999"}},
	}
}

func (e *remediationTestEnv) propose(t *testing.T, executionID, incidentID string, rb runbook.Runbook) store.RemediationExecution {
	t.Helper()
	exec, err := e.remed.Propose(context.Background(), executionID, incidentID, rb)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	return exec
}

func (e *remediationTestEnv) mintToken(t *testing.T, action, incidentID string, files []string) string {
	t.Helper()
	tok, err := e.review.MintConfirmationToken(action, "watchtower:"+incidentID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	return tok.Token
}

func remediationRoundTrip(t *testing.T, cfg Config, kind string, payload []byte) Frame {
	t.Helper()
	return dockerRoundTripConfig(t, cfg, kind, payload)
}

// waitForStatus polls incident.runbook.get over a fresh round trip until
// exec.Status is one of want or the deadline elapses.
func waitForStatus(t *testing.T, cfg Config, executionID string, want ...string) store.RemediationExecution {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"execution_id": executionID})
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp := remediationRoundTrip(t, cfg, "incident.runbook.get", payload)
		var out struct {
			Execution store.RemediationExecution `json:"execution"`
		}
		if resp.Kind == "incident.runbook.get" {
			_ = json.Unmarshal(resp.Payload, &out)
			for _, w := range want {
				if out.Execution.Status == w {
					return out.Execution
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("execution %s did not reach %v (last frame kind=%q payload=%s)", executionID, want, resp.Kind, resp.Payload)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// AC: incident.runbook.get is a pure read of an already-persisted execution
// and its full immutable runbook JSON; it never proposes and 404s cleanly
// when the execution does not exist.
func TestIncidentRunbookGet_ReturnsFullRunbookJSON_AndNotFound(t *testing.T) {
	env := newRemediationTestEnv(t)
	rb := firewallDenyRunbook("rb1", "inc1")
	exec := env.propose(t, "exec1", "inc1", rb)

	payload, _ := json.Marshal(map[string]any{"execution_id": "exec1"})
	resp := remediationRoundTrip(t, env.cfg, "incident.runbook.get", payload)
	if resp.Kind != "incident.runbook.get" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Execution store.RemediationExecution `json:"execution"`
		Runbook   runbook.Runbook            `json:"runbook"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if out.Execution.Status != store.RemediationProposed || out.Execution.RunbookHash != exec.RunbookHash {
		t.Fatalf("execution mismatch: %+v", out.Execution)
	}
	if out.Runbook.ID != rb.ID || out.Runbook.Summary != rb.Summary || len(out.Runbook.Steps) != 1 ||
		out.Runbook.Steps[0].Kind != aiproposal.KindFirewallAdd || len(out.Runbook.Rollback) != 1 ||
		out.Runbook.Risk != runbook.RiskL1 || out.Runbook.ContentHash == "" {
		t.Fatalf("runbook JSON incomplete: %+v", out.Runbook)
	}

	missing, _ := json.Marshal(map[string]any{"execution_id": "does-not-exist"})
	resp = remediationRoundTrip(t, env.cfg, "incident.runbook.get", missing)
	if resp.Kind != "error.not_found" {
		t.Fatalf("missing kind = %q", resp.Kind)
	}
}

// AC: incident.runbook.decline transitions proposed -> declined.
func TestIncidentRunbookDecline(t *testing.T) {
	env := newRemediationTestEnv(t)
	env.propose(t, "exec1", "inc1", firewallDenyRunbook("rb1", "inc1"))

	payload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "reason": "not needed"})
	resp := remediationRoundTrip(t, env.cfg, "incident.runbook.decline", payload)
	if resp.Kind != "incident.runbook.decline" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Execution store.RemediationExecution `json:"execution"`
	}
	_ = json.Unmarshal(resp.Payload, &out)
	if out.Execution.Status != store.RemediationDeclined {
		t.Fatalf("status = %q, want declined", out.Execution.Status)
	}
}

// AC: wrong content hash, wrong token, an already-used token, and a
// blocked_l3 runbook are all rejected by incident.runbook.execute with a
// stable error.* kind and zero StepExecutor mutation.
func TestIncidentRunbookExecute_RejectsBeforeAnyMutation(t *testing.T) {
	env := newRemediationTestEnv(t)
	rb := firewallDenyRunbook("rb1", "inc1")
	exec := env.propose(t, "exec1", "inc1", rb)
	hash := exec.RunbookHash

	assertNoMutation := func(t *testing.T) {
		t.Helper()
		if len(env.firewall.added) != 0 || len(env.firewall.removed) != 0 {
			t.Fatalf("executor mutated host: added=%v removed=%v", env.firewall.added, env.firewall.removed)
		}
	}

	t.Run("wrong_hash", func(t *testing.T) {
		tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})
		payload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "content_hash": "not-the-hash", "confirmation_token": tok})
		resp := remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
		if resp.Kind != "error.hash_mismatch" {
			t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
		}
		assertNoMutation(t)
	})

	t.Run("wrong_token", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "content_hash": hash, "confirmation_token": "bogus"})
		resp := remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
		if resp.Kind != "error.token_invalid" {
			t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
		}
		assertNoMutation(t)
	})

	t.Run("used_token", func(t *testing.T) {
		tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})
		if err := env.review.ConsumeToken(tok, testRemediationExecuteAction, "watchtower:inc1", []string{hash}, ""); err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "content_hash": hash, "confirmation_token": tok})
		resp := remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
		if resp.Kind != "error.token_used" {
			t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
		}
		assertNoMutation(t)
	})

	t.Run("requested_incident_or_runbook_must_match_execution", func(t *testing.T) {
		tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})
		payload, _ := json.Marshal(map[string]any{
			"execution_id": "exec1", "incident_id": "other-incident", "runbook_id": "rb1",
			"content_hash": hash, "confirmation_token": tok,
		})
		resp := remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
		if resp.Kind != "error.execution_mismatch" {
			t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
		}
		assertNoMutation(t)
	})

	t.Run("blocked_l3", func(t *testing.T) {
		blocked := firewallDenyRunbook("rb2", "inc1")
		blocked.Blocked = true
		blocked.BlockedReason = runbook.BlockedL3Reason
		bexec := env.propose(t, "exec2", "inc1", blocked)
		tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{bexec.RunbookHash})
		payload, _ := json.Marshal(map[string]any{"execution_id": "exec2", "content_hash": bexec.RunbookHash, "confirmation_token": tok})
		resp := remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
		if resp.Kind != "error.blocked_l3" {
			t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
		}
		assertNoMutation(t)
	})
}

// AC: a valid execute call acks immediately, mutates the host exactly once
// through the typed firewall manager, reaches "verifying", and an exact
// duplicate call (same execution id + hash) is idempotent -- no second
// mutation.
func TestIncidentRunbookExecute_RunsOnceReachesVerifying_DuplicateIsIdempotent(t *testing.T) {
	env := newRemediationTestEnv(t)
	rb := firewallDenyRunbook("rb1", "inc1")
	exec := env.propose(t, "exec1", "inc1", rb)
	hash := exec.RunbookHash

	tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})
	payload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "content_hash": hash, "confirmation_token": tok})
	resp := remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
	if resp.Kind != "incident.runbook.execute" {
		t.Fatalf("ack kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var ack struct {
		Execution store.RemediationExecution `json:"execution"`
	}
	_ = json.Unmarshal(resp.Payload, &ack)
	if ack.Execution.Status != store.RemediationApproved {
		t.Fatalf("ack status = %q, want approved", ack.Execution.Status)
	}

	final := waitForStatus(t, env.cfg, "exec1", store.RemediationVerifying, store.RemediationRemediationFailed)
	if final.Status != store.RemediationVerifying {
		t.Fatalf("final status = %q, want verifying", final.Status)
	}
	if len(env.firewall.added) != 1 {
		t.Fatalf("firewall Add called %d times, want 1: %+v", len(env.firewall.added), env.firewall.added)
	}

	// Exact duplicate: same execution id + same content hash. No new
	// approve (already past "proposed") and no second host mutation.
	dupTok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})
	dupPayload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "content_hash": hash, "confirmation_token": dupTok})
	dupResp := remediationRoundTrip(t, env.cfg, "incident.runbook.execute", dupPayload)
	if dupResp.Kind != "incident.runbook.execute" {
		t.Fatalf("dup kind = %q payload = %s", dupResp.Kind, dupResp.Payload)
	}
	time.Sleep(50 * time.Millisecond) // let any (incorrect) second background run settle
	if len(env.firewall.added) != 1 {
		t.Fatalf("duplicate execute re-mutated host: added=%+v", env.firewall.added)
	}
}

// AC: a step's approved "backend" param must match the firewall manager's
// live-detected backend before any mutation; a mismatch fails the step
// (stopping later steps) without ever calling Add/Remove.
func TestIncidentRunbookExecute_BackendMismatch_ZeroMutation(t *testing.T) {
	env := newRemediationTestEnv(t) // fake backend reports "ufw"
	rb := firewallDenyRunbook("rb1", "inc1")
	rb.Steps[0].Params["backend"] = "firewalld" // approved backend disagrees with the live one
	exec := env.propose(t, "exec1", "inc1", rb)
	hash := exec.RunbookHash

	tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})
	payload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "content_hash": hash, "confirmation_token": tok})
	remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)

	final := waitForStatus(t, env.cfg, "exec1", store.RemediationVerifying, store.RemediationRemediationFailed)
	if final.Status != store.RemediationRemediationFailed {
		t.Fatalf("status = %q, want remediation_failed", final.Status)
	}
	if len(env.firewall.added) != 0 {
		t.Fatalf("firewall mutated despite backend mismatch: %+v", env.firewall.added)
	}
}

// AC: incident.execution.subscribe replays every persisted event with
// seq > after_seq, then streams live events, with no duplicate delivery.
func TestIncidentExecutionSubscribe_ReplaysThenLiveNoDuplicates(t *testing.T) {
	env := newRemediationTestEnv(t)
	rb := firewallDenyRunbook("rb1", "inc1")
	exec := env.propose(t, "exec1", "inc1", rb)
	hash := exec.RunbookHash
	tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})

	payload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "content_hash": hash, "confirmation_token": tok})
	remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
	waitForStatus(t, env.cfg, "exec1", store.RemediationVerifying, store.RemediationRemediationFailed)

	wsURL, stop := startTestServerWith(t, env.cfg)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	subPayload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "after_seq": 1})
	req, _ := json.Marshal(Frame{ID: "sub", Kind: "incident.execution.subscribe", Payload: subPayload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ack Frame
	_ = json.Unmarshal(data, &ack)
	if ack.Kind != "incident.execution.subscribe" {
		t.Fatalf("subscribe ack kind = %q", ack.Kind)
	}

	readEvent := func() RemediationEventDTO {
		t.Helper()
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var f Frame
		_ = json.Unmarshal(data, &f)
		if f.Kind != "incident.execution.event" {
			t.Fatalf("event kind = %q payload = %s", f.Kind, f.Payload)
		}
		var ev RemediationEventDTO
		_ = json.Unmarshal(f.Payload, &ev)
		return ev
	}

	// seq 2 is a persisted catch-up event. The subscriber was registered
	// before this snapshot, so a racing fanout for seq 2 would be dropped
	// as a duplicate by the manager's replay high-water mark.
	replayed := readEvent()
	if replayed.Seq != 2 {
		t.Fatalf("replayed seq = %d, want 2", replayed.Seq)
	}

	// Manufacture an interrupted execution only through the durable store
	// transition and call the production recovery path. RecoverInterrupted
	// persists seq 3 before it fans out, proving the same subscription
	// receives a true post-subscribe live event after its replay.
	if err := env.st.TransitionExecution("exec1", store.RemediationVerifying, store.RemediationExecuting, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := env.remed.RecoverInterrupted(context.Background()); err != nil {
		t.Fatal(err)
	}
	live := readEvent()
	if live.Seq != 3 {
		t.Fatalf("live seq = %d, want 3", live.Seq)
	}
}

// AC: incident.verify is a read-only lookup of the last persisted
// internal_verification result.
func TestIncidentVerify_ReadsPersistedResult(t *testing.T) {
	env := newRemediationTestEnv(t)
	rb := firewallDenyRunbook("rb1", "inc1")
	exec := env.propose(t, "exec1", "inc1", rb)
	hash := exec.RunbookHash
	tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})
	payload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "content_hash": hash, "confirmation_token": tok})
	remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
	waitForStatus(t, env.cfg, "exec1", store.RemediationVerifying, store.RemediationRemediationFailed)

	verifyPayload, _ := json.Marshal(map[string]any{"execution_id": "exec1"})
	resp := remediationRoundTrip(t, env.cfg, "incident.verify", verifyPayload)
	if resp.Kind != "incident.verify" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Execution    store.RemediationExecution `json:"execution"`
		Verification map[string]any             `json:"verification"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if out.Execution.Status != store.RemediationVerifying {
		t.Fatalf("execution status = %q", out.Execution.Status)
	}
	if out.Verification == nil {
		t.Fatalf("verification missing: %+v", out)
	}
	if passed, _ := out.Verification["passed"].(bool); !passed {
		t.Fatalf("verification = %+v, want passed", out.Verification)
	}
}

// AC: incident.rollback is two-phase. Phase A (no token) derives + persists
// a separate immutable rollback runbook from the executed parent's
// Rollback plan and returns its own id/hash for review -- no mutation.
// Phase B (fresh content_hash + a token freshly minted for
// "incident.runbook.rollback") approves and executes it independently of
// the original execute token/hash.
func TestIncidentRollback_DerivesFreshRunbookAndExecutesWithFreshToken(t *testing.T) {
	env := newRemediationTestEnv(t)
	rb := firewallDenyRunbook("rb1", "inc1")
	exec := env.propose(t, "exec1", "inc1", rb)
	hash := exec.RunbookHash
	tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})
	execPayload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "content_hash": hash, "confirmation_token": tok})
	remediationRoundTrip(t, env.cfg, "incident.runbook.execute", execPayload)
	waitForStatus(t, env.cfg, "exec1", store.RemediationVerifying, store.RemediationRemediationFailed)
	if len(env.firewall.added) != 1 {
		t.Fatalf("setup: firewall Add called %d times, want 1", len(env.firewall.added))
	}

	// Phase A: derive.
	phaseA, _ := json.Marshal(map[string]any{"execution_id": "exec1"})
	respA := remediationRoundTrip(t, env.cfg, "incident.rollback", phaseA)
	if respA.Kind != "incident.rollback" {
		t.Fatalf("phase A kind = %q payload = %s", respA.Kind, respA.Payload)
	}
	var outA struct {
		RollbackExecutionID string `json:"rollback_execution_id"`
		RollbackRunbookID   string `json:"rollback_runbook_id"`
		RollbackContentHash string `json:"rollback_content_hash"`
	}
	if err := json.Unmarshal(respA.Payload, &outA); err != nil {
		t.Fatal(err)
	}
	if outA.RollbackExecutionID == "" || outA.RollbackExecutionID == "exec1" {
		t.Fatalf("bad rollback execution id: %+v", outA)
	}
	if outA.RollbackContentHash == "" || outA.RollbackContentHash == hash {
		t.Fatalf("rollback hash must be its own separate hash: %+v", outA)
	}
	if len(env.firewall.removed) != 0 {
		t.Fatalf("phase A mutated the host: %+v", env.firewall.removed)
	}

	// The original execute token/hash must NOT authorise the rollback
	// execution (different action binding).
	badPayload, _ := json.Marshal(map[string]any{"execution_id": outA.RollbackExecutionID, "content_hash": outA.RollbackContentHash, "confirmation_token": tok})
	badResp := remediationRoundTrip(t, env.cfg, "incident.rollback", badPayload)
	if badResp.Kind == "incident.rollback" {
		t.Fatalf("stale execute token authorised rollback: %s", badResp.Payload)
	}
	if len(env.firewall.removed) != 0 {
		t.Fatalf("rejected token attempt mutated the host: %+v", env.firewall.removed)
	}

	// Phase B: a token freshly minted for incident.runbook.rollback.
	rollbackTok := env.mintToken(t, testRemediationRollbackAction, "inc1", []string{outA.RollbackContentHash})
	phaseB, _ := json.Marshal(map[string]any{"execution_id": outA.RollbackExecutionID, "content_hash": outA.RollbackContentHash, "confirmation_token": rollbackTok})
	respB := remediationRoundTrip(t, env.cfg, "incident.rollback", phaseB)
	if respB.Kind != "incident.rollback" {
		t.Fatalf("phase B kind = %q payload = %s", respB.Kind, respB.Payload)
	}
	waitForStatus(t, env.cfg, outA.RollbackExecutionID, store.RemediationVerifying, store.RemediationRemediationFailed)
	if len(env.firewall.removed) != 1 {
		t.Fatalf("rollback did not run exactly once: removed=%+v", env.firewall.removed)
	}
}
