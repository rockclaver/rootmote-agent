package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/remediation"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/steps"
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
	firewall *fakeHelper
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

	helper := &fakeHelper{rules: map[string]bool{}}
	sysClient := &fakeSystemdClient{details: map[string]systemd.UnitDetail{}}
	sysMgr, err := systemd.New(systemd.Config{Client: sysClient})
	if err != nil {
		t.Fatal(err)
	}
	runner := &steps.Runner{Env: NewStepsEnv(StepsDeps{Systemd: sysMgr, Priv: helper})}

	remed, err := remediation.New(remediation.Config{
		Store:     st,
		Executor:  NewRemediationStepExecutor(runner),
		Validator: NewRemediationApprovalValidator(rm, st),
		Verifier:  NewRemediationInternalVerifier(runner, runner.Env.Units),
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{Addr: "127.0.0.1:0", Review: rm, Remediation: remed, Systemd: sysMgr}
	return &remediationTestEnv{st: st, review: rm, remed: remed, firewall: helper, systemd: sysClient, cfg: cfg}
}

// fakeHelper stands in for the privilege helper: it records every call and
// keeps the set of open firewall ports so verification can read them back.
type fakeHelper struct {
	mu      sync.Mutex
	rules   map[string]bool
	calls   []string
	added   []string
	removed []string
}

func (f *fakeHelper) Call(_ context.Context, action string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, action+" "+strings.Join(args, " "))
	switch action {
	case "firewall.allow":
		f.added = append(f.added, args[0]+"/"+args[1])
		f.rules[args[0]+"/"+args[1]] = true
	case "firewall.remove":
		f.removed = append(f.removed, args[0]+"/"+args[1])
		delete(f.rules, args[0]+"/"+args[1])
	case "firewall-rules":
		out := []map[string]any{}
		for k := range f.rules {
			port, proto, _ := strings.Cut(k, "/")
			n, _ := strconv.Atoi(port)
			out = append(out, map[string]any{"port": n, "proto": proto})
		}
		return json.Marshal(out)
	}
	return []byte("ok"), nil
}

// firewallDenyRunbook is a one-step L1 runbook that opens port 9999 through
// the firewall.allow step, with a non-empty Rollback plan (so DeriveRollback
// has something to reverse). The name is historical.
func firewallDenyRunbook(id, incidentID string) runbook.Runbook {
	return runbook.Runbook{
		ID:         id,
		IncidentID: incidentID,
		Summary:    "Open port 9999",
		Risk:       runbook.RiskL1,
		Steps: []runbook.Step{{
			Kind:        steps.FirewallAllowID,
			Params:      map[string]any{"proto": "tcp", "port": float64(9999)},
			Description: "Open port 9999",
		}},
		Rollback: []runbook.Command{{Command: "ufw delete allow 9999/tcp", RunAs: "root", Description: "Close port 9999"}},
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
		out.Runbook.Steps[0].Kind != steps.FirewallAllowID || len(out.Runbook.Rollback) != 1 ||
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

// A declined execution is terminal: execute must not turn it into an OK
// acknowledgement or consume/perform any mutation.
func TestIncidentRunbookExecute_DeclinedIsInvalidState(t *testing.T) {
	env := newRemediationTestEnv(t)
	exec := env.propose(t, "exec1", "inc1", firewallDenyRunbook("rb1", "inc1"))
	if _, err := env.remed.Decline(context.Background(), exec.ID, "declined"); err != nil {
		t.Fatal(err)
	}
	tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{exec.RunbookHash})
	payload, _ := json.Marshal(map[string]any{"execution_id": exec.ID, "content_hash": exec.RunbookHash, "confirmation_token": tok})
	resp := remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
	if resp.Kind != "error.invalid_state" {
		t.Fatalf("kind = %q payload=%s", resp.Kind, resp.Payload)
	}
	if len(env.firewall.added) != 0 {
		t.Fatalf("declined execution mutated firewall: %+v", env.firewall.added)
	}
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

// AC: a step the catalog refuses (here: restarting sshd) fails the step
// before the privilege helper or the service manager is ever called, and
// stops the execution.
func TestIncidentRunbookExecute_ProtectedServiceRefused_ZeroMutation(t *testing.T) {
	env := newRemediationTestEnv(t)
	rb := firewallDenyRunbook("rb1", "inc1")
	rb.Steps[0] = runbook.Step{Kind: steps.ServiceRestartID, Params: map[string]any{"unit": "sshd.service"}, Description: "restart ssh"}
	exec := env.propose(t, "exec1", "inc1", rb)
	hash := exec.RunbookHash

	tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})
	payload, _ := json.Marshal(map[string]any{"execution_id": "exec1", "content_hash": hash, "confirmation_token": tok})
	remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)

	final := waitForStatus(t, env.cfg, "exec1", store.RemediationVerifying, store.RemediationRemediationFailed)
	if final.Status != store.RemediationRemediationFailed {
		t.Fatalf("status = %q, want remediation_failed", final.Status)
	}
	if len(env.firewall.calls) != 0 || len(env.systemd.actions) != 0 {
		t.Fatalf("host touched despite refusal: helper=%v systemd=%v", env.firewall.calls, env.systemd.actions)
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

// AC (#74 Task 3 follow-up): a confirmation token's required action must
// come from the execution's persisted Kind, never from the client-minted
// execution ID's shape -- a *primary* execution whose ID happens to end in
// "-rollback" (Propose always persists Kind == store.RemediationKindExecute,
// regardless of ID) still binds and authorises with
// incident.runbook.execute, and a token minted for incident.runbook.rollback
// against the same execution/hash must NOT authorise it.
func TestIncidentRunbookExecute_PrimaryIDLookingLikeRollbackBindsExecuteAction(t *testing.T) {
	env := newRemediationTestEnv(t)
	rb := firewallDenyRunbook("rb1", "inc1")
	exec := env.propose(t, "exec1-rollback", "inc1", rb)
	hash := exec.RunbookHash

	wrongTok := env.mintToken(t, testRemediationRollbackAction, "inc1", []string{hash})
	wrongPayload, _ := json.Marshal(map[string]any{"execution_id": "exec1-rollback", "content_hash": hash, "confirmation_token": wrongTok})
	wrongResp := remediationRoundTrip(t, env.cfg, "incident.runbook.execute", wrongPayload)
	if wrongResp.Kind == "incident.runbook.execute" {
		t.Fatalf("a rollback-action token authorised a primary execution: %s", wrongResp.Payload)
	}
	if len(env.firewall.added) != 0 {
		t.Fatalf("rejected token attempt mutated the host: %+v", env.firewall.added)
	}

	tok := env.mintToken(t, testRemediationExecuteAction, "inc1", []string{hash})
	payload, _ := json.Marshal(map[string]any{"execution_id": "exec1-rollback", "content_hash": hash, "confirmation_token": tok})
	resp := remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
	if resp.Kind != "incident.runbook.execute" {
		t.Fatalf("execute kind = %q payload = %s, want incident.runbook.execute despite ID suffix", resp.Kind, resp.Payload)
	}
	waitForStatus(t, env.cfg, "exec1-rollback", store.RemediationVerifying, store.RemediationRemediationFailed)
	if len(env.firewall.added) != 1 {
		t.Fatalf("firewall Add called %d times, want 1", len(env.firewall.added))
	}
}

// The verifier runs each step's own catalog check and reports the result per
// step, so the app can say which step did not take effect.
func TestInternalVerifier_ReportsEachStepSeparately(t *testing.T) {
	helper := &fakeHelper{rules: map[string]bool{"9999/tcp": true}}
	runner := &steps.Runner{Env: NewStepsEnv(StepsDeps{Priv: helper})}
	verifier := NewRemediationInternalVerifier(runner, nil)
	rb := runbook.Runbook{Steps: []runbook.Step{
		{Kind: steps.FirewallAllowID, Params: map[string]any{"proto": "tcp", "port": float64(9999)}},
		{Kind: steps.FirewallAllowID, Params: map[string]any{"proto": "tcp", "port": float64(8888)}},
	}}
	res, err := verifier.Verify(context.Background(), rb)
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Fatalf("verification passed although port 8888 is not open: %+v", res)
	}
	if len(res.Steps) != 2 || !res.Steps[0].Passed || res.Steps[1].Passed || res.Steps[1].Index != 1 {
		t.Fatalf("per-step results = %+v, want step 0 passed and step 1 failed", res.Steps)
	}
	if res.Steps[1].Detail == "" || !strings.Contains(res.Detail, "step 2") {
		t.Fatalf("failure not explained: detail=%q step=%+v", res.Detail, res.Steps[1])
	}
}

// Every step's verification is stored as its own execution event.
func TestIncidentExecute_RecordsStepVerificationEvents(t *testing.T) {
	env := newRemediationTestEnv(t)
	exec := env.propose(t, "exec-sv", "inc-sv", firewallDenyRunbook("rb-sv", "inc-sv"))
	tok := env.mintToken(t, testRemediationExecuteAction, "inc-sv", []string{exec.RunbookHash})
	payload, _ := json.Marshal(map[string]any{"execution_id": "exec-sv", "content_hash": exec.RunbookHash, "confirmation_token": tok})
	remediationRoundTrip(t, env.cfg, "incident.runbook.execute", payload)
	waitForStatus(t, env.cfg, "exec-sv", store.RemediationVerifying)

	events, err := env.remed.EventsAfter("exec-sv", 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range events {
		if ev.Type != "step_verification" {
			continue
		}
		found = true
		var d struct {
			Index  int    `json:"index"`
			Kind   string `json:"kind"`
			Passed bool   `json:"passed"`
		}
		if err := json.Unmarshal([]byte(ev.Data), &d); err != nil {
			t.Fatal(err)
		}
		if d.Index != 0 || d.Kind != "firewall.allow" || !d.Passed {
			t.Fatalf("step_verification = %+v", d)
		}
	}
	if !found {
		t.Fatalf("no step_verification event in %+v", events)
	}
}
