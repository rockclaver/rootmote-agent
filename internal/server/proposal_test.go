package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/firewall"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	agentprocess "github.com/rockclaver/rootmote-agent/internal/process"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/security"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

// proposalFromResp extracts the proposal object from a successful
// infra.proposal.* response frame.
func proposalFromResp(t *testing.T, resp Frame) aiproposal.Proposal {
	t.Helper()
	var out struct {
		Proposal aiproposal.Proposal `json:"proposal"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatalf("decode proposal: %v (payload=%s)", err, resp.Payload)
	}
	return out.Proposal
}

// AC #46.1: an AI session can read host metrics, service states, processes,
// and firewall state in one round-trip via infra.snapshot.
func TestProposal_InfraSnapshotGroundsAIWithAllFourReads(t *testing.T) {
	infraMgr, err := infra.New(infra.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sysMgr, err := systemd.New(systemd.Config{Client: &fakeSystemdClient{
		units: []systemd.Unit{{Name: "nginx.service", LoadState: "loaded"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeProcFixture(t, root, 200, "worker", "1000", "worker\x00", 1, 1, 1, 1)
	mustWriteFile(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	pm, err := agentprocess.New(agentprocess.Config{
		ProcRoot:     root,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	fwm := newFirewallTestMgr(t,
		&fakeFWBackend{kind: firewall.BackendUFW, rules: []firewall.Rule{
			{Action: firewall.ActionAllow, Protocol: firewall.ProtoTCP, Port: 22},
		}},
		[]int{22}, nil,
	)
	cfg := Config{Addr: "127.0.0.1:0", Infra: infraMgr, Systemd: sysMgr, Processes: pm, Firewall: fwm}
	resp := systemdRoundTrip(t, cfg, "infra.snapshot", nil)
	if resp.Kind != "infra.snapshot" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	// All four read sources must be populated (non-null) so a grounded answer
	// is possible.
	for _, key := range []string{"metrics", "services", "processes", "firewall"} {
		if !strings.Contains(string(resp.Payload), `"`+key+`"`) {
			t.Fatalf("snapshot missing %q field: %s", key, resp.Payload)
		}
		if strings.Contains(string(resp.Payload), `"`+key+`":null`) {
			t.Fatalf("snapshot %q was null: %s", key, resp.Payload)
		}
	}
}

func TestProposalTokenBinding_SecurityFix(t *testing.T) {
	action, projectID, files, err := proposalTokenBinding(
		aiproposal.KindSecurityFix,
		map[string]any{"kind": "enable_auditd"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if action != "security.fix.enable_auditd" || projectID != "security" || len(files) != 1 || files[0] != "auditd" {
		t.Fatalf("binding = %s %s %+v", action, projectID, files)
	}
}

func TestExecuteProposal_SecurityFixEnablesAuditd(t *testing.T) {
	var calls []string
	sec, err := security.New(security.Config{
		ReadFile: func(path string) ([]byte, error) {
			if path == "/etc/debian_version" {
				return []byte("12\n"), nil
			}
			return nil, errors.New("missing")
		},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			call := strings.Join(append([]string{name}, args...), " ")
			calls = append(calls, call)
			if name == "systemctl" && strings.Join(args, " ") == "is-active auditd" {
				return []byte("inactive\n"), errors.New("inactive")
			}
			return []byte("ok\n"), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Security: sec})
	err = s.executeProposal(context.Background(), aiproposal.Proposal{
		Kind:   aiproposal.KindSecurityFix,
		Params: map[string]any{"kind": "enable_auditd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "apt-get install -y auditd") || !strings.Contains(joined, "systemctl enable --now auditd") {
		t.Fatalf("calls =\n%s", joined)
	}
}

func TestProposalTokenBinding_SecurityFixRunScript(t *testing.T) {
	script := "chmod 640 /etc/shadow && chown root:shadow /etc/shadow"
	action, projectID, files, err := proposalTokenBinding(
		aiproposal.KindSecurityFix,
		map[string]any{"kind": "run_script", "script": script},
	)
	if err != nil {
		t.Fatal(err)
	}
	if action != "security.fix.run_script" || projectID != "security" {
		t.Fatalf("binding = %s %s", action, projectID)
	}
	// The token must bind to the exact script text, not a short label —
	// approving one script must never authorise executing a different one.
	if len(files) != 1 || files[0] != script {
		t.Fatalf("token files = %+v, want exact script text", files)
	}
}

func TestProposalTokenBinding_SecurityFixRunScriptRequiresScript(t *testing.T) {
	if _, _, _, err := proposalTokenBinding(
		aiproposal.KindSecurityFix,
		map[string]any{"kind": "run_script"},
	); err == nil {
		t.Fatal("expected error for missing script")
	}
}

func TestExecuteProposal_SecurityFixRunsScriptAsRoot(t *testing.T) {
	var calls []string
	sec, err := security.New(security.Config{
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return []byte("ok\n"), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Security: sec})
	err = s.executeProposal(context.Background(), aiproposal.Proposal{
		Kind:   aiproposal.KindSecurityFix,
		Params: map[string]any{"kind": "run_script", "script": "chmod 640 /etc/shadow"},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "-c chmod 640 /etc/shadow") {
		t.Fatalf("calls =\n%s", joined)
	}
}

// AC #46.2: an AI-proposed action renders as an approval card whose token
// binding is byte-for-byte identical to the binding the human flow uses for
// the same action.
func TestProposal_CreateExposesBindingMatchingHumanPath(t *testing.T) {
	mgr := aiproposal.New()
	cfg := Config{Addr: "127.0.0.1:0", AIProposals: mgr}
	payload, _ := json.Marshal(map[string]any{
		"kind": "infra.service.action",
		"params": map[string]any{
			"name":   "nginx.service",
			"action": "restart",
		},
		"rationale": "high CPU correlates with nginx worker churn",
	})
	resp := systemdRoundTrip(t, cfg, "infra.proposal.create", payload)
	if resp.Kind != "infra.proposal.create" {
		t.Fatalf("create kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	p := proposalFromResp(t, resp)
	if p.Status != aiproposal.StatusPending || p.ID == "" {
		t.Fatalf("bad proposal: %+v", p)
	}
	wantAction, wantProj, wantFiles := serviceLifecycleTokenBinding("nginx.service", systemd.ActionRestart)
	if p.TokenAction != wantAction || p.TokenProjectID != wantProj || strings.Join(p.TokenFiles, ",") != strings.Join(wantFiles, ",") {
		t.Fatalf("binding mismatch: got (%s,%s,%v) want (%s,%s,%v)", p.TokenAction, p.TokenProjectID, p.TokenFiles, wantAction, wantProj, wantFiles)
	}
	// And list returns it.
	resp = systemdRoundTrip(t, cfg, "infra.proposal.list", nil)
	if !strings.Contains(string(resp.Payload), p.ID) {
		t.Fatalf("list missing proposal: %s", resp.Payload)
	}
}

// AC #46.3 + #46.4 + #46.5: approving an AI-proposed action consumes the
// confirmation token, executes through the same systemd manager as the human
// path, and writes an audit row attributed to "ai-proposed".
func TestProposal_ApproveRunsViaTokenPathAndAuditsAsAIProposed(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	fc := &fakeSystemdClient{}
	sysMgr, err := systemd.New(systemd.Config{Client: fc})
	if err != nil {
		t.Fatal(err)
	}
	pmgr := aiproposal.New()
	cfg := Config{Addr: "127.0.0.1:0", AIProposals: pmgr, Systemd: sysMgr, Review: rm}

	// Create the proposal.
	createPayload, _ := json.Marshal(map[string]any{
		"kind": "infra.service.action",
		"params": map[string]any{
			"name": "nginx.service", "action": "restart",
		},
	})
	resp := systemdRoundTrip(t, cfg, "infra.proposal.create", createPayload)
	p := proposalFromResp(t, resp)

	// Approve without token -> rejected, no side effect.
	approvePayload, _ := json.Marshal(map[string]any{"id": p.ID})
	resp = systemdRoundTrip(t, cfg, "infra.proposal.approve", approvePayload)
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("missing-token kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(fc.actions) != 0 {
		t.Fatalf("approve without token executed: %v", fc.actions)
	}

	// Mint a token bound to the proposal and approve.
	tok, err := rm.MintConfirmationToken(p.TokenAction, p.TokenProjectID, p.TokenFiles, "")
	if err != nil {
		t.Fatal(err)
	}
	approvePayload, _ = json.Marshal(map[string]any{"id": p.ID, "confirmation_token": tok.Token})
	resp = systemdRoundTrip(t, cfg, "infra.proposal.approve", approvePayload)
	if resp.Kind != "infra.proposal.approve" {
		t.Fatalf("approve kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(fc.actions) != 1 || fc.actions[0] != "nginx.service:restart" {
		t.Fatalf("executor not called: %v", fc.actions)
	}

	// Audit entry must be attributed to "ai-proposed".
	entries, err := rm.ListAudit("infra.proposal.infra.service.action", "infra", 10)
	if err != nil {
		t.Fatal(err)
	}
	var sawAI bool
	for _, e := range entries {
		if e.Actor == "ai-proposed" && strings.Contains(e.Summary, "executed") {
			sawAI = true
		}
	}
	if !sawAI {
		t.Fatalf("missing ai-proposed audit entry: %+v", entries)
	}

	// Second approval of the same proposal returns already_resolved and
	// performs no additional side effect.
	resp = systemdRoundTrip(t, cfg, "infra.proposal.approve", approvePayload)
	if resp.Kind != "error.already_resolved" {
		t.Fatalf("replay kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(fc.actions) != 1 {
		t.Fatalf("replay re-executed: %v", fc.actions)
	}
}

// AC #46.3 + #46.5: declining an AI proposal performs no side effect.
func TestProposal_DeclineDoesNotExecute(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	fc := &fakeSystemdClient{}
	sysMgr, err := systemd.New(systemd.Config{Client: fc})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Addr: "127.0.0.1:0", AIProposals: aiproposal.New(), Systemd: sysMgr, Review: rm}

	createPayload, _ := json.Marshal(map[string]any{
		"kind":   "infra.service.action",
		"params": map[string]any{"name": "nginx.service", "action": "restart"},
	})
	p := proposalFromResp(t, systemdRoundTrip(t, cfg, "infra.proposal.create", createPayload))

	declinePayload, _ := json.Marshal(map[string]any{"id": p.ID, "comment": "not now"})
	resp := systemdRoundTrip(t, cfg, "infra.proposal.decline", declinePayload)
	if resp.Kind != "infra.proposal.decline" {
		t.Fatalf("decline kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(fc.actions) != 0 {
		t.Fatalf("decline executed action: %v", fc.actions)
	}
	got := proposalFromResp(t, resp)
	if got.Status != aiproposal.StatusDeclined {
		t.Fatalf("status = %q", got.Status)
	}
}

// AC #46.4: AI-proposed actions are rejected by the same protected-unit
// guard as human actions. The guard fires BEFORE the confirmation token is
// consumed.
func TestProposal_ProtectedUnitRejectedBeforeTokenConsumed(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	fc := &fakeSystemdClient{}
	sysMgr, err := systemd.New(systemd.Config{Client: fc})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Addr: "127.0.0.1:0", AIProposals: aiproposal.New(), Systemd: sysMgr, Review: rm}

	createPayload, _ := json.Marshal(map[string]any{
		"kind":   "infra.service.action",
		"params": map[string]any{"name": "sshd.service", "action": "stop"},
	})
	p := proposalFromResp(t, systemdRoundTrip(t, cfg, "infra.proposal.create", createPayload))

	tok, err := rm.MintConfirmationToken(p.TokenAction, p.TokenProjectID, p.TokenFiles, "")
	if err != nil {
		t.Fatal(err)
	}
	approvePayload, _ := json.Marshal(map[string]any{"id": p.ID, "confirmation_token": tok.Token})
	resp := systemdRoundTrip(t, cfg, "infra.proposal.approve", approvePayload)
	if resp.Kind != "error.protected_unit" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(fc.actions) != 0 {
		t.Fatalf("protected unit was acted on: %v", fc.actions)
	}
	// Token was not consumed (guard ran first).
	if err := rm.ConsumeToken(tok.Token, p.TokenAction, p.TokenProjectID, p.TokenFiles, ""); err != nil {
		t.Fatalf("guard consumed token: %v", err)
	}
}

// AC #46.4: AI-proposed process kill on a protected PID is rejected by the
// same guard as the human path.
func TestProposal_ProtectedPIDRejected(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	root := filepath.Join(dir, "proc")
	writeProcFixture(t, root, 66, "bash", "1000", "bash\x00", 1, 1, 1, 1)
	mustWriteFile(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	var signalled bool
	pm, err := agentprocess.New(agentprocess.Config{
		ProcRoot: root,
		AgentPID: 999,
		TmuxPanePIDs: func(context.Context) []int {
			return []int{66}
		},
		Signal: func(context.Context, int, syscall.Signal) error {
			signalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Addr: "127.0.0.1:0", AIProposals: aiproposal.New(), Processes: pm, Review: rm}

	createPayload, _ := json.Marshal(map[string]any{
		"kind": "infra.process.kill",
		"params": map[string]any{
			"pid":              66,
			"start_time_ticks": 1,
			"signal":           agentprocess.SignalTerm,
		},
	})
	p := proposalFromResp(t, systemdRoundTrip(t, cfg, "infra.proposal.create", createPayload))
	tok, err := rm.MintConfirmationToken(p.TokenAction, p.TokenProjectID, p.TokenFiles, "")
	if err != nil {
		t.Fatal(err)
	}
	approvePayload, _ := json.Marshal(map[string]any{"id": p.ID, "confirmation_token": tok.Token})
	resp := systemdRoundTrip(t, cfg, "infra.proposal.approve", approvePayload)
	if resp.Kind != "error.protected_pid" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if signalled {
		t.Fatal("protected pid was signalled via AI proposal")
	}
}

// Review #3329556102 (P1): two concurrent approve calls for the same pending
// proposal — each holding a separately-minted valid confirmation token — must
// not both reach the executor. The proposal is atomically claimed before the
// token is consumed, so only one approver runs the side effect; the other
// sees already_resolved.
func TestProposal_ConcurrentApprovesExecuteAtMostOnce(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})

	// Gate the executor so both goroutines line up at the claim before
	// either is allowed to actually invoke the systemd manager. This makes
	// the race deterministic without sleeps.
	release := make(chan struct{})
	fc := &gatedSystemdClient{release: release}
	sysMgr, err := systemd.New(systemd.Config{Client: fc})
	if err != nil {
		t.Fatal(err)
	}
	pmgr := aiproposal.New()
	cfg := Config{Addr: "127.0.0.1:0", AIProposals: pmgr, Systemd: sysMgr, Review: rm}

	createPayload, _ := json.Marshal(map[string]any{
		"kind": "infra.service.action",
		"params": map[string]any{
			"name": "nginx.service", "action": "restart",
		},
	})
	p := proposalFromResp(t, systemdRoundTrip(t, cfg, "infra.proposal.create", createPayload))

	// Two distinct confirmation tokens, both validly bound to this proposal.
	tokA, err := rm.MintConfirmationToken(p.TokenAction, p.TokenProjectID, p.TokenFiles, "")
	if err != nil {
		t.Fatal(err)
	}
	tokB, err := rm.MintConfirmationToken(p.TokenAction, p.TokenProjectID, p.TokenFiles, "")
	if err != nil {
		t.Fatal(err)
	}
	payloadA, _ := json.Marshal(map[string]any{"id": p.ID, "confirmation_token": tokA.Token})
	payloadB, _ := json.Marshal(map[string]any{"id": p.ID, "confirmation_token": tokB.Token})

	var wg sync.WaitGroup
	respC := make(chan Frame, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		respC <- systemdRoundTrip(t, cfg, "infra.proposal.approve", payloadA)
	}()
	go func() {
		defer wg.Done()
		respC <- systemdRoundTrip(t, cfg, "infra.proposal.approve", payloadB)
	}()
	// Allow the executor to proceed once both goroutines are likely past
	// the claim. The gate is buffered enough that both goroutines complete
	// (one with success, one with already_resolved) regardless of arrival
	// order.
	close(release)
	wg.Wait()
	close(respC)

	var okCount, racedCount int
	for resp := range respC {
		switch resp.Kind {
		case "infra.proposal.approve":
			okCount++
		case "error.already_resolved":
			racedCount++
		default:
			t.Fatalf("unexpected kind %q payload=%s", resp.Kind, resp.Payload)
		}
	}
	if okCount != 1 || racedCount != 1 {
		t.Fatalf("expected exactly one success + one already_resolved, got ok=%d raced=%d", okCount, racedCount)
	}
	if got := fc.calls(); got != 1 {
		t.Fatalf("executor invoked %d times, want exactly 1", got)
	}
}

// gatedSystemdClient blocks Action() until release is closed so the test can
// stage two approval goroutines past the claim before either executes.
type gatedSystemdClient struct {
	release chan struct{}
	mu      sync.Mutex
	count   int
}

func (g *gatedSystemdClient) Available(_ context.Context) error { return nil }
func (g *gatedSystemdClient) List(_ context.Context) ([]systemd.Unit, error) {
	return nil, nil
}
func (g *gatedSystemdClient) Get(_ context.Context, _ string) (systemd.UnitDetail, error) {
	return systemd.UnitDetail{}, nil
}
func (g *gatedSystemdClient) Action(_ context.Context, _ string, _ systemd.Action) error {
	<-g.release
	g.mu.Lock()
	g.count++
	g.mu.Unlock()
	return nil
}
func (g *gatedSystemdClient) Reboot(_ context.Context) error { return nil }
func (g *gatedSystemdClient) calls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.count
}

// AC #46.4: AI-proposed firewall edit covering the active SSH port is
// rejected by anti-lockout (same guard as the human path).
func TestProposal_AntiLockoutRejected(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	b := &fakeFWBackend{kind: firewall.BackendUFW, rules: []firewall.Rule{
		{Action: firewall.ActionAllow, Protocol: firewall.ProtoTCP, Port: 22},
	}}
	fwm := newFirewallTestMgr(t, b, []int{22}, nil)
	cfg := Config{Addr: "127.0.0.1:0", AIProposals: aiproposal.New(), Firewall: fwm, Review: rm}

	createPayload, _ := json.Marshal(map[string]any{
		"kind": "infra.firewall.rule_add",
		"params": map[string]any{
			"action": "deny", "protocol": "tcp", "port": 22,
		},
	})
	p := proposalFromResp(t, systemdRoundTrip(t, cfg, "infra.proposal.create", createPayload))
	tok, err := rm.MintConfirmationToken(p.TokenAction, p.TokenProjectID, p.TokenFiles, "")
	if err != nil {
		t.Fatal(err)
	}
	approvePayload, _ := json.Marshal(map[string]any{"id": p.ID, "confirmation_token": tok.Token})
	resp := systemdRoundTrip(t, cfg, "infra.proposal.approve", approvePayload)
	if resp.Kind != "error.anti_lockout" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(b.added) != 0 {
		t.Fatal("anti-lockout AI proposal reached backend")
	}
}
