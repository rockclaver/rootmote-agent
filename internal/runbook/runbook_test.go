package runbook

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/notifications"
)

// stubProposer returns a canned Proposal and counts invocations so throttle
// tests can assert "called exactly once".
type stubProposer struct {
	mu        sync.Mutex
	result    Proposal
	err       error
	calls     int
	gotAlert  Alert
	gotGround Grounding
}

func (s *stubProposer) Propose(_ context.Context, a Alert, g Grounding) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.gotAlert = a
	s.gotGround = g
	return s.result, s.err
}

func (s *stubProposer) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func newTestManager(t *testing.T, proposer Proposer) (*Manager, *aiproposal.Manager, *notifications.Hub) {
	t.Helper()
	apm := aiproposal.New()
	hub := notifications.NewHub()
	m, err := New(Config{
		AIProposals:   apm,
		Proposer:      proposer,
		Notifications: hub,
		Now:           func() time.Time { return time.Unix(1700000000, 0) },
		Throttle:      50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m, apm, hub
}

func sampleAlert() Alert {
	return Alert{
		ServerID: "local",
		Rule:     "disk_usage",
		Target:   "/",
		Body:     "Disk / usage 91.0%",
		Severity: "warning",
		FiredAt:  time.Unix(1700000000, 0),
	}
}

func TestHandle_CreatesRunbookAndFansOutSteps(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "rotate journal logs, restart postgres",
		Risk:    RiskMedium,
		Steps: []Step{
			{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "postgres.service", "action": "restart"}, Description: "restart postgres"},
		},
	}}
	m, apm, _ := newTestManager(t, prop)

	rb := m.Handle(context.Background(), sampleAlert())
	if rb.ID == "" {
		t.Fatalf("expected runbook ID, got zero")
	}
	if len(rb.ProposalIDs) != 1 || rb.ProposalIDs[0] == "" {
		t.Fatalf("step not fanned out as aiproposal: %+v", rb.ProposalIDs)
	}
	if rb.Skipped {
		t.Fatalf("non-empty steps should not be Skipped")
	}
	if rb.Risk != RiskMedium {
		t.Fatalf("risk=%q want medium", rb.Risk)
	}

	// aiproposal must be queryable with the existing approve path's binding.
	ap, err := apm.Get(rb.ProposalIDs[0])
	if err != nil {
		t.Fatalf("aiproposal.Get: %v", err)
	}
	if ap.TokenAction != "infra.service.restart" {
		t.Fatalf("token action mismatch: %q", ap.TokenAction)
	}
	if len(ap.TokenFiles) != 1 || ap.TokenFiles[0] != "postgres.service" {
		t.Fatalf("token files mismatch: %+v", ap.TokenFiles)
	}
	if ap.Rationale != "restart postgres" {
		t.Fatalf("rationale mismatch: %q", ap.Rationale)
	}
}

func TestHandleManual_UsesSelectedAgentProposerAndBypassesThrottle(t *testing.T) {
	defaultProp := &stubProposer{result: Proposal{
		Summary: "default",
		Steps:   []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "default.service", "action": "restart"}}},
	}}
	codexProp := &stubProposer{result: Proposal{
		Summary: "codex fix",
		Risk:    RiskLow,
		Steps:   []Step{{Kind: aiproposal.KindFirewallAdd, Params: map[string]any{"action": "deny", "protocol": "tcp", "port": 6379}}},
	}}
	apm := aiproposal.New()
	m, err := New(Config{
		AIProposals: apm,
		Proposer:    defaultProp,
		ProposerForAgent: func(agent string) Proposer {
			if agent == "codex" {
				return codexProp
			}
			return nil
		},
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
		Throttle: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	rb1, err := m.HandleManual(context.Background(), sampleAlert(), "codex")
	if err != nil {
		t.Fatal(err)
	}
	rb2, err := m.HandleManual(context.Background(), sampleAlert(), "codex")
	if err != nil {
		t.Fatal(err)
	}
	if rb1.ID == "" || rb2.ID == "" {
		t.Fatalf("manual runbooks should be created, got %+v %+v", rb1, rb2)
	}
	if defaultProp.Calls() != 0 {
		t.Fatalf("default proposer calls=%d, want 0", defaultProp.Calls())
	}
	if codexProp.Calls() != 2 {
		t.Fatalf("codex proposer calls=%d, want 2", codexProp.Calls())
	}
	if len(apm.List()) != 2 {
		t.Fatalf("aiproposals=%d, want 2", len(apm.List()))
	}
}

func TestHandleManual_ReturnsProposerError(t *testing.T) {
	proposer := &stubProposer{err: errors.New("codex exec: auth token expired")}
	m, _, _ := newTestManager(t, proposer)

	_, err := m.HandleManual(context.Background(), sampleAlert(), "")
	if err == nil {
		t.Fatal("expected proposer error")
	}
	if !strings.Contains(err.Error(), "auth token expired") {
		t.Fatalf("err=%q", err)
	}
}

func TestHandle_SecurityFixStepFansOutAsProposal(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "enable auditd",
		Risk:    RiskLow,
		Steps: []Step{{
			Kind:        aiproposal.KindSecurityFix,
			Params:      map[string]any{"kind": "enable_auditd"},
			Description: "install and enable auditd",
		}},
	}}
	m, apm, _ := newTestManager(t, prop)

	rb := m.Handle(context.Background(), sampleAlert())
	if rb.ID == "" || len(rb.ProposalIDs) != 1 || rb.ProposalIDs[0] == "" {
		t.Fatalf("runbook/proposals = %+v", rb)
	}
	ap, err := apm.Get(rb.ProposalIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if ap.Kind != aiproposal.KindSecurityFix {
		t.Fatalf("kind = %q", ap.Kind)
	}
	if ap.TokenAction != "security.fix.enable_auditd" || ap.TokenProjectID != "security" || len(ap.TokenFiles) != 1 || ap.TokenFiles[0] != "auditd" {
		t.Fatalf("token binding = %s %s %+v", ap.TokenAction, ap.TokenProjectID, ap.TokenFiles)
	}
}

func TestHandle_RunScriptStepForcesHighRiskAndBindsExactScript(t *testing.T) {
	script := "chmod 640 /etc/shadow && chown root:shadow /etc/shadow"
	prop := &stubProposer{result: Proposal{
		Summary: "tighten /etc/shadow permissions",
		Risk:    RiskLow, // model under-reports; manager must not trust this.
		Steps: []Step{{
			Kind:        aiproposal.KindSecurityFix,
			Params:      map[string]any{"kind": "run_script", "script": script},
			Description: "fix /etc/shadow ownership and permissions",
		}},
	}}
	m, apm, _ := newTestManager(t, prop)

	rb := m.Handle(context.Background(), sampleAlert())
	if rb.Risk != RiskHigh {
		t.Fatalf("risk = %q, want forced high for a run_script step", rb.Risk)
	}
	if len(rb.ProposalIDs) != 1 || rb.ProposalIDs[0] == "" {
		t.Fatalf("step not fanned out: %+v", rb)
	}
	ap, err := apm.Get(rb.ProposalIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if ap.TokenAction != "security.fix.run_script" || ap.TokenProjectID != "security" {
		t.Fatalf("token binding = %s %s", ap.TokenAction, ap.TokenProjectID)
	}
	if len(ap.TokenFiles) != 1 || ap.TokenFiles[0] != script {
		t.Fatalf("token files = %+v, want exact script text", ap.TokenFiles)
	}
}

func TestHandle_RunScriptStepMissingScriptSkipped(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "bad step",
		Risk:    RiskMedium,
		Steps: []Step{{
			Kind:   aiproposal.KindSecurityFix,
			Params: map[string]any{"kind": "run_script"},
		}},
	}}
	m, _, _ := newTestManager(t, prop)

	rb := m.Handle(context.Background(), sampleAlert())
	if len(rb.ProposalIDs) != 1 || rb.ProposalIDs[0] != "" {
		t.Fatalf("expected invalid step skipped with empty proposal id: %+v", rb.ProposalIDs)
	}
}

func TestHandle_NoFixRecommendedProducesNoProposalsAndNoPush(t *testing.T) {
	prop := &stubProposer{result: Proposal{Summary: "manual investigation required"}}
	m, apm, hub := newTestManager(t, prop)

	var pushes int32
	unsub := hub.Subscribe(func(n notifications.Notification) {
		if n.Type == "infra.runbook" {
			atomic.AddInt32(&pushes, 1)
		}
	})
	defer unsub()

	rb := m.Handle(context.Background(), sampleAlert())
	if !rb.Skipped {
		t.Fatalf("expected Skipped=true")
	}
	if len(rb.ProposalIDs) != 0 {
		t.Fatalf("no-fix path must not create proposals: %+v", rb.ProposalIDs)
	}
	if len(apm.List()) != 0 {
		t.Fatalf("no-fix path created %d aiproposals", len(apm.List()))
	}
	if atomic.LoadInt32(&pushes) != 0 {
		t.Fatalf("no-fix path emitted %d push notifications", pushes)
	}
}

func TestHandle_ThrottlePreventsDuplicateWithinWindow(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "x", Risk: RiskLow,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "x.service", "action": "restart"}}},
	}}
	m, _, _ := newTestManager(t, prop)

	rb1 := m.Handle(context.Background(), sampleAlert())
	rb2 := m.Handle(context.Background(), sampleAlert())
	if rb1.ID == "" {
		t.Fatalf("first call should produce a runbook")
	}
	if rb2.ID != "" {
		t.Fatalf("throttled call should produce zero runbook, got %+v", rb2)
	}
	if prop.Calls() != 1 {
		t.Fatalf("proposer calls=%d, want 1 (throttled)", prop.Calls())
	}
}

func TestHandle_ThrottleAdvancesWithTimeAfterWindow(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "x", Risk: RiskLow,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "x.service", "action": "restart"}}},
	}}
	apm := aiproposal.New()
	clock := time.Unix(1700000000, 0)
	m, err := New(Config{
		AIProposals: apm,
		Proposer:    prop,
		Now:         func() time.Time { return clock },
		Throttle:    10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	if rb := m.Handle(context.Background(), sampleAlert()); rb.ID == "" {
		t.Fatalf("first should fire")
	}
	clock = clock.Add(11 * time.Minute)
	if rb := m.Handle(context.Background(), sampleAlert()); rb.ID == "" {
		t.Fatalf("post-window call should fire")
	}
	if prop.Calls() != 2 {
		t.Fatalf("proposer calls=%d, want 2", prop.Calls())
	}
}

func TestHandle_ThrottleScopedPerAlertKey(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "x", Risk: RiskLow,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "x.service", "action": "restart"}}},
	}}
	m, _, _ := newTestManager(t, prop)

	a1 := sampleAlert()
	a2 := sampleAlert()
	a2.Target = "/var" // different mountpoint => different key
	a3 := sampleAlert()
	a3.Rule = "unit_failed"
	a3.Target = "postgres.service"

	if rb := m.Handle(context.Background(), a1); rb.ID == "" {
		t.Fatalf("a1 should fire")
	}
	if rb := m.Handle(context.Background(), a2); rb.ID == "" {
		t.Fatalf("a2 different target should fire")
	}
	if rb := m.Handle(context.Background(), a3); rb.ID == "" {
		t.Fatalf("a3 different rule should fire")
	}
	if prop.Calls() != 3 {
		t.Fatalf("proposer calls=%d, want 3", prop.Calls())
	}
}

func TestHandle_ProposerErrorStillConsumesThrottleSlot(t *testing.T) {
	// Flapping-alert defence: if the proposer fails, we must NOT immediately
	// retry on the next alert burst (which would tight-loop). The throttle
	// slot is consumed on attempt, not on success.
	prop := &stubProposer{err: errors.New("api down")}
	m, _, _ := newTestManager(t, prop)

	for range 5 {
		_ = m.Handle(context.Background(), sampleAlert())
	}
	if prop.Calls() != 1 {
		t.Fatalf("proposer calls=%d, want 1 (throttle holds on failure)", prop.Calls())
	}
}

func TestHandle_InvalidStepSkippedNotFanout(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "kill bad process, restart good service",
		Steps: []Step{
			{Kind: aiproposal.KindProcessKill, Params: map[string]any{"pid": 0}}, // invalid
			{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "good.service", "action": "restart"}},
		},
	}}
	m, apm, _ := newTestManager(t, prop)

	rb := m.Handle(context.Background(), sampleAlert())
	if len(rb.ProposalIDs) != 2 {
		t.Fatalf("ProposalIDs len=%d, want 2 (slot reserved per step)", len(rb.ProposalIDs))
	}
	if rb.ProposalIDs[0] != "" {
		t.Fatalf("invalid step should have empty proposal ID, got %q", rb.ProposalIDs[0])
	}
	if rb.ProposalIDs[1] == "" {
		t.Fatalf("valid step should have a proposal ID")
	}
	if len(apm.List()) != 1 {
		t.Fatalf("aiproposals=%d, want 1 (only valid step fanned out)", len(apm.List()))
	}
}

func TestHandle_PublishesRunbookNotificationWithDeepLink(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "restart it", Risk: RiskHigh,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "api.service", "action": "restart"}}},
	}}
	m, _, hub := newTestManager(t, prop)

	gotCh := make(chan notifications.Notification, 1)
	unsub := hub.Subscribe(func(n notifications.Notification) {
		if n.Type == "infra.runbook" {
			select {
			case gotCh <- n:
			default:
			}
		}
	})
	defer unsub()

	rb := m.Handle(context.Background(), sampleAlert())
	select {
	case got := <-gotCh:
		if got.Severity != "critical" {
			t.Fatalf("high-risk should map to critical severity, got %q", got.Severity)
		}
		if got.Data["runbook_id"].(string) != rb.ID {
			t.Fatalf("notification missing runbook_id")
		}
		if got.Data["deep_link"].(string) != "runbook/"+rb.ID {
			t.Fatalf("deep_link wrong: %v", got.Data["deep_link"])
		}
		ids, _ := got.Data["proposal_ids"].([]string)
		if len(ids) != 1 || ids[0] != rb.ProposalIDs[0] {
			t.Fatalf("proposal_ids missing from notification: %+v", got.Data["proposal_ids"])
		}
	case <-time.After(time.Second):
		t.Fatal("no runbook notification within deadline")
	}
}

func TestHandle_GroundingPassedToProposer(t *testing.T) {
	prop := &stubProposer{result: Proposal{Summary: "ok"}}
	apm := aiproposal.New()
	m, err := New(Config{
		AIProposals: apm,
		Proposer:    prop,
		Snapshotter: SnapshotFunc(func(_ context.Context) Grounding {
			return Grounding{Metrics: "M", Services: "S", Processes: "P", Firewall: "F"}
		}),
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
		Throttle: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	m.Handle(context.Background(), sampleAlert())
	if prop.gotGround.Metrics != "M" || prop.gotGround.Services != "S" ||
		prop.gotGround.Processes != "P" || prop.gotGround.Firewall != "F" {
		t.Fatalf("grounding not threaded: %+v", prop.gotGround)
	}
}

func TestStart_FiredAlertProducesProposalQuickly(t *testing.T) {
	// AC: "fired alert produces a proposal within N seconds". We assert
	// well under one second to keep CI fast while still proving the
	// alert -> hub -> manager -> aiproposal chain is wired async.
	prop := &stubProposer{result: Proposal{
		Summary: "x", Risk: RiskLow,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "x.service", "action": "restart"}}},
	}}
	m, apm, hub := newTestManager(t, prop)

	cleanup := m.Start(context.Background())
	defer cleanup()

	_ = hub.Publish(context.Background(), notifications.Notification{
		Type:      "infra.alert",
		Title:     "Infrastructure alert",
		Body:      "Disk / usage 91.0%",
		Severity:  "warning",
		CreatedAt: time.Unix(1700000000, 0),
		Data: map[string]any{
			"server_id": "local",
			"rule":      "disk_usage",
			"target":    "/",
		},
	})

	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("aiproposal not created within deadline; calls=%d, list=%d", prop.Calls(), len(apm.List()))
		default:
		}
		if len(apm.List()) == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStart_AlertClearedDoesNotTrigger(t *testing.T) {
	prop := &stubProposer{result: Proposal{Summary: "x"}}
	m, _, hub := newTestManager(t, prop)
	cleanup := m.Start(context.Background())
	defer cleanup()

	_ = hub.Publish(context.Background(), notifications.Notification{
		Type:      "infra.alert",
		CreatedAt: time.Unix(1700000000, 0),
		Data: map[string]any{
			"server_id": "local", "rule": "disk_usage", "target": "/", "clear": true,
		},
	})
	time.Sleep(50 * time.Millisecond)
	if prop.Calls() != 0 {
		t.Fatalf("cleared alert should not trigger proposer, calls=%d", prop.Calls())
	}
}

func TestSessionHook_AttributesRunbookAndRecordsTrace(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "do thing", Risk: RiskLow,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "x.service", "action": "restart"}}},
	}}
	apm := aiproposal.New()
	var recordedPrompt, recordedResp string
	m, err := New(Config{
		AIProposals: apm,
		Proposer:    prop,
		Session: func(_ context.Context, _ Alert) (string, func(string, string)) {
			return "sess-1", func(p, r string) { recordedPrompt, recordedResp = p, r }
		},
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
		Throttle: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	rb := m.Handle(context.Background(), sampleAlert())
	if rb.SessionID != "sess-1" {
		t.Fatalf("runbook session_id=%q", rb.SessionID)
	}
	if recordedPrompt == "" || recordedResp != "do thing" {
		t.Fatalf("session hook not invoked with prompt/response: %q / %q", recordedPrompt, recordedResp)
	}
	// aiproposal should inherit the session id so audit attribution links.
	ap, _ := apm.Get(rb.ProposalIDs[0])
	if ap.SessionID != "sess-1" {
		t.Fatalf("aiproposal session_id=%q want sess-1", ap.SessionID)
	}
}
