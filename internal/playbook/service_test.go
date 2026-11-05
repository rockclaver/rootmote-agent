package playbook

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/steps"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/watchtower"
)

type recordingProposer struct {
	mu    sync.Mutex
	store *store.Store
	calls []proposal
}

type proposal struct {
	executionID string
	incidentID  string
	rb          runbook.Runbook
}

func (p *recordingProposer) Propose(_ context.Context, executionID, incidentID string, rb runbook.Runbook) (store.RemediationExecution, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, proposal{executionID, incidentID, rb})
	e, _, err := p.store.CreateExecution(store.RemediationExecution{
		ID: executionID, IncidentID: incidentID, RunbookID: rb.ID, RunbookHash: "h", Status: store.RemediationProposed,
	})
	return e, err
}

func (p *recordingProposer) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

type countingClient struct {
	mu    sync.Mutex
	calls int
	reply watchtower.PlaybookResponse
	err   error
}

func (c *countingClient) RequestPlaybook(context.Context, watchtower.PlaybookRequest) (watchtower.PlaybookResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.reply, c.err
}

func (c *countingClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

type serviceEnv struct {
	svc      *Service
	st       *store.Store
	proposer *recordingProposer
	client   *countingClient
	bundle   diagnose.Bundle
}

func newServiceEnv(t *testing.T, bundle diagnose.Bundle) *serviceEnv {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	env := &serviceEnv{
		st:       st,
		proposer: &recordingProposer{store: st},
		client:   &countingClient{reply: answer("service.restart", map[string]any{"unit": "nginx.service"})},
		bundle:   bundle,
	}
	env.svc = &Service{
		Store:       st,
		Remediation: env.proposer,
		Generator:   &Generator{Client: env.client, Redactor: newRedactor(t)},
		Collect: func(_ context.Context, tg diagnose.Target) diagnose.Bundle {
			b := env.bundle
			b.IncidentID = tg.IncidentID
			return b
		},
		Inventory:    func(context.Context) (Inventory, OSInfo) { return baseInventory(), OSInfo{Distro: "ubuntu"} },
		ServerID:     func() string { return "srv_1" },
		MonitoringOn: func() bool { return true },
	}
	return env
}

func failedUnitBundle() diagnose.Bundle {
	return diagnose.Bundle{Components: []diagnose.Component{{ID: "cmp_systemd", Kind: "systemd_unit", Name: "demo-api.service", State: "failed"}}}
}

func unmatchedBundle() diagnose.Bundle {
	return diagnose.Bundle{Logs: []diagnose.LogExcerpt{{ID: "log", Source: "systemd:x", Content: "something odd happened"}}}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func firingEvent(kind, target, severity string) watchtower.MonitorEvent {
	return watchtower.MonitorEvent{EventID: "mevt_1", MonitorKind: kind, Target: target, Severity: severity, ToState: "firing", Summary: target + " failed"}
}

func TestIncidentOpened_ProposesCatalogPlaybookWithoutCallingTheService(t *testing.T) {
	env := newServiceEnv(t, failedUnitBundle())
	env.svc.IncidentOpened(firingEvent("systemd_unit", "demo-api.service", "warning"), "inc-42")
	waitFor(t, "the catalog proposal", func() bool { return env.proposer.count() == 1 })

	p := env.proposer.calls[0]
	if p.incidentID != "inc-42" || p.rb.IncidentID != "inc-42" {
		t.Fatalf("proposal bound to %q / %q, want the relay incident id inc-42", p.incidentID, p.rb.IncidentID)
	}
	if p.rb.Source != runbook.SourceCatalog || len(p.rb.Steps) != 1 || p.rb.Steps[0].Kind != steps.ServiceRestartID {
		t.Fatalf("runbook = %+v", p.rb)
	}
	if env.client.count() != 0 {
		t.Fatal("a catalog playbook must not call the playbook service")
	}
	b, err := env.st.GetIncidentBinding("inc-42")
	if err != nil || b.MonitorKind != "systemd_unit" || b.Target != "demo-api.service" || b.Severity != "warning" {
		t.Fatalf("binding = %+v err = %v", b, err)
	}
}

type stackStub struct{ apps []diagnose.PM2App }

func (s stackStub) Stack(context.Context) diagnose.Stack { return diagnose.Stack{PM2Apps: s.apps} }

func TestIncidentOpened_PM2AppMonitorProposesPM2Restart(t *testing.T) {
	for _, status := range []string{"stopped", "errored", "online"} {
		env := newServiceEnv(t, diagnose.Bundle{})
		collector := diagnose.NewCollector(diagnose.CollectorConfig{
			Stack: stackStub{apps: []diagnose.PM2App{{User: "ubuntu", App: "worker", Status: status}}},
		})
		env.svc.Collect = collector.Collect

		env.svc.IncidentOpened(firingEvent("pm2_app", "ubuntu/worker", "critical"), "inc-pm2")
		waitFor(t, status+" proposal", func() bool { return env.proposer.count() == 1 })

		rb := env.proposer.calls[0].rb
		if rb.Source != runbook.SourceCatalog || len(rb.Steps) != 1 || rb.Steps[0].Kind != steps.PM2RestartID {
			t.Fatalf("%s: runbook = %+v, want one pm2.restart step", status, rb)
		}
		p := rb.Steps[0].Params
		if p["app"] != "worker" || p["user"] != "ubuntu" {
			t.Fatalf("%s: params = %v, want app=worker user=ubuntu", status, p)
		}
		if env.client.count() != 0 {
			t.Fatalf("%s: the playbook service was called for a catalog playbook", status)
		}
	}
}

func TestIncidentOpened_CriticalWithNoMatchAsksTheServiceOnce(t *testing.T) {
	env := newServiceEnv(t, unmatchedBundle())
	ev := firingEvent("systemd_unit", "x.service", "critical")
	env.svc.IncidentOpened(ev, "inc-1")
	waitFor(t, "the generated proposal", func() bool { return env.proposer.count() == 1 })
	if env.proposer.calls[0].rb.Source != runbook.SourceGenerated || env.client.count() != 1 {
		t.Fatalf("source = %q, calls = %d", env.proposer.calls[0].rb.Source, env.client.count())
	}
	// The same incident reported again does not start a second request.
	env.svc.IncidentOpened(ev, "inc-1")
	time.Sleep(50 * time.Millisecond)
	if env.client.count() != 1 || env.proposer.count() != 1 {
		t.Fatalf("service calls = %d, proposals = %d, want 1 and 1", env.client.count(), env.proposer.count())
	}
}

func TestIncidentOpened_NonCriticalWithNoMatchMakesNoRequest(t *testing.T) {
	env := newServiceEnv(t, unmatchedBundle())
	env.svc.IncidentOpened(firingEvent("systemd_unit", "x.service", "warning"), "inc-2")
	time.Sleep(100 * time.Millisecond)
	if env.client.count() != 0 || env.proposer.count() != 0 {
		t.Fatalf("service calls = %d, proposals = %d, want none", env.client.count(), env.proposer.count())
	}
}

func TestIncidentOpened_ServiceRefusalProposesNothing(t *testing.T) {
	env := newServiceEnv(t, unmatchedBundle())
	env.client.reply = watchtowerStatus("consent_required")
	env.svc.IncidentOpened(firingEvent("systemd_unit", "x.service", "critical"), "inc-3")
	waitFor(t, "the service call", func() bool { return env.client.count() == 1 })
	time.Sleep(50 * time.Millisecond)
	if env.proposer.count() != 0 {
		t.Fatal("a refused request must not propose anything")
	}
}

func watchtowerStatus(status string) watchtower.PlaybookResponse {
	return watchtower.PlaybookResponse{Status: status, Message: "No."}
}

func TestGenerate_ReturnsExistingExecutionInsteadOfAskingAgain(t *testing.T) {
	env := newServiceEnv(t, failedUnitBundle())
	env.svc.IncidentOpened(firingEvent("systemd_unit", "demo-api.service", "critical"), "inc-5")
	waitFor(t, "the catalog proposal", func() bool { return env.proposer.count() == 1 })

	id, err := env.svc.Generate(context.Background(), Request{IncidentID: "inc-5"})
	if err != nil {
		t.Fatal(err)
	}
	if id != env.proposer.calls[0].executionID || env.proposer.count() != 1 || env.client.count() != 0 {
		t.Fatalf("id = %q, proposals = %d, service calls = %d", id, env.proposer.count(), env.client.count())
	}
}

func TestGenerate_AfterDeclineBuildsAFreshPlaybook(t *testing.T) {
	env := newServiceEnv(t, failedUnitBundle())
	env.svc.IncidentOpened(firingEvent("systemd_unit", "demo-api.service", "warning"), "inc-6")
	waitFor(t, "the catalog proposal", func() bool { return env.proposer.count() == 1 })
	first := env.proposer.calls[0].executionID
	if err := env.st.TransitionExecution(first, store.RemediationProposed, store.RemediationDeclined, time.Now()); err != nil {
		t.Fatal(err)
	}
	id, err := env.svc.Generate(context.Background(), Request{IncidentID: "inc-6"})
	if err != nil || id == first || env.proposer.count() != 2 {
		t.Fatalf("id = %q (first %q) err = %v proposals = %d", id, first, err, env.proposer.count())
	}
}

func TestGenerate_UserRequestCallsTheServiceWhenNothingFitsAndMarksItRequested(t *testing.T) {
	env := newServiceEnv(t, unmatchedBundle())
	var got watchtower.PlaybookRequest
	env.svc.Generator.Client = clientFunc(func(in watchtower.PlaybookRequest) (watchtower.PlaybookResponse, error) {
		got = in
		return env.client.reply, nil
	})
	// An incident the agent has no record of: the app supplies the monitor.
	id, err := env.svc.Generate(context.Background(), Request{IncidentID: "inc-web", MonitorKind: "external_http", Target: "https://shop.example.com/", Severity: "warning"})
	if err != nil || id == "" {
		t.Fatalf("id = %q err = %v", id, err)
	}
	if !got.UserRequested || got.Kind != "external_http" || got.Severity != "warning" || got.IncidentID != "inc-web" {
		t.Fatalf("request = %+v", got)
	}
}

type clientFunc func(watchtower.PlaybookRequest) (watchtower.PlaybookResponse, error)

func (f clientFunc) RequestPlaybook(_ context.Context, in watchtower.PlaybookRequest) (watchtower.PlaybookResponse, error) {
	return f(in)
}

func TestGenerate_UnknownIncidentWithoutDetailsIsUnavailable(t *testing.T) {
	env := newServiceEnv(t, failedUnitBundle())
	_, err := env.svc.Generate(context.Background(), Request{IncidentID: "inc-unknown"})
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != StatusUnavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestGenerate_MonitoringOffIsUnavailable(t *testing.T) {
	env := newServiceEnv(t, failedUnitBundle())
	env.svc.MonitoringOn = func() bool { return false }
	_, err := env.svc.Generate(context.Background(), Request{IncidentID: "inc-1", MonitorKind: "systemd_unit"})
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != StatusUnavailable || pe.Message != "Turn on monitoring to generate playbooks." {
		t.Fatalf("err = %v", err)
	}
}

func TestGenerate_NoPlaybookKeepsFindings(t *testing.T) {
	env := newServiceEnv(t, failedUnitBundle())
	// A failed unit that is not in the inventory has no catalog playbook; the
	// service has nothing either.
	env.bundle.Components[0].Name = "mystery.service"
	env.client.reply = watchtowerStatus("no_playbook")
	_, err := env.svc.Generate(context.Background(), Request{IncidentID: "inc-9", MonitorKind: "systemd_unit", Target: "mystery.service"})
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != StatusNoPlaybook || len(pe.Findings) != 1 || pe.Findings[0].Title != "mystery.service failed" {
		t.Fatalf("err = %v (%+v)", err, pe)
	}
}

func TestToRunbook_CarriesCatalogTextAndUndoFlags(t *testing.T) {
	pb := Playbook{
		Title: "Fix it", Summary: "Because.", Source: "catalog",
		Steps: []Step{
			{Step: steps.ServiceRestartID, Params: steps.Params{"unit": "demo-api.service"}},
			{Step: steps.ServiceStopID, Params: steps.Params{"unit": "worker.service"}},
			{Step: steps.CheckHTTPID, Params: steps.Params{"url": "https://shop.example.com/"}},
		},
		Manual: []Manual{{Text: "Check the last deploy."}},
	}
	rb := ToRunbook(pb, "rb_1", "inc-1", "srv_1")
	if rb.Title != "Fix it" || rb.Source != "catalog" || rb.IncidentID != "inc-1" || rb.ServerID != "srv_1" || len(rb.ManualSteps) != 1 {
		t.Fatalf("runbook = %+v", rb)
	}
	want := []struct {
		command  string
		undoable bool
	}{
		{"systemctl restart demo-api.service", false},
		{"systemctl stop worker.service", true},
		{"", false},
	}
	for i, w := range want[:2] {
		s := rb.Steps[i]
		if s.Command != w.command || s.Undoable != w.undoable || s.Verify == "" || s.Description == "" {
			t.Fatalf("step %d = %+v", i, s)
		}
	}
	if rb.Steps[2].Verify == "" || rb.Steps[2].Undoable {
		t.Fatalf("check step = %+v", rb.Steps[2])
	}
	if len(rb.Rollback) != 1 || rb.Rollback[0].Command != "systemctl start worker.service" {
		t.Fatalf("rollback = %+v, want only the undoable step", rb.Rollback)
	}
	if rb.Risk != runbook.RiskL1 || rb.RunAs != "root" {
		t.Fatalf("risk/runAs = %s/%s", rb.Risk, rb.RunAs)
	}
	hash, err := runbook.ContentHash(rb)
	if err != nil || hash == "" {
		t.Fatalf("hash = %q err = %v", hash, err)
	}
}

func TestToRunbook_RiskLevels(t *testing.T) {
	check := ToRunbook(Playbook{Steps: []Step{{Step: steps.CheckHTTPID, Params: steps.Params{"url": "https://a.example/"}}}}, "r", "i", "s")
	if check.Risk != runbook.RiskL0 || check.RunAs != "" {
		t.Fatalf("check-only risk = %s runAs = %q", check.Risk, check.RunAs)
	}
	fw := ToRunbook(Playbook{Steps: []Step{{Step: steps.FirewallAllowID, Params: steps.Params{"port": 8080, "proto": "tcp"}}}}, "r", "i", "s")
	if fw.Risk != runbook.RiskL2 {
		t.Fatalf("firewall risk = %s", fw.Risk)
	}
	manual := ToRunbook(Playbook{Manual: []Manual{{Text: "Do this."}}}, "r", "i", "s")
	if manual.Risk != runbook.RiskL0 || len(manual.Steps) != 0 {
		t.Fatalf("manual-only = %+v", manual)
	}
}
