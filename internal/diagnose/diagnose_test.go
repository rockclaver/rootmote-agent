package diagnose

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
	"github.com/rockclaver/rootmote-agent/internal/infra"
)

func newDiagnoseTestPipeline(t *testing.T, threshold float64) (*Pipeline, Target) {
	t.Helper()
	redactor, err := redact.New(nil)
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	hm := infra.HostMetrics{
		Timestamp: fixedNow(),
		Memory:    infra.MemoryMetric{MetricReason: infra.MetricReason{Available: true}, Percent: 97.2}, // available = 2.8%
	}
	collector := NewCollector(CollectorConfig{
		Infra:    &fakeInfraSource{metrics: hm},
		Redactor: redactor,
		Now:      fixedNow,
	})
	return NewPipeline(PipelineConfig{Collector: collector, ConfidenceThreshold: threshold}), Target{IncidentID: "inc_test", Target: "api"}
}

func TestRun_BuildsAssessmentFromSignatures(t *testing.T) {
	pipeline, target := newDiagnoseTestPipeline(t, DefaultConfidenceThreshold)
	assessment, bundle := pipeline.Run(context.Background(), target)

	if len(bundle.EvidenceIDs()) == 0 {
		t.Fatal("bundle has no evidence: collection did not run")
	}
	if len(assessment.Signatures) != 1 || assessment.Signatures[0].ID != "sig_memory_pressure" {
		t.Fatalf("signatures = %+v, want exactly sig_memory_pressure", assessment.Signatures)
	}
	if assessment.SummaryText == "" || assessment.Confidence <= 0 || len(assessment.Hypotheses) != 1 {
		t.Fatalf("assessment not populated from the signature: %+v", assessment)
	}
	if assessment.Hypotheses[0].EvidenceIDs[0] != "met_available_memory_percent" {
		t.Fatalf("hypothesis evidence = %v, want the memory metric id", assessment.Hypotheses[0].EvidenceIDs)
	}
}

func TestRun_MarksLowConfidenceUncertain(t *testing.T) {
	lowThreshold, targetLow := newDiagnoseTestPipeline(t, 0.5)
	notUncertain, _ := lowThreshold.Run(context.Background(), targetLow)
	if notUncertain.Uncertain {
		t.Fatalf("Uncertain = true at confidence %.3f with threshold 0.5, want false", notUncertain.Confidence)
	}

	highThreshold, targetHigh := newDiagnoseTestPipeline(t, 0.99)
	uncertain, _ := highThreshold.Run(context.Background(), targetHigh)
	if !uncertain.Uncertain {
		t.Fatalf("Uncertain = false at confidence %.3f with threshold 0.99, want true", uncertain.Confidence)
	}
}

func TestAssess_NoSignaturesAsksForManualInvestigation(t *testing.T) {
	a := Assess(Bundle{IncidentID: "inc_x"}, nil)
	if !strings.Contains(a.SummaryText, "manual investigation") || a.Confidence != 0 || len(a.Hypotheses) != 0 {
		t.Fatalf("empty assessment = %+v", a)
	}
}

// --- evidence the playbooks depend on ---

type fakeDisk struct {
	dirs []DirSize
	err  error
}

func (f fakeDisk) LargestDirs(context.Context, string, int) ([]DirSize, error) { return f.dirs, f.err }

type fakeStack struct{ stack Stack }

func (f fakeStack) Stack(context.Context) Stack { return f.stack }

type fakeProxy struct {
	log string
	ups []Upstream
}

func (f fakeProxy) Upstreams(context.Context, string) ([]Upstream, error) { return f.ups, nil }
func (f fakeProxy) ErrorLog(context.Context, int) (string, error) {
	if f.log == "" {
		return "", errors.New("permission denied")
	}
	return f.log, nil
}

func collectorWith(cfg CollectorConfig) *Collector {
	cfg.Now = fixedNow
	if cfg.Infra == nil {
		cfg.Infra = &fakeInfraSource{metrics: availableMetrics()}
	}
	return NewCollector(cfg)
}

func TestCollect_DiskIncidentListsLargestDirectories(t *testing.T) {
	c := collectorWith(CollectorConfig{Disk: fakeDisk{dirs: []DirSize{{"/var/lib/docker", 5120}, {"/var/log", 900.4}}}})
	b := c.Collect(context.Background(), Target{IncidentID: "i", MonitorKind: "disk_capacity", Target: "/"})
	var got []Signal
	for _, s := range b.Signals {
		if s.Type == "large_directory" {
			got = append(got, s)
		}
	}
	if len(got) != 2 || got[0].Subject != "/var/lib/docker" || got[0].Value != 5120 || got[1].Value != 900 {
		t.Fatalf("large_directory signals = %+v", got)
	}
}

func TestCollect_DiskIncidentWithoutSourceWarns(t *testing.T) {
	b := collectorWith(CollectorConfig{}).Collect(context.Background(), Target{MonitorKind: "disk_capacity", Target: "/"})
	assertWarningContains(t, b, "by directory")
}

func TestCollect_StoppedPM2AppsBecomeSignatures(t *testing.T) {
	stack := Stack{PM2Apps: []PM2App{
		{User: "ubuntu", App: "worker", Status: "stopped"},
		{User: "ubuntu", App: "web", Status: "online"},
		{User: "deploy", App: "crashy", Status: "errored"},
	}}
	b := collectorWith(CollectorConfig{Stack: fakeStack{stack}}).Collect(context.Background(), Target{MonitorKind: "process_running", Target: "worker"})
	sigs := Match(b)
	var subjects []string
	for _, s := range sigs {
		if s.Type == SigPM2AppStopped {
			subjects = append(subjects, s.Subject)
		}
	}
	if len(subjects) != 2 {
		t.Fatalf("pm2 signatures = %v, want worker and crashy only", subjects)
	}
	for _, c := range b.Components {
		if c.Kind == "pm2_app" && c.Owner == "" {
			t.Fatalf("pm2 component %+v has no owner", c)
		}
	}
}

func TestCollect_PM2AppMonitorSelectsOnlyItsApp(t *testing.T) {
	stack := Stack{PM2Apps: []PM2App{
		{User: "deploy", App: "web", Status: "online"},
		{User: "deploy", App: "worker", Status: "stopped"},
		{User: "app", App: "web", Status: "errored"},
	}}
	c := collectorWith(CollectorConfig{Stack: fakeStack{stack}})

	b := c.Collect(context.Background(), Target{MonitorKind: "pm2_app", Target: "deploy/web"})
	var comps []Component
	for _, comp := range b.Components {
		if comp.Kind == "pm2_app" {
			comps = append(comps, comp)
		}
	}
	if len(comps) != 1 || comps[0].Name != "web" || comps[0].Owner != "deploy" || comps[0].State != "restarting" {
		t.Fatalf("components = %+v, want deploy/web restarting", comps)
	}
	if sigs := Match(b); len(sigs) == 0 || sigs[0].Type != SigPM2AppStopped {
		t.Fatalf("signatures = %+v, want pm2_app_stopped", sigs)
	}

	b = c.Collect(context.Background(), Target{MonitorKind: "pm2_app", Target: "deploy/worker"})
	for _, comp := range b.Components {
		if comp.Kind == "pm2_app" && (comp.Name != "worker" || comp.State != "stopped") {
			t.Fatalf("component = %+v, want deploy/worker stopped", comp)
		}
	}
}

func TestCollect_ExpiringCertificatesBecomeSignatures(t *testing.T) {
	now := fixedNow()
	stack := Stack{Certs: []Cert{
		{Name: "shop.example.com", ExpiresAt: now.Add(9 * 24 * time.Hour)},
		{Name: "old.example.com", ExpiresAt: now.Add(-48 * time.Hour)},
		{Name: "fine.example.com", ExpiresAt: now.Add(90 * 24 * time.Hour)},
	}}
	b := collectorWith(CollectorConfig{Stack: fakeStack{stack}}).Collect(context.Background(), Target{MonitorKind: "cert_expiry", Target: "https://shop.example.com/"})
	var subjects []string
	for _, s := range Match(b) {
		if s.Type == SigCertExpiring {
			subjects = append(subjects, s.Subject)
		}
	}
	if len(subjects) != 1 || subjects[0] != "shop.example.com" {
		t.Fatalf("cert signatures = %v, want only the certificate named by the target", subjects)
	}

	b = collectorWith(CollectorConfig{Stack: fakeStack{stack}}).Collect(context.Background(), Target{MonitorKind: "cert_expiry", Target: "unrelated"})
	if n := len(Match(b)); n != 2 {
		t.Fatalf("with no matching target every expiring certificate is listed; got %d signatures", n)
	}
}

func TestCollect_ProxyIncidentFindsUpstreamService(t *testing.T) {
	proxy := fakeProxy{
		log: `2026/08/05 12:46:01 [error] 12#12: *3 connect() failed (111: Connection refused) while connecting to upstream, upstream: "http://127.0.0.1:3000/api"`,
		ups: []Upstream{{Address: "127.0.0.1:3000", Kind: "unit", Name: "demo-api.service"}},
	}
	b := collectorWith(CollectorConfig{Proxy: proxy}).Collect(context.Background(), Target{MonitorKind: "external_http", Target: "https://shop.example.com", Summary: "HTTP 502"})
	var proxySig *Signature
	for _, s := range Match(b) {
		if s.Type == "proxy_upstream_error" {
			s := s
			proxySig = &s
		}
	}
	if proxySig == nil {
		t.Fatalf("no proxy_upstream_error signature; logs=%+v", b.Logs)
	}
	if proxySig.Subject != "unit:demo-api.service" {
		t.Fatalf("Subject = %q, want unit:demo-api.service", proxySig.Subject)
	}
	if len(proxySig.EvidenceIDs) != 2 {
		t.Fatalf("evidence = %v, want the monitor summary and the error log", proxySig.EvidenceIDs)
	}
}

func TestCollect_ProxyIncidentWithOnlyTheMonitorSummary(t *testing.T) {
	b := collectorWith(CollectorConfig{Proxy: fakeProxy{}}).Collect(context.Background(), Target{MonitorKind: "external_http", Target: "https://shop.example.com", Summary: "Returned HTTP 502"})
	assertWarningContains(t, b, "proxy error log unavailable")
	found := false
	for _, s := range Match(b) {
		if s.Type == "proxy_upstream_error" {
			found = true
			if s.Subject != "" {
				t.Fatalf("Subject = %q, want empty when no backend is known", s.Subject)
			}
		}
	}
	if !found {
		t.Fatal("a 502 in the monitor summary should match proxy_upstream_error")
	}
}

func TestCollect_OOMSignalNamesTheKilledProcessAndMemoryNumbers(t *testing.T) {
	hm := availableMetrics()
	hm.Memory = infra.MemoryMetric{MetricReason: infra.MetricReason{Available: true}, TotalBytes: 960 << 20, Percent: 97}
	hm.Swap = infra.MemoryMetric{MetricReason: infra.MetricReason{Available: true}, TotalBytes: 0, Percent: 0}
	c := collectorWith(CollectorConfig{Infra: &fakeInfraSource{metrics: hm, oom: []infra.OOMEvent{{PID: 5, Process: "mysqld"}}}})
	b := c.Collect(context.Background(), Target{MonitorKind: "memory_pressure"})
	var oom *Signal
	for i := range b.Signals {
		if b.Signals[i].Type == "oom_kill" {
			oom = &b.Signals[i]
		}
	}
	if oom == nil || oom.Subject != "mysqld" {
		t.Fatalf("oom signal = %+v", oom)
	}
	values := map[string]float64{}
	for _, m := range b.Metrics {
		values[m.Name] = m.Value
	}
	if values["memory_total_mb"] != 960 || values["memory_used_percent"] != 97 {
		t.Fatalf("memory metrics = %v", values)
	}
	if _, ok := values["swap_total_mb"]; !ok {
		t.Fatalf("swap_total_mb missing: %v", values)
	}
}

func TestMatch_StoppedUnitIsAFailureToo(t *testing.T) {
	for state, wantTitle := range map[string]string{"failed": "demo-api.service failed", "inactive": "demo-api.service is inactive"} {
		b := Bundle{Components: []Component{{ID: "cmp_systemd", Kind: "systemd_unit", Name: "demo-api.service", State: state}}}
		sigs := Match(b)
		if len(sigs) != 1 || sigs[0].Type != "unit_failed" || sigs[0].Title != wantTitle || sigs[0].Subject != "demo-api.service" {
			t.Fatalf("state %q: signatures = %+v", state, sigs)
		}
	}
	active := Bundle{Components: []Component{{ID: "c", Kind: "systemd_unit", Name: "x.service", State: "active"}}}
	if len(Match(active)) != 0 {
		t.Fatal("an active unit must not match")
	}
}

func TestCollect_CertificateMonitorOnAFilePathFindsItsCertificate(t *testing.T) {
	now := fixedNow()
	stack := Stack{Certs: []Cert{
		{Name: "shop", ExpiresAt: now.Add(5 * 24 * time.Hour)},
		{Name: "blog", ExpiresAt: now.Add(6 * 24 * time.Hour)},
	}}
	b := collectorWith(CollectorConfig{Stack: fakeStack{stack}}).Collect(context.Background(), Target{MonitorKind: "cert_expiry", Target: "/etc/letsencrypt/live/shop/fullchain.pem"})
	sigs := Match(b)
	if len(sigs) != 1 || sigs[0].Subject != "shop" {
		t.Fatalf("signatures = %+v, want only the certificate in the path", sigs)
	}
}
