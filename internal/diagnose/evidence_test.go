package diagnose

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/webserver"
)

// --- fakes ---

type fakeDockerSource struct {
	summaries     []docker.ContainerSummary
	details       map[string]docker.ContainerDetail
	logs          map[string][]docker.LogEntry
	containersErr error
	logsErr       error
}

func (f *fakeDockerSource) Containers(context.Context) ([]docker.ContainerSummary, error) {
	if f.containersErr != nil {
		return nil, f.containersErr
	}
	return f.summaries, nil
}

func (f *fakeDockerSource) Container(_ context.Context, id string) (docker.ContainerDetail, error) {
	d, ok := f.details[id]
	if !ok {
		return docker.ContainerDetail{}, errors.New("fakeDockerSource: no detail for " + id)
	}
	return d, nil
}

func (f *fakeDockerSource) Logs(_ context.Context, id string, _ int) ([]docker.LogEntry, error) {
	if f.logsErr != nil {
		return nil, f.logsErr
	}
	return f.logs[id], nil
}

type fakeSystemdSource struct {
	unit    systemd.UnitDetail
	getErr  error
	list    []systemd.Unit
	logs    string
	logsErr error
}

func (f *fakeSystemdSource) Get(context.Context, string) (systemd.UnitDetail, error) {
	if f.getErr != nil {
		return systemd.UnitDetail{}, f.getErr
	}
	return f.unit, nil
}

func (f *fakeSystemdSource) List(context.Context) ([]systemd.Unit, error) { return f.list, nil }

func (f *fakeSystemdSource) Logs(context.Context, string, int) (string, error) {
	if f.logsErr != nil {
		return "", f.logsErr
	}
	return f.logs, nil
}

type fakeInfraSource struct {
	metrics infra.HostMetrics
	oom     []infra.OOMEvent
	oomErr  error
}

func (f *fakeInfraSource) Sample(context.Context) infra.HostMetrics { return f.metrics }

func (f *fakeInfraSource) OOMEvents(context.Context, time.Time) ([]infra.OOMEvent, error) {
	if f.oomErr != nil {
		return nil, f.oomErr
	}
	return f.oom, nil
}

type fakeWebserverSource struct {
	snap webserver.Snapshot
}

func (f *fakeWebserverSource) List(context.Context) webserver.Snapshot { return f.snap }

func fixedNow() time.Time {
	return time.Date(2026, 8, 5, 12, 47, 0, 0, time.UTC)
}

func availableMetrics() infra.HostMetrics {
	return infra.HostMetrics{
		Timestamp: fixedNow(),
		Memory:    infra.MemoryMetric{MetricReason: infra.MetricReason{Available: true}, TotalBytes: 100, AvailableBytes: 40, Percent: 60},
		Swap:      infra.MemoryMetric{MetricReason: infra.MetricReason{Available: true}, Percent: 5},
		Load:      infra.LoadMetric{MetricReason: infra.MetricReason{Available: true}, One: 0.5},
		Disks: []infra.DiskMetric{
			{Mountpoint: "/", Available: true, Percent: 40, InodePercent: 10},
		},
	}
}

func availableWebserver() webserver.Snapshot {
	return webserver.Snapshot{
		Available: true,
		Webservers: []webserver.Instance{
			{ID: "caddy", Kind: webserver.KindCaddy, ActiveState: "active", Domains: []webserver.Domain{{Host: "example.com"}}},
		},
	}
}

// --- AC1 ---

func TestCollect_AttachesBoundedLogsAndComponentState(t *testing.T) {
	docker1 := &fakeDockerSource{
		summaries: []docker.ContainerSummary{
			{ID: "c1", Name: "api", State: "running", Health: "unhealthy", ComposeProject: "proj"},
			{ID: "c2", Name: "worker", State: "running", ComposeProject: "proj"},
		},
		details: map[string]docker.ContainerDetail{
			"c1": {ID: "c1", Name: "api", Status: "Up 2 minutes (unhealthy)", State: "running", Health: "unhealthy", RestartCount: 1, ComposeProject: "proj"},
		},
		logs: map[string][]docker.LogEntry{
			"c1": {
				{ContainerID: "c1", Line: "starting api"},
				{ContainerID: "c1", Line: "listening on :8080"},
			},
		},
	}
	infraSrc := &fakeInfraSource{metrics: availableMetrics()}
	webSrc := &fakeWebserverSource{snap: availableWebserver()}

	redactor, err := redact.New(nil)
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	c := NewCollector(CollectorConfig{Docker: docker1, Infra: infraSrc, Webserver: webSrc, Redactor: redactor, Now: fixedNow})

	b := c.Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "docker_container", Target: "api"})

	if b.Service.Status != "degraded" {
		t.Fatalf("Service.Status = %q, want degraded (unhealthy running container)", b.Service.Status)
	}
	dockerComponents := 0
	for _, comp := range b.Components {
		if comp.Kind == "docker_container" {
			dockerComponents++
		}
	}
	if dockerComponents != 2 {
		t.Fatalf("docker Components = %d, want 2 (primary + compose sibling); all components = %+v", dockerComponents, b.Components)
	}
	var primary *Component
	for i := range b.Components {
		if b.Components[i].Name == "api" {
			primary = &b.Components[i]
		}
	}
	if primary == nil {
		t.Fatalf("no api component in %+v", b.Components)
	}
	if primary.ID != "cmp_docker_api" || primary.Kind != "docker_container" || primary.State != "running" || primary.Health != "unhealthy" {
		t.Fatalf("primary component = %+v, want cmp_docker_api/docker_container/running/unhealthy", primary)
	}

	if len(b.Logs) != 1 {
		t.Fatalf("Logs = %d, want 1", len(b.Logs))
	}
	if b.Logs[0].Source != "docker:api" || b.Logs[0].ID != "log_docker_api" || !b.Logs[0].Redacted {
		t.Fatalf("log excerpt = %+v", b.Logs[0])
	}
	if !strings.Contains(b.Logs[0].Content, "listening on :8080") {
		t.Fatalf("log content = %q, want it to contain the seeded log line", b.Logs[0].Content)
	}

	if len(b.Metrics) == 0 {
		t.Fatal("Metrics is empty, want host metrics attached")
	}
	foundMem := false
	for _, m := range b.Metrics {
		if m.Name == "available_memory_percent" {
			foundMem = true
			if m.Value != 40 {
				t.Fatalf("available_memory_percent = %v, want 40", m.Value)
			}
		}
	}
	if !foundMem {
		t.Fatalf("Metrics = %+v, want available_memory_percent", b.Metrics)
	}

	if len(b.RecentChanges) != 1 || b.RecentChanges[0].Type != "container_restart" {
		t.Fatalf("RecentChanges = %+v, want one container_restart", b.RecentChanges)
	}
}

// --- AC2 ---

func TestCollect_RedactsEverythingBeforeItEntersTheBundle(t *testing.T) {
	const (
		bearerToken = "sk-liveTOKEN1234567890ABCDEF"
		pemBody     = "MIIBOGabcSECRETKEYBODYxyz=="
		logDBPass   = "S3cretPW9"
		envDBPass   = "sup3rEnvPW1"
		envToken    = "tok_abcdef1234567890"
	)

	docker1 := &fakeDockerSource{
		summaries: []docker.ContainerSummary{{ID: "c1", Name: "api", State: "running"}},
		details: map[string]docker.ContainerDetail{
			"c1": {
				ID: "c1", Name: "api", Status: "Up 1 minute", State: "running",
				EnvironmentVars: []docker.EnvSummary{
					{Key: "DATABASE_URL", Value: "postgres://appuser:" + envDBPass + "@db.internal:5432/app"},
					{Key: "API_TOKEN", Value: envToken},
				},
			},
		},
		logs: map[string][]docker.LogEntry{
			"c1": {
				{ContainerID: "c1", Line: "Authorization: Bearer " + bearerToken},
				{ContainerID: "c1", Line: "-----BEGIN RSA PRIVATE KEY-----"},
				{ContainerID: "c1", Line: pemBody},
				{ContainerID: "c1", Line: "-----END RSA PRIVATE KEY-----"},
				{ContainerID: "c1", Line: "connecting to postgres://dbuser:" + logDBPass + "@dbhost:5432/appdb"},
			},
		},
	}

	redactor, err := redact.New(nil)
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	c := NewCollector(CollectorConfig{Docker: docker1, Redactor: redactor, Now: fixedNow})
	b := c.Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "docker_container", Target: "api"})

	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	blob := string(raw)

	for _, secret := range []string{bearerToken, pemBody, logDBPass, envDBPass, envToken} {
		if strings.Contains(blob, secret) {
			t.Fatalf("marshalled bundle leaked secret %q:\n%s", secret, blob)
		}
	}

	if !b.Redaction.Applied {
		t.Fatal("Redaction.Applied = false, want true")
	}
	want := []string{redact.RuleAuthHeader, redact.RulePrivateKey, redact.RuleDatabaseURL, redact.RuleEnvValue}
	have := map[string]bool{}
	for _, r := range b.Redaction.Rules {
		have[r] = true
	}
	for _, r := range want {
		if !have[r] {
			t.Fatalf("Redaction.Rules = %v, missing %q", b.Redaction.Rules, r)
		}
	}
}

// --- budgets ---

func TestCollect_EnforcesLineByteAndItemBudgets(t *testing.T) {
	t.Run("line and byte budgets", func(t *testing.T) {
		lines := make([]docker.LogEntry, 0, 10)
		for i := range 10 {
			lines = append(lines, docker.LogEntry{ContainerID: "c1", Line: "log line number " + string(rune('0'+i))})
		}
		docker1 := &fakeDockerSource{
			summaries: []docker.ContainerSummary{{ID: "c1", Name: "api", State: "running"}},
			details:   map[string]docker.ContainerDetail{"c1": {ID: "c1", Name: "api", State: "running"}},
			logs:      map[string][]docker.LogEntry{"c1": lines},
		}
		redactor, _ := redact.New(nil)
		c := NewCollector(CollectorConfig{
			Docker:   docker1,
			Redactor: redactor,
			Now:      fixedNow,
			Budget:   Budget{MaxLogLines: 3, MaxItemBytes: 20, MaxItems: DefaultMaxItems},
		})
		b := c.Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "docker_container", Target: "api"})

		if len(b.Logs) != 1 {
			t.Fatalf("Logs = %d, want 1", len(b.Logs))
		}
		log := b.Logs[0]
		if log.LineCount != 3 {
			t.Fatalf("LineCount = %d, want 3 (MaxLogLines)", log.LineCount)
		}
		if !log.Truncated {
			t.Fatal("Truncated = false, want true (line and byte budgets both exceeded)")
		}
		if len(log.Content) > 20 {
			t.Fatalf("Content len = %d, want <= 20 (MaxItemBytes)", len(log.Content))
		}
		if b.DroppedItems < 7 {
			t.Fatalf("DroppedItems = %d, want >= 7 (10 lines - 3 kept)", b.DroppedItems)
		}
	})

	t.Run("item budget", func(t *testing.T) {
		docker1 := &fakeDockerSource{
			summaries: []docker.ContainerSummary{
				{ID: "c1", Name: "api", State: "running", ComposeProject: "proj"},
				{ID: "c2", Name: "worker-a", State: "running", ComposeProject: "proj"},
				{ID: "c3", Name: "worker-b", State: "running", ComposeProject: "proj"},
				{ID: "c4", Name: "worker-c", State: "running", ComposeProject: "proj"},
			},
			details: map[string]docker.ContainerDetail{"c1": {ID: "c1", Name: "api", State: "running"}},
			logs:    map[string][]docker.LogEntry{"c1": {{ContainerID: "c1", Line: "hello"}}},
		}
		infraSrc := &fakeInfraSource{metrics: availableMetrics()}
		redactor, _ := redact.New(nil)
		c := NewCollector(CollectorConfig{
			Docker:   docker1,
			Infra:    infraSrc,
			Redactor: redactor,
			Now:      fixedNow,
			Budget:   Budget{MaxItems: 2},
		})
		b := c.Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "docker_container", Target: "api"})

		total := len(b.Signals) + len(b.Logs) + len(b.Components) + len(b.RecentChanges) + len(b.Metrics)
		if total > 2 {
			t.Fatalf("total bundle items = %d, want <= MaxItems(2)", total)
		}
		if b.DroppedItems == 0 {
			t.Fatal("DroppedItems = 0, want > 0 (more candidate evidence than MaxItems)")
		}
	})
}

// --- per-source degradation ---

func TestCollect_DegradesPerSourceIntoWarnings(t *testing.T) {
	redactor, _ := redact.New(nil)

	t.Run("nil docker source", func(t *testing.T) {
		c := NewCollector(CollectorConfig{
			Infra: &fakeInfraSource{metrics: availableMetrics()}, Webserver: &fakeWebserverSource{snap: availableWebserver()},
			Redactor: redactor, Now: fixedNow,
		})
		b := c.Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "docker_container", Target: "api"})
		assertWarningContains(t, b, "docker")
		if hasComponentKind(b, "docker_container") || len(b.Logs) != 0 {
			t.Fatalf("docker sections should be empty, got Components=%v Logs=%v", b.Components, b.Logs)
		}
		if len(b.Metrics) == 0 {
			t.Fatal("infra metrics should still be populated when only docker is nil")
		}
	})

	t.Run("docker containers error", func(t *testing.T) {
		c := NewCollector(CollectorConfig{
			Docker:   &fakeDockerSource{containersErr: errors.New("daemon unreachable")},
			Infra:    &fakeInfraSource{metrics: availableMetrics()},
			Redactor: redactor, Now: fixedNow,
		})
		b := c.Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "docker_container", Target: "api"})
		assertWarningContains(t, b, "daemon unreachable")
		if len(b.Metrics) == 0 {
			t.Fatal("infra metrics should still be populated when docker fails")
		}
	})

	t.Run("nil systemd source", func(t *testing.T) {
		c := NewCollector(CollectorConfig{
			Infra: &fakeInfraSource{metrics: availableMetrics()}, Webserver: &fakeWebserverSource{snap: availableWebserver()},
			Redactor: redactor, Now: fixedNow,
		})
		b := c.Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "systemd_unit", Target: "myservice.service"})
		assertWarningContains(t, b, "systemd")
		if hasComponentKind(b, "systemd_unit") || len(b.Logs) != 0 {
			t.Fatalf("systemd sections should be empty, got Components=%v Logs=%v", b.Components, b.Logs)
		}
		if len(b.Metrics) == 0 {
			t.Fatal("infra metrics should still be populated when only systemd is nil")
		}
	})

	t.Run("nil infra source", func(t *testing.T) {
		docker1 := &fakeDockerSource{
			summaries: []docker.ContainerSummary{{ID: "c1", Name: "api", State: "running"}},
			details:   map[string]docker.ContainerDetail{"c1": {ID: "c1", Name: "api", State: "running"}},
		}
		c := NewCollector(CollectorConfig{Docker: docker1, Redactor: redactor, Now: fixedNow})
		b := c.Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "docker_container", Target: "api"})
		assertWarningContains(t, b, "infra")
		if len(b.Metrics) != 0 {
			t.Fatalf("Metrics = %v, want empty when infra is nil", b.Metrics)
		}
		if len(b.Components) == 0 {
			t.Fatal("docker component should still be populated when infra is nil")
		}
	})

	t.Run("nil webserver source", func(t *testing.T) {
		docker1 := &fakeDockerSource{
			summaries: []docker.ContainerSummary{{ID: "c1", Name: "api", State: "running"}},
			details:   map[string]docker.ContainerDetail{"c1": {ID: "c1", Name: "api", State: "running"}},
		}
		c := NewCollector(CollectorConfig{Docker: docker1, Infra: &fakeInfraSource{metrics: availableMetrics()}, Redactor: redactor, Now: fixedNow})
		b := c.Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "docker_container", Target: "api"})
		assertWarningContains(t, b, "webserver")
		if len(b.Components) == 0 {
			t.Fatal("docker component should still be populated when webserver is nil")
		}
	})
}

func assertWarningContains(t *testing.T, b Bundle, substr string) {
	t.Helper()
	for _, w := range b.Warnings {
		if strings.Contains(strings.ToLower(w), strings.ToLower(substr)) {
			return
		}
	}
	t.Fatalf("Warnings = %v, want one containing %q", b.Warnings, substr)
}

func hasComponentKind(b Bundle, kind string) bool {
	for _, c := range b.Components {
		if c.Kind == kind {
			return true
		}
	}
	return false
}

// --- deterministic, unique IDs ---

func TestCollect_ProducesDeterministicUniqueEvidenceIDs(t *testing.T) {
	newCollector := func() *Collector {
		docker1 := &fakeDockerSource{
			summaries: []docker.ContainerSummary{
				{ID: "c1", Name: "api", State: "running", ComposeProject: "proj"},
				{ID: "c2", Name: "worker:1", State: "running", ComposeProject: "proj"},
				{ID: "c3", Name: "worker/1", State: "running", ComposeProject: "proj"},
			},
			details: map[string]docker.ContainerDetail{"c1": {ID: "c1", Name: "api", State: "running", RestartCount: 5}},
			logs:    map[string][]docker.LogEntry{"c1": {{ContainerID: "c1", Line: "hi"}}},
		}
		infraSrc := &fakeInfraSource{metrics: availableMetrics(), oom: []infra.OOMEvent{{At: fixedNow(), PID: 42, Process: "api"}}}
		redactor, _ := redact.New(nil)
		return NewCollector(CollectorConfig{Docker: docker1, Infra: infraSrc, Redactor: redactor, Now: fixedNow})
	}

	b1 := newCollector().Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "docker_container", Target: "api"})
	b2 := newCollector().Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "docker_container", Target: "api"})

	ids1, ids2 := b1.EvidenceIDs(), b2.EvidenceIDs()
	if len(ids1) == 0 {
		t.Fatal("EvidenceIDs is empty, want a populated bundle")
	}
	if strings.Join(ids1, ",") != strings.Join(ids2, ",") {
		t.Fatalf("EvidenceIDs not deterministic:\n%v\n%v", ids1, ids2)
	}

	seen := map[string]bool{}
	for _, id := range ids1 {
		if seen[id] {
			t.Fatalf("duplicate evidence id %q in %v", id, ids1)
		}
		seen[id] = true
	}

	if !seen["cmp_docker_worker_1"] || !seen["cmp_docker_worker_1_2"] {
		t.Fatalf("expected colliding sanitized names to get suffixed ids, got %v", ids1)
	}
}

// --- systemd target ---

func TestCollect_SystemdTargetCollectsUnitStateAndLogs(t *testing.T) {
	systemdSrc := &fakeSystemdSource{
		unit: systemd.UnitDetail{
			Unit:         systemd.Unit{Name: "myservice.service", ActiveState: "failed", SubState: "core-dump"},
			FragmentPath: "/etc/systemd/system/myservice.service",
		},
		logs: "line one\nline two\nline three",
	}
	redactor, _ := redact.New(nil)
	c := NewCollector(CollectorConfig{Systemd: systemdSrc, Redactor: redactor, Now: fixedNow})

	b := c.Collect(context.Background(), Target{IncidentID: "inc_1", MonitorKind: "systemd_unit", Target: "myservice.service"})

	if b.Service.Status != "down" {
		t.Fatalf("Service.Status = %q, want down (ActiveState=failed)", b.Service.Status)
	}
	if len(b.Components) != 1 {
		t.Fatalf("Components = %d, want 1", len(b.Components))
	}
	comp := b.Components[0]
	if comp.Kind != "systemd_unit" || comp.Name != "myservice.service" || comp.State != "failed" {
		t.Fatalf("component = %+v, want systemd_unit/myservice.service/failed", comp)
	}
	if len(b.Logs) != 1 {
		t.Fatalf("Logs = %d, want 1", len(b.Logs))
	}
	if b.Logs[0].Source != "systemd:myservice.service" {
		t.Fatalf("log source = %q, want systemd:myservice.service", b.Logs[0].Source)
	}
	if !strings.Contains(b.Logs[0].Content, "line two") {
		t.Fatalf("log content = %q, want it to contain seeded lines", b.Logs[0].Content)
	}
}
