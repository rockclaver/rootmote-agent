package alerts

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/notifications"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

type fakeMetrics struct {
	samples []infra.HostMetrics
	i       int
}

func (f *fakeMetrics) Sample(context.Context) infra.HostMetrics {
	if f.i >= len(f.samples) {
		return f.samples[len(f.samples)-1]
	}
	s := f.samples[f.i]
	f.i++
	return s
}

type fakeUnits struct {
	units [][]systemd.Unit
	i     int
}

func (f *fakeUnits) Status(context.Context) systemd.Status {
	return systemd.Status{Available: true}
}

func (f *fakeUnits) List(context.Context) ([]systemd.Unit, error) {
	if len(f.units) == 0 {
		return nil, nil
	}
	if f.i >= len(f.units) {
		return f.units[len(f.units)-1], nil
	}
	u := f.units[f.i]
	f.i++
	return u, nil
}

type captureSink struct {
	got []notifications.Notification
}

func (s *captureSink) Publish(_ context.Context, n notifications.Notification) error {
	s.got = append(s.got, n)
	return nil
}

func newTestManager(t *testing.T, samples []infra.HostMetrics, units [][]systemd.Unit) (*Manager, *captureSink, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	m, err := New(Config{
		Store:               st,
		Metrics:             &fakeMetrics{samples: samples},
		Systemd:             &fakeUnits{units: units},
		Sink:                sink,
		Now:                 func() time.Time { return time.Unix(1700000000, 0) },
		LoadConsecutiveHits: 2,
		UnitConsecutiveHits: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, sink, st
}

func sample(disk, load float64) infra.HostMetrics {
	return infra.HostMetrics{
		Timestamp: time.Unix(1700000000, 0),
		Load: infra.LoadMetric{
			MetricReason: infra.MetricReason{Available: true},
			One:          load,
		},
		Disks: []infra.DiskMetric{{
			Mountpoint: "/",
			Available:  true,
			Percent:    disk,
		}},
	}
}

func TestAlertEngine_DefaultRulesEnabledAndPersistedConfig(t *testing.T) {
	m, _, st := newTestManager(t, []infra.HostMetrics{sample(1, 1)}, nil)
	defer st.Close()

	rules, err := m.Config(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("default rule count=%d", len(rules))
	}
	for _, r := range rules {
		if !r.Enabled {
			t.Fatalf("default %s disabled", r.Kind)
		}
	}
	if _, err := m.SetConfig(context.Background(), store.InfraAlertRule{
		ServerID:  ServerLocal,
		Kind:      RuleDiskUsage,
		Enabled:   false,
		Threshold: 80,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAlertEngine_ConfigPersistsAcrossRestart(t *testing.T) {
	db := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{Store: st, Metrics: &fakeMetrics{samples: []infra.HostMetrics{sample(1, 1)}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetConfig(context.Background(), store.InfraAlertRule{
		ServerID:  ServerLocal,
		Kind:      RuleLoadSustained,
		Enabled:   false,
		Threshold: 2.5,
	}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	st2, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	got, err := st2.ListInfraAlertRules(ServerLocal)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Kind == RuleLoadSustained && (r.Enabled || r.Threshold != 2.5) {
			t.Fatalf("persisted rule mismatch: %+v", r)
		}
	}
}

func TestAlertEngine_DiskThresholdDedupeHysteresisAndClear(t *testing.T) {
	m, sink, st := newTestManager(t, []infra.HostMetrics{
		sample(91, 1),
		sample(92, 1),
		sample(88, 1),
		sample(84, 1),
	}, nil)
	defer st.Close()

	for range 4 {
		m.Evaluate(context.Background())
	}
	if len(sink.got) != 2 {
		t.Fatalf("notifications=%d want fire+clear: %+v", len(sink.got), sink.got)
	}
	if sink.got[0].Severity != "warning" || sink.got[1].Severity != "resolved" {
		t.Fatalf("unexpected severities: %+v", sink.got)
	}
}

func TestAlertEngine_LoadRequiresSustainedSamplesAndClear(t *testing.T) {
	m, sink, st := newTestManager(t, []infra.HostMetrics{
		sample(1, 4.2),
		sample(1, 4.3),
		sample(1, 4.4),
		sample(1, 3.2),
	}, nil)
	defer st.Close()

	for range 4 {
		m.Evaluate(context.Background())
	}
	if len(sink.got) != 2 {
		t.Fatalf("notifications=%d want sustained fire+clear", len(sink.got))
	}
	if sink.got[0].Data["rule"] != RuleLoadSustained {
		t.Fatalf("wrong rule: %+v", sink.got[0])
	}
}

func TestAlertEngine_LoadSamplesMustBeConsecutiveBeforeEntry(t *testing.T) {
	m, sink, st := newTestManager(t, []infra.HostMetrics{
		sample(1, 4.2),
		sample(1, 3.9),
		sample(1, 4.2),
	}, nil)
	defer st.Close()

	for range 3 {
		m.Evaluate(context.Background())
	}
	if len(sink.got) != 0 {
		t.Fatalf("non-consecutive load samples emitted: %+v", sink.got)
	}
}

func TestAlertEngine_UnitFailedRequiresConsecutiveSamplesAndClears(t *testing.T) {
	m, sink, st := newTestManager(
		t,
		[]infra.HostMetrics{sample(1, 1), sample(1, 1), sample(1, 1), sample(1, 1)},
		[][]systemd.Unit{
			{{Name: "api.service", ActiveState: "failed", SubState: "failed"}},
			{{Name: "api.service", ActiveState: "failed", SubState: "failed"}},
			{{Name: "api.service", ActiveState: "active", SubState: "running"}},
			{{Name: "api.service", ActiveState: "active", SubState: "running"}},
		},
	)
	defer st.Close()

	for range 4 {
		m.Evaluate(context.Background())
	}
	if len(sink.got) != 2 {
		t.Fatalf("notifications=%d want unit fire+clear: %+v", len(sink.got), sink.got)
	}
	if sink.got[0].Data["target"] != "api.service" || sink.got[1].Severity != "resolved" {
		t.Fatalf("unexpected unit notifications: %+v", sink.got)
	}
	if _, ok := sink.got[0].Data["value"]; ok {
		t.Fatalf("unit alert should omit numeric value: %+v", sink.got[0].Data)
	}
	if _, err := json.Marshal(sink.got[0]); err != nil {
		t.Fatalf("unit alert must be JSON-safe: %v", err)
	}
	if _, err := json.Marshal(sink.got[1]); err != nil {
		t.Fatalf("unit clear must be JSON-safe: %v", err)
	}
}

// TestAlertEngine_UnitFlapBelowThresholdFiresNothing reproduces the flood a
// crash-looping unit used to cause: caught failed on one poll and healthy
// again on the next, faster than it can satisfy the consecutive-sample
// debounce. No enter/clear pair should ever reach the sink.
func TestAlertEngine_UnitFlapBelowThresholdFiresNothing(t *testing.T) {
	m, sink, st := newTestManager(
		t,
		[]infra.HostMetrics{sample(1, 1), sample(1, 1), sample(1, 1), sample(1, 1)},
		[][]systemd.Unit{
			{{Name: "api.service", ActiveState: "failed", SubState: "failed"}},
			{{Name: "api.service", ActiveState: "active", SubState: "running"}},
			{{Name: "api.service", ActiveState: "failed", SubState: "failed"}},
			{{Name: "api.service", ActiveState: "active", SubState: "running"}},
		},
	)
	defer st.Close()

	for range 4 {
		m.Evaluate(context.Background())
	}
	if len(sink.got) != 0 {
		t.Fatalf("flapping unit below debounce threshold emitted: %+v", sink.got)
	}
}

// TestAlertEngine_UnitFlapAfterFiringDoesNotClearPrematurely covers the
// symmetric case: once an alert is firing, a single healthy poll must not
// clear it outright -- that would immediately re-fire on the next failed
// poll and double the notification count. The recovery counter must reset
// when the unit dips back to failed before reaching the clear threshold.
func TestAlertEngine_UnitFlapAfterFiringDoesNotClearPrematurely(t *testing.T) {
	m, sink, st := newTestManager(
		t,
		[]infra.HostMetrics{sample(1, 1), sample(1, 1), sample(1, 1), sample(1, 1)},
		[][]systemd.Unit{
			{{Name: "api.service", ActiveState: "failed", SubState: "failed"}},
			{{Name: "api.service", ActiveState: "failed", SubState: "failed"}},
			{{Name: "api.service", ActiveState: "active", SubState: "running"}},
			{{Name: "api.service", ActiveState: "failed", SubState: "failed"}},
		},
	)
	defer st.Close()

	for range 4 {
		m.Evaluate(context.Background())
	}
	if len(sink.got) != 1 {
		t.Fatalf("notifications=%d want exactly the initial fire: %+v", len(sink.got), sink.got)
	}
	active := m.ActiveAlerts()
	if len(active) != 1 || active[0].Target != "api.service" {
		t.Fatalf("alert should still be active after the single healthy blip: %+v", active)
	}
}

func TestAlertEngine_DisabledRuleSuppressesNotification(t *testing.T) {
	m, sink, st := newTestManager(t, []infra.HostMetrics{sample(95, 1)}, nil)
	defer st.Close()
	if _, err := m.SetConfig(context.Background(), store.InfraAlertRule{
		ServerID:  ServerLocal,
		Kind:      RuleDiskUsage,
		Enabled:   false,
		Threshold: 90,
	}); err != nil {
		t.Fatal(err)
	}
	m.Evaluate(context.Background())
	if len(sink.got) != 0 {
		t.Fatalf("disabled rule emitted: %+v", sink.got)
	}
}
