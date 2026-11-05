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

type testClock struct{ t time.Time }

func (c *testClock) Now() time.Time { return c.t }

func newTestManager(t *testing.T, samples []infra.HostMetrics, units [][]systemd.Unit) (*Manager, *captureSink, *store.Store) {
	t.Helper()
	return newTestManagerWithClock(t, samples, units, &testClock{t: time.Unix(1700000000, 0)})
}

// newTestManagerWithClock runs on a 2-CPU host whose load alert fires and
// clears after two consecutive 30s samples, so the default per-core
// threshold of 2 fires at a 5-minute load of 4 and clears at 3.
func newTestManagerWithClock(t *testing.T, samples []infra.HostMetrics, units [][]systemd.Unit, clock *testClock) (*Manager, *captureSink, *store.Store) {
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
		Now:                 clock.Now,
		Cadence:             30 * time.Second,
		CPUCount:            2,
		LoadFiringFor:       time.Minute,
		LoadRecoveryFor:     time.Minute,
		UnitConsecutiveHits: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, sink, st
}

// step runs n evaluation cycles, advancing clock by one cadence after each.
func step(m *Manager, clock *testClock, n int) {
	for range n {
		m.Evaluate(context.Background())
		clock.t = clock.t.Add(30 * time.Second)
	}
}

func sample(disk, load5 float64) infra.HostMetrics {
	return infra.HostMetrics{
		Timestamp: time.Unix(1700000000, 0),
		Load: infra.LoadMetric{
			MetricReason: infra.MetricReason{Available: true},
			Five:         load5,
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
		sample(1, 2.9),
		sample(1, 2.8),
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
	if v, _ := sink.got[0].Data["value"].(float64); v != 2.15 {
		t.Fatalf("value should be load per core (4.3/2), got %+v", sink.got[0].Data["value"])
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

// TestAlertEngine_LoadIsNormalizedPerCore: a load that saturates a small
// box is routine on a large one. 6.0 on 8 CPUs is 0.75 per core.
func TestAlertEngine_LoadIsNormalizedPerCore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sink := &captureSink{}
	m, err := New(Config{
		Store:    st,
		Metrics:  &fakeMetrics{samples: []infra.HostMetrics{sample(1, 6)}},
		Sink:     sink,
		CPUCount: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 60 {
		m.Evaluate(context.Background())
	}
	if len(sink.got) != 0 {
		t.Fatalf("load 6 on 8 CPUs alerted: %+v", sink.got)
	}
}

// TestAlertEngine_LoadHoveringAtThresholdNotifiesOnce reproduces the push
// flood: load sitting around the threshold used to fire, clear on the next
// dip, and fire again a minute later. Dips shorter than the recovery hold
// must keep the original episode open.
func TestAlertEngine_LoadHoveringAtThresholdNotifiesOnce(t *testing.T) {
	samples := []infra.HostMetrics{sample(1, 4.2), sample(1, 4.2)}
	for range 30 {
		samples = append(samples, sample(1, 2.5), sample(1, 4.4))
	}
	clock := &testClock{t: time.Unix(1700000000, 0)}
	m, sink, st := newTestManagerWithClock(t, samples, nil, clock)
	defer st.Close()

	step(m, clock, len(samples))
	if len(sink.got) != 1 {
		t.Fatalf("notifications=%d want a single fire: %+v", len(sink.got), sink.got)
	}
	if active := m.ActiveAlerts(); len(active) != 1 {
		t.Fatalf("alert should stay active through short dips: %+v", active)
	}
}

// TestAlertEngine_RefireInsideQuietWindowReopensSilently: once an alert has
// cleared, coming back within RenotifyAfter is the same problem, not a new
// emergency. It reappears in the inbox under its original episode without
// a push; after the window a fresh episode notifies again.
func TestAlertEngine_RefireInsideQuietWindowReopensSilently(t *testing.T) {
	high, low := sample(1, 4.5), sample(1, 2)
	samples := []infra.HostMetrics{high, high, low, low} // fire, clear
	samples = append(samples, high, high, low, low)      // back within minutes
	samples = append(samples, high, high)                // back after the window
	clock := &testClock{t: time.Unix(1700000000, 0)}
	m, sink, st := newTestManagerWithClock(t, samples, nil, clock)
	defer st.Close()

	step(m, clock, 4)
	firstFiredAt := sink.got[0].Data["fired_at"]
	step(m, clock, 2)
	if len(sink.got) != 2 {
		t.Fatalf("re-fire inside quiet window notified: %+v", sink.got)
	}
	active := m.ActiveAlerts()
	if len(active) != 1 || active[0].FiredAt.Unix() != firstFiredAt {
		t.Fatalf("reopened alert should keep its original episode: %+v", active)
	}
	step(m, clock, 2)
	clock.t = clock.t.Add(2 * time.Hour)
	step(m, clock, 2)
	fires := 0
	for _, n := range sink.got {
		if n.Data["clear"] == false {
			fires++
		}
	}
	if fires != 2 {
		t.Fatalf("fire notifications=%d want 2 (original + after window): %+v", fires, sink.got)
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

// One condition, one push: once the monitor engine owns disk_usage the legacy
// manager must not publish it, yet the episode stays visible in the inbox
// feed and load_sustained (not owned) still notifies.
func TestAlertEngine_MonitorOwnedRuleDoesNotPushButStaysActive(t *testing.T) {
	m, sink, st := newTestManager(t, []infra.HostMetrics{
		sample(95, 1),
		sample(95, 8),
		sample(95, 8),
	}, nil)
	defer st.Close()
	owned := true
	m.monitorOwned = func(rule string) bool { return owned && rule == RuleDiskUsage }

	for range 3 {
		m.Evaluate(context.Background())
	}
	for _, n := range sink.got {
		if n.Data["rule"] == RuleDiskUsage {
			t.Fatalf("legacy disk alert pushed while monitor engine owns it: %+v", n)
		}
	}
	if len(sink.got) != 1 || sink.got[0].Data["rule"] != RuleLoadSustained {
		t.Fatalf("want exactly the unowned load alert, got %+v", sink.got)
	}
	active := m.ActiveAlerts()
	var disk bool
	for _, a := range active {
		if a.RuleKind == RuleDiskUsage {
			disk = true
		}
	}
	if !disk {
		t.Fatalf("owned disk alert must stay in the inbox feed: %+v", active)
	}
}

func TestAlertEngine_UnownedDiskRulePushesWhenMonitorNotRunning(t *testing.T) {
	m, sink, st := newTestManager(t, []infra.HostMetrics{sample(95, 1)}, nil)
	defer st.Close()
	m.monitorOwned = func(string) bool { return false }
	m.Evaluate(context.Background())
	if len(sink.got) != 1 || sink.got[0].Data["rule"] != RuleDiskUsage {
		t.Fatalf("legacy disk alert must push when no monitor engine runs: %+v", sink.got)
	}
}

func TestAlertEngine_OneshotAndTransientUnitsDoNotAlert(t *testing.T) {
	failed := func(name, typ string) systemd.Unit {
		return systemd.Unit{Name: name, ActiveState: "failed", SubState: "failed", Type: typ}
	}
	m, sink, st := newTestManager(t,
		[]infra.HostMetrics{sample(1, 1)},
		[][]systemd.Unit{{
			failed("backup.service", "oneshot"),
			failed("run-r42.service", ""),
			failed("session-3.scope", ""),
			failed("api.service", "simple"),
		}},
	)
	defer st.Close()
	for range 3 {
		m.Evaluate(context.Background())
	}
	if len(sink.got) != 1 || sink.got[0].Data["target"] != "api.service" {
		t.Fatalf("only the long-running service may alert: %+v", sink.got)
	}
}
