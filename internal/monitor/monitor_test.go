package monitor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/watchtower"
)

// --- fakes ---------------------------------------------------------------

type fakeStateStore struct {
	states map[string]store.MonitorState
}

func newFakeStateStore() *fakeStateStore {
	return &fakeStateStore{states: map[string]store.MonitorState{}}
}

func (f *fakeStateStore) PutMonitorState(s store.MonitorState) error {
	f.states[s.Key] = s
	return nil
}

func (f *fakeStateStore) ListMonitorStates() ([]store.MonitorState, error) {
	out := make([]store.MonitorState, 0, len(f.states))
	for _, s := range f.states {
		out = append(out, s)
	}
	return out, nil
}

// fakeSender records enqueued events; FlushQueue is a no-op (the real
// offline-queue behavior is covered in the watchtower package's AC8 tests).
type fakeSender struct {
	events     []watchtower.MonitorEvent
	enqueueErr error
}

func (f *fakeSender) EnqueueMonitorEvent(ev watchtower.MonitorEvent) error {
	if f.enqueueErr != nil {
		return f.enqueueErr
	}
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeSender) FlushQueue(context.Context) error { return nil }

func (f *fakeSender) countTo(to string) int {
	n := 0
	for _, e := range f.events {
		if e.ToState == to {
			n++
		}
	}
	return n
}

type fakeInfra struct {
	metrics infra.HostMetrics
	oom     []infra.OOMEvent
}

func (f *fakeInfra) Sample(context.Context) infra.HostMetrics { return f.metrics }
func (f *fakeInfra) OOMEvents(context.Context, time.Time) ([]infra.OOMEvent, error) {
	return f.oom, nil
}

type fakeDocker struct {
	summaries []docker.ContainerSummary
	details   map[string]docker.ContainerDetail
}

func (f *fakeDocker) Containers(context.Context) ([]docker.ContainerSummary, error) {
	return f.summaries, nil
}
func (f *fakeDocker) Container(_ context.Context, id string) (docker.ContainerDetail, error) {
	return f.details[id], nil
}

type fakeSystemd struct {
	units []systemd.Unit
}

func (f *fakeSystemd) Status(context.Context) systemd.Status        { return systemd.Status{Available: true} }
func (f *fakeSystemd) List(context.Context) ([]systemd.Unit, error) { return f.units, nil }

// harness builds a Manager driven by a mutable clock.
type harness struct {
	m      *Manager
	sender *fakeSender
	infra  *fakeInfra
	docker *fakeDocker
	now    time.Time
}

func newHarness(t *testing.T, withDocker, withSystemd bool) *harness {
	t.Helper()
	h := &harness{
		sender: &fakeSender{},
		infra:  &fakeInfra{},
		docker: &fakeDocker{details: map[string]docker.ContainerDetail{}},
		now:    time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC),
	}
	cfg := Config{
		Infra:  h.infra,
		Store:  newFakeStateStore(),
		Client: h.sender,
		Now:    func() time.Time { return h.now },
		Logf:   t.Logf,
	}
	if withDocker {
		cfg.Docker = h.docker
	}
	if withSystemd {
		cfg.Systemd = &fakeSystemd{}
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("monitor.New: %v", err)
	}
	h.m = m
	return h
}

func (h *harness) tick() {
	h.m.Evaluate(context.Background())
	h.now = h.now.Add(30 * time.Second)
}

func diskSample(percent float64) infra.HostMetrics {
	return infra.HostMetrics{
		Disks:  []infra.DiskMetric{{Mountpoint: "/", Available: true, Percent: percent}},
		Memory: infra.MemoryMetric{Percent: 10},
	}
}

// --- AC1: state machine + transient-failure guard ------------------------

func TestStateMachine_TransientFailureNeverFires(t *testing.T) {
	h := newHarness(t, false, false)
	// One failing check (disk 95%, fire threshold 90, failure_threshold 3)
	// then a success: must go pending -> healthy with NO event.
	h.infra.metrics = diskSample(95)
	h.tick()
	h.infra.metrics = diskSample(70)
	h.tick()
	if got := len(h.sender.events); got != 0 {
		t.Fatalf("events after transient failure = %d, want 0: %+v", got, h.sender.events)
	}
}

func TestStateMachine_FullFiringThenResolvedPath(t *testing.T) {
	h := newHarness(t, false, false)
	// 3 consecutive failing checks -> exactly one firing event.
	h.infra.metrics = diskSample(95)
	h.tick() // pending (fail 1)
	h.tick() // pending (fail 2)
	h.tick() // firing (fail 3) -> event
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("firing events = %d, want 1", got)
	}
	if got := h.sender.countTo("resolved"); got != 0 {
		t.Fatalf("resolved events before recovery = %d, want 0", got)
	}
	// 3 consecutive successes below recoveryValue (85) -> exactly one resolved.
	h.infra.metrics = diskSample(70)
	h.tick() // recovering (ok 1)
	h.tick() // recovering (ok 2)
	h.tick() // resolved (ok 3) -> event
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("firing events after full path = %d, want 1", got)
	}
	if got := h.sender.countTo("resolved"); got != 1 {
		t.Fatalf("resolved events = %d, want 1", got)
	}
	// The firing event carries the first-failure timestamp, not the firing time.
	var fired watchtower.MonitorEvent
	for _, e := range h.sender.events {
		if e.ToState == "firing" {
			fired = e
		}
	}
	wantFirstFailure := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	if !fired.FirstFailureAt.Equal(wantFirstFailure) {
		t.Fatalf("firing FirstFailureAt = %s, want %s", fired.FirstFailureAt, wantFirstFailure)
	}
}

func TestStateMachine_CooldownSuppressesImmediateRefire(t *testing.T) {
	h := newHarness(t, false, false)
	h.infra.metrics = diskSample(95)
	h.tick()
	h.tick()
	h.tick()
	h.infra.metrics = diskSample(70)
	h.tick()
	h.tick()
	h.tick()

	h.infra.metrics = diskSample(95)
	for range 4 {
		h.tick()
	}
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("firing events during cooldown = %d, want original firing only", got)
	}

	h.now = h.now.Add(5 * time.Minute)
	h.tick()
	h.tick()
	h.tick()
	if got := h.sender.countTo("firing"); got != 2 {
		t.Fatalf("firing events after cooldown = %d, want 2", got)
	}
}

func TestStateMachine_EnqueueFailureDoesNotCommitFiring(t *testing.T) {
	h := newHarness(t, false, false)
	h.infra.metrics = diskSample(95)
	h.tick()
	h.tick()
	h.sender.enqueueErr = errors.New("disk full")
	h.tick()
	if got := h.sender.countTo("firing"); got != 0 {
		t.Fatalf("firing events after enqueue failure = %d, want 0", got)
	}
	if state := State(h.m.states[key(KindDiskCapacity, "/")].State); state != StatePending {
		t.Fatalf("state after enqueue failure = %s, want pending", state)
	}
	h.sender.enqueueErr = nil
	h.tick()
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("firing events after enqueue recovery = %d, want 1", got)
	}
	if h.sender.events[0].EventID == "" {
		t.Fatal("firing event has no stable event id")
	}
}

// --- AC2: disk hysteresis ------------------------------------------------

func TestDiskMonitor_HysteresisDoesNotFlap(t *testing.T) {
	h := newHarness(t, false, false)

	// Fire at 92 (>=90) after 3 checks.
	h.infra.metrics = diskSample(92)
	h.tick()
	h.tick()
	h.tick()
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("firing events = %d, want 1", got)
	}
	// Hover in the 85-90 band: 87% must NOT resolve (stays firing, no flap).
	h.infra.metrics = diskSample(87)
	for range 5 {
		h.tick()
	}
	if got := h.sender.countTo("resolved"); got != 0 {
		t.Fatalf("resolved events while hovering at 87%% = %d, want 0 (no flap)", got)
	}
	// Drop below recoveryValue (85): resolves after recovery_threshold.
	h.infra.metrics = diskSample(80)
	h.tick()
	h.tick()
	h.tick()
	if got := h.sender.countTo("resolved"); got != 1 {
		t.Fatalf("resolved events after dropping below 85%% = %d, want 1", got)
	}
	// Exactly one firing episode total.
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("firing events total = %d, want 1", got)
	}
}

func TestStateMachine_FirstFailureSurvivesManagerRestart(t *testing.T) {
	stateStore := newFakeStateStore()
	infraSource := &fakeInfra{metrics: diskSample(95)}
	firstSender := &fakeSender{}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	first, err := New(Config{
		Infra: infraSource, Store: stateStore, Client: firstSender,
		Now: func() time.Time { return now }, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	first.Evaluate(context.Background()) // pending, fail 1 persisted

	now = now.Add(30 * time.Second)
	afterRestart := &fakeSender{}
	second, err := New(Config{
		Infra: infraSource, Store: stateStore, Client: afterRestart,
		Now: func() time.Time { return now }, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	second.Evaluate(context.Background()) // fail 2
	now = now.Add(30 * time.Second)
	second.Evaluate(context.Background()) // fail 3 -> firing

	if len(afterRestart.events) != 1 {
		t.Fatalf("events after restart = %d, want one firing", len(afterRestart.events))
	}
	want := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	if !afterRestart.events[0].FirstFailureAt.Equal(want) {
		t.Fatalf("FirstFailureAt after restart = %s, want %s", afterRestart.events[0].FirstFailureAt, want)
	}
}

// --- AC3: docker stopped + crash-loop ------------------------------------

func TestDockerMonitor_StoppedContainerFiresOnce(t *testing.T) {
	h := newHarness(t, true, false)
	h.docker.summaries = []docker.ContainerSummary{{ID: "c1", Name: "api", State: "exited"}}
	// failure_threshold for docker default is 2.
	h.tick() // pending
	h.tick() // firing -> one event
	// Keep reporting it stopped; must not emit more firing events.
	for range 4 {
		h.tick()
	}
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("firing events for stopped container = %d, want exactly 1", got)
	}
}

func TestDockerMonitor_CrashLoopIsOneIncident(t *testing.T) {
	h := newHarness(t, true, false)
	h.docker.summaries = []docker.ContainerSummary{{ID: "c1", Name: "api", State: "running"}}
	// Baseline restart count.
	h.docker.details["c1"] = docker.ContainerDetail{ID: "c1", RestartCount: 0}
	h.tick() // healthy (no restarts yet)
	// Jump by 3 restarts inside the window -> crash-loop failing.
	h.docker.details["c1"] = docker.ContainerDetail{ID: "c1", RestartCount: 3}
	h.tick() // pending (crashloop fail 1)
	h.tick() // firing (crashloop fail 2) -> event
	for range 3 {
		h.tick()
	}
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("crash-loop firing events = %d, want 1 (one incident, not per-restart)", got)
	}
	// The firing event summary identifies it as a crash loop.
	var e watchtower.MonitorEvent
	for _, ev := range h.sender.events {
		if ev.ToState == "firing" {
			e = ev
		}
	}
	if want := "crash-looping"; !strings.Contains(e.Summary, want) {
		t.Fatalf("crash-loop summary = %q, want it to mention %q", e.Summary, want)
	}
}

// --- AC4: OOM attribution ------------------------------------------------

func TestMemoryMonitor_OOMAttribution(t *testing.T) {
	h := newHarness(t, false, false)
	// Memory percent below threshold, but an OOM kill forces failing and
	// names the affected process.
	h.infra.metrics = infra.HostMetrics{Memory: infra.MemoryMetric{Percent: 40}}
	h.infra.oom = []infra.OOMEvent{{
		At: h.now, PID: 1234, Process: "postgres", ContainerID: "0123456789ab",
	}}
	// memory failure_threshold default is 3.
	h.tick()
	h.tick()
	h.tick()
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("memory firing events = %d, want 1", got)
	}
	var e watchtower.MonitorEvent
	for _, ev := range h.sender.events {
		if ev.ToState == "firing" && ev.MonitorKind == string(KindMemoryPressure) {
			e = ev
		}
	}
	if e.Attributes["oomProcess"] != "postgres" {
		t.Fatalf("OOM attribution = %q, want postgres in event attributes: %+v", e.Attributes["oomProcess"], e.Attributes)
	}
	if e.Attributes["oomContainer"] != "0123456789ab" {
		t.Fatalf("OOM container attribution = %q, want 0123456789ab: %+v", e.Attributes["oomContainer"], e.Attributes)
	}
}

// --- memory pressure combines available memory + swap --------------------

func TestMemoryMonitor_HighSwapPressureFires(t *testing.T) {
	h := newHarness(t, false, false)
	h.infra.metrics = infra.HostMetrics{
		Memory: infra.MemoryMetric{Percent: 40},
		Swap:   infra.MemoryMetric{Percent: 95},
	}
	h.tick()
	h.tick()
	h.tick()
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("memory firing events from high swap = %d, want 1", got)
	}
	var event watchtower.MonitorEvent
	for _, ev := range h.sender.events {
		if ev.MonitorKind == string(KindMemoryPressure) && ev.ToState == "firing" {
			event = ev
		}
	}
	if event.Attributes["swap_percent"] != "95.0" {
		t.Fatalf("swap evidence = %+v, want swap_percent=95.0", event.Attributes)
	}
}

// --- AC7 (agent side): disabling a monitor stops evaluation --------------

func TestSyncedDisable_StopsEvaluation(t *testing.T) {
	h := newHarness(t, false, false)
	// Relay syncs the disk "/" monitor as disabled.
	h.m.SetSyncedDefinitions([]Definition{{
		Kind: KindDiskCapacity, Target: "/", Enabled: false, Severity: "critical",
		FailureThreshold: 3, RecoveryThreshold: 3, CooldownSeconds: 300, FiringThreshold: 90, RecoveryValue: 85,
	}})
	if state := State(h.m.states[key(KindDiskCapacity, "/")].State); state != StateMuted {
		t.Fatalf("state after disable = %s, want muted", state)
	}
	h.infra.metrics = diskSample(99) // would fire if enabled
	for range 5 {
		h.tick()
	}
	if got := len(h.sender.events); got != 0 {
		t.Fatalf("events while disabled = %d, want 0", got)
	}
}

func TestSyncedWildcardDisable_StopsDynamicTargets(t *testing.T) {
	defs := NewDefinitionSet(DefaultDefinitions())
	defs.SetSynced([]Definition{{
		Kind: KindDockerContainer, Target: wildcardTarget, Enabled: false,
	}})
	if _, enabled := defs.Resolve(KindDockerContainer, "api"); enabled {
		t.Fatal("synced wildcard disable did not stop docker target api")
	}
}
