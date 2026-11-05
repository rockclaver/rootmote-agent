package monitor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakePM2 struct {
	apps  map[string][]PM2App
	errs  map[string]error
	calls []string
}

func (f *fakePM2) Apps(_ context.Context, user string) ([]PM2App, error) {
	f.calls = append(f.calls, user)
	if err := f.errs[user]; err != nil {
		return nil, err
	}
	return f.apps[user], nil
}

type pm2Harness struct {
	*harness
	pm2 *fakePM2
}

const pm2Target = "deploy/web"

func newPM2Harness(t *testing.T) *pm2Harness {
	t.Helper()
	h := &harness{
		sender: &fakeSender{},
		infra:  &fakeInfra{metrics: diskSample(10)},
		now:    time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC),
	}
	pm2 := &fakePM2{apps: map[string][]PM2App{}, errs: map[string]error{}}
	m, err := New(Config{
		Infra:  h.infra,
		PM2:    pm2,
		Store:  newFakeStateStore(),
		Client: h.sender,
		Now:    func() time.Time { return h.now },
		Logf:   t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.m = m
	m.SetSyncedDefinitions([]Definition{{
		Kind: KindPM2App, Target: pm2Target, Enabled: true, Severity: "critical", EvaluationLocation: "agent",
		FailureThreshold: 2, RecoveryThreshold: 2, CooldownSeconds: 300,
	}})
	return &pm2Harness{harness: h, pm2: pm2}
}

func (h *pm2Harness) set(status string, restarts int) {
	h.pm2.apps["deploy"] = []PM2App{{Name: "web", Status: status, Restarts: restarts}}
}

func TestPM2App_StoppedFiresOnceAndRecoversAfterSixtySeconds(t *testing.T) {
	h := newPM2Harness(t)
	h.set("online", 0)
	h.tick()
	h.set("stopped", 0)
	h.tick() // pending
	if h.sender.countTo("firing") != 0 {
		t.Fatal("one failing tick must not fire")
	}
	h.tick() // firing
	for range 3 {
		h.tick()
	}
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("firing events = %d, want 1", got)
	}
	e := h.sender.events[0]
	if e.MonitorKind != "pm2_app" || e.Target != pm2Target || e.Severity != "critical" || !strings.Contains(e.Summary, "is stopped") {
		t.Fatalf("event = %+v", e)
	}

	h.set("online", 0)
	h.tick() // recovering
	if h.sender.countTo("resolved") != 0 {
		t.Fatal("a single online tick must not resolve")
	}
	h.tick() // 60s online
	h.tick()
	if got := h.sender.countTo("resolved"); got != 1 {
		t.Fatalf("resolved events = %d, want 1", got)
	}
}

func TestPM2App_ErroredAndMissingFire(t *testing.T) {
	for name, apps := range map[string][]PM2App{
		"errored": {{Name: "web", Status: "errored"}},
		"missing": {{Name: "other", Status: "online"}},
		"no apps": nil,
	} {
		h := newPM2Harness(t)
		h.pm2.apps["deploy"] = apps
		for range 3 {
			h.tick()
		}
		if got := h.sender.countTo("firing"); got != 1 {
			t.Errorf("%s: firing events = %d, want 1", name, got)
		}
	}
}

func TestPM2App_RestartLoopFiresAndRecoversWhenCountIsStable(t *testing.T) {
	h := newPM2Harness(t)
	h.set("online", 5)
	h.tick() // baseline
	h.set("online", 6)
	h.tick()
	h.set("online", 7)
	h.tick()
	if h.sender.countTo("firing") != 0 {
		t.Fatal("two restarts must not count as a loop")
	}
	h.set("online", 8) // third restart inside 5 minutes
	h.tick()           // failing 1 (pending)
	h.tick()           // failing 2 (firing)
	if got := h.sender.countTo("firing"); got != 1 {
		t.Fatalf("firing events = %d, want 1", got)
	}
	if e := h.sender.events[0]; !strings.Contains(e.Summary, "keeps restarting") || e.Attributes["restarts"] != "8" {
		t.Fatalf("event = %+v", e)
	}

	// The count stops moving: the loop is over after 60 s, then two online
	// ticks resolve it.
	for range 6 {
		h.tick()
	}
	if got := h.sender.countTo("resolved"); got != 1 {
		t.Fatalf("resolved events = %d, want 1", got)
	}
}

func TestPM2App_SlowRestartsAreNotALoop(t *testing.T) {
	h := newPM2Harness(t)
	h.set("online", 0)
	h.tick()
	// One restart every 3 minutes: never 3 inside 5 minutes.
	for i := 1; i <= 4; i++ {
		h.set("online", i)
		h.tick()
		for range 5 {
			h.tick()
		}
	}
	if len(h.sender.events) != 0 {
		t.Fatalf("events = %+v, want none", h.sender.events)
	}
}

func TestPM2App_CounterResetIsNotARestart(t *testing.T) {
	h := newPM2Harness(t)
	h.set("online", 40)
	h.tick()
	h.set("online", 0) // pm2 reset counters
	h.tick()
	h.set("online", 1)
	for range 4 {
		h.tick()
	}
	if len(h.sender.events) != 0 {
		t.Fatalf("events = %+v, want none", h.sender.events)
	}
}

func TestPM2App_ListFailureHoldsState(t *testing.T) {
	h := newPM2Harness(t)
	h.set("stopped", 0)
	h.tick()
	h.tick() // firing
	h.pm2.errs["deploy"] = errors.New("exit status 1")
	for range 4 {
		h.tick()
	}
	if h.sender.countTo("resolved") != 0 || h.sender.countTo("firing") != 1 {
		t.Fatalf("events = %+v, want only the original firing", h.sender.events)
	}
	if st := h.m.states[key(KindPM2App, pm2Target)]; st.State != string(StateFiring) {
		t.Fatalf("state = %s, want firing", st.State)
	}
}

func TestPM2App_OneListPerUserPerTick(t *testing.T) {
	h := newPM2Harness(t)
	h.m.SetSyncedDefinitions([]Definition{
		{Kind: KindPM2App, Target: "deploy/web", Enabled: true},
		{Kind: KindPM2App, Target: "deploy/worker", Enabled: true},
		{Kind: KindPM2App, Target: "app/api", Enabled: true},
		{Kind: KindPM2App, Target: "not-a-target", Enabled: true},
	})
	h.tick()
	counts := map[string]int{}
	for _, u := range h.pm2.calls {
		counts[u]++
	}
	if len(counts) != 2 || counts["deploy"] != 1 || counts["app"] != 1 {
		t.Fatalf("pm2-list calls = %v, want one per user", h.pm2.calls)
	}
}

func TestPM2App_RemovedDefinitionClosesEpisode(t *testing.T) {
	h := newPM2Harness(t)
	h.set("stopped", 0)
	h.tick()
	h.tick() // firing
	h.m.SetSyncedDefinitions(nil)
	h.tick()
	h.tick()
	h.tick()
	if st := h.m.states[key(KindPM2App, pm2Target)]; State(st.State).inEpisode() {
		t.Fatalf("state = %s, want the episode closed", st.State)
	}
}

func TestParsePM2Target(t *testing.T) {
	for in, ok := range map[string]bool{"deploy/web": true, "deploy/": false, "/web": false, "web": false, "": false} {
		if _, _, got := ParsePM2Target(in); got != ok {
			t.Errorf("ParsePM2Target(%q) ok = %v, want %v", in, got, ok)
		}
	}
}

type recordingPriv struct {
	out  string
	err  error
	args []string
}

func (r *recordingPriv) Call(_ context.Context, action string, args ...string) ([]byte, error) {
	r.args = append([]string{action}, args...)
	return []byte(r.out), r.err
}

func TestPrivPM2Source_ReadsPM2List(t *testing.T) {
	p := &recordingPriv{out: `[{"app":"api","status":"online","restarts":3},{"app":"w","status":"stopped","restarts":0}]`}
	apps, err := NewPM2Source(p).Apps(context.Background(), "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.args, " ") != "pm2-list deploy" {
		t.Fatalf("priv args = %v", p.args)
	}
	if len(apps) != 2 || apps[0] != (PM2App{Name: "api", Status: "online", Restarts: 3}) || apps[1].Status != "stopped" {
		t.Fatalf("apps = %+v", apps)
	}
	p.out = "not json"
	if _, err := NewPM2Source(p).Apps(context.Background(), "deploy"); err == nil {
		t.Fatal("bad output must be an error")
	}
	p.err = errors.New("refused")
	if _, err := NewPM2Source(p).Apps(context.Background(), "deploy"); err == nil {
		t.Fatal("helper error must surface")
	}
}
