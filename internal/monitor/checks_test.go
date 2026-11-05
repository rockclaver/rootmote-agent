package monitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/firewall"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/store"
)

// --- fakes ---------------------------------------------------------------

type heldSet map[string]bool

func (h heldSet) WasFailing(k Kind, target string) bool { return h[key(k, target)] }

type fakeDefs struct{ defs map[string]Definition }

func newDefs(defs ...Definition) *fakeDefs {
	f := &fakeDefs{defs: map[string]Definition{}}
	for _, d := range defs {
		d.Enabled = true
		f.defs[key(d.Kind, d.Target)] = d
	}
	return f
}

func (f *fakeDefs) Resolve(k Kind, target string) (Definition, bool) {
	if d, ok := f.defs[key(k, target)]; ok {
		return d, d.Enabled
	}
	if d, ok := f.defs[key(k, wildcardTarget)]; ok {
		d.Target = target
		return d, d.Enabled
	}
	return Definition{}, false
}

func (f *fakeDefs) Targets(k Kind) []string {
	var out []string
	for _, d := range f.defs {
		if d.Kind == k && d.Target != wildcardTarget {
			out = append(out, d.Target)
		}
	}
	return out
}

type fakeFileInfo struct {
	mod  time.Time
	size int64
}

func (f fakeFileInfo) Name() string       { return "f" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() fs.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return f.mod }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

type fakeHost struct {
	files    map[string]fakeFileInfo
	contents map[string][]byte
	runOut   map[string]string // joined args -> stdout
	runErr   error
	runCalls []string
	bootID   string
	bootErr  error
	certs    map[string]time.Time
	certErr  error
	certHits int
	// ReadFrom support: append-only log files.
	logs map[string]*strings.Builder
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		files: map[string]fakeFileInfo{}, contents: map[string][]byte{}, runOut: map[string]string{},
		certs: map[string]time.Time{}, logs: map[string]*strings.Builder{},
	}
}

func (h *fakeHost) Stat(p string) (fs.FileInfo, error) {
	if fi, ok := h.files[p]; ok {
		return fi, nil
	}
	return nil, fs.ErrNotExist
}

func (h *fakeHost) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range h.files {
		if ok, _ := filepath.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (h *fakeHost) ReadFile(p string) ([]byte, error) {
	if b, ok := h.contents[p]; ok {
		return b, nil
	}
	return nil, fs.ErrNotExist
}

func (h *fakeHost) ReadFrom(p string, offset, max int64) ([]byte, int64, error) {
	b, ok := h.logs[p]
	if !ok {
		return nil, 0, fs.ErrNotExist
	}
	s := b.String()
	size := int64(len(s))
	if size < offset {
		offset = 0
	}
	if size-offset > max {
		offset = size - max
	}
	return []byte(s[offset:]), size, nil
}

func (h *fakeHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	h.runCalls = append(h.runCalls, cmd)
	if h.runErr != nil {
		return nil, h.runErr
	}
	for prefix, out := range h.runOut {
		if strings.HasPrefix(cmd, prefix) {
			return []byte(out), nil
		}
	}
	return nil, nil
}

func (h *fakeHost) BootID(context.Context) (string, error) { return h.bootID, h.bootErr }

func (h *fakeHost) CertNotAfter(_ context.Context, addr, _ string) (time.Time, error) {
	h.certHits++
	if h.certErr != nil {
		return time.Time{}, h.certErr
	}
	return h.certs[addr], nil
}

type fakeInfraSampler struct{ m infra.HostMetrics }

func (f *fakeInfraSampler) Sample(context.Context) infra.HostMetrics { return f.m }
func (f *fakeInfraSampler) OOMEvents(context.Context, time.Time) ([]infra.OOMEvent, error) {
	return nil, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock { return &clock{t: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)} }

func evalOne(t *testing.T, ev Evaluator) Observation {
	t.Helper()
	obs, err := ev.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("observations = %d, want 1: %+v", len(obs), obs)
	}
	return obs[0]
}

// --- cpu_pressure / load_per_core -----------------------------------------

func TestCPUPressure_HysteresisBand(t *testing.T) {
	smp := &fakeInfraSampler{}
	held := heldSet{}
	ev := &CPUEvaluator{Infra: smp, Defs: newDefs(Definition{Kind: KindCPUPressure}), Held: held}
	set := func(p float64) {
		smp.m.CPU = infra.CPUMetric{MetricReason: infra.MetricReason{Available: true}, Percent: p}
	}

	set(94.9)
	if evalOne(t, ev).Failing {
		t.Fatal("94.9% must not fire at the default 95% threshold")
	}
	set(95)
	o := evalOne(t, ev)
	if !o.Failing || o.Severity != "warning" {
		t.Fatalf("95%%: %+v, want failing warning", o)
	}
	if o.Attributes["unit"] != "%" || o.Attributes["threshold"] != "95.0" || o.Attributes["observed"] != "95.0" {
		t.Fatalf("attrs = %v", o.Attributes)
	}
	held[key(KindCPUPressure, "")] = true
	set(85) // inside the 80-95 band: stays failing
	if !evalOne(t, ev).Failing {
		t.Fatal("85% mid-episode must keep failing (hysteresis)")
	}
	set(79.9)
	if evalOne(t, ev).Failing {
		t.Fatal("79.9% must recover")
	}
}

func TestCPUPressure_UnavailableSampleProducesNothing(t *testing.T) {
	ev := &CPUEvaluator{Infra: &fakeInfraSampler{}, Defs: newDefs(Definition{Kind: KindCPUPressure}), Held: heldSet{}}
	obs, _ := ev.Evaluate(context.Background())
	if len(obs) != 0 {
		t.Fatalf("obs = %+v, want none", obs)
	}
}

func TestLoadPerCore_UsesFiveMinuteLoadPerCore(t *testing.T) {
	smp := &fakeInfraSampler{}
	held := heldSet{}
	ev := &LoadEvaluator{Infra: smp, Defs: newDefs(Definition{Kind: KindLoadPerCore}), Held: held, Cores: func() int { return 4 }}
	set := func(one, five float64) {
		smp.m.Load = infra.LoadMetric{MetricReason: infra.MetricReason{Available: true}, One: one, Five: five}
	}
	set(40, 7.99) // huge 1-min spike must be ignored; 7.99/4 = 1.9975 < 2
	if evalOne(t, ev).Failing {
		t.Fatal("5-min load 7.99 on 4 cores (<2/core) must not fire")
	}
	set(0, 8) // exactly 2.0 per core
	if !evalOne(t, ev).Failing {
		t.Fatal("2.0 per core must fire")
	}
	held[key(KindLoadPerCore, "")] = true
	set(0, 6.4) // 1.6 per core: inside band
	if !evalOne(t, ev).Failing {
		t.Fatal("1.6/core mid-episode must hold")
	}
	set(0, 6) // 1.5 per core: recover boundary (<=1.5)
	// evalThreshold treats value >= recovery as still failing; 1.5 is the
	// recovery value itself, so it must still hold and 1.49 must clear.
	if !evalOne(t, ev).Failing {
		t.Fatal("exactly 1.5/core still within band")
	}
	set(0, 5.96)
	if evalOne(t, ev).Failing {
		t.Fatal("1.49/core must recover")
	}
}

// --- disk_fill_rate ---------------------------------------------------------

type fillHarness struct {
	smp   *fakeInfraSampler
	clk   *clock
	held  heldSet
	ev    *DiskFillEvaluator
	total uint64
	used  uint64
}

func newFillHarness() *fillHarness {
	h := &fillHarness{smp: &fakeInfraSampler{}, clk: newClock(), held: heldSet{}, total: 100 << 30, used: 50 << 30}
	h.ev = &DiskFillEvaluator{
		Infra: h.smp, Held: h.held, Now: h.clk.now,
		Defs: newDefs(Definition{Kind: KindDiskFillRate, Target: "/", Severity: "warning", FiringThreshold: 24, RecoveryValue: 36}),
	}
	return h
}

// step moves the clock a minute, grows used space by grow bytes, evaluates.
func (h *fillHarness) step(grow uint64) []Observation {
	h.clk.advance(time.Minute)
	h.used += grow
	h.smp.m.Disks = []infra.DiskMetric{{
		Mountpoint: "/", Available: true, TotalBytes: h.total, UsedBytes: h.used,
		AvailableBytes: h.total - h.used, Percent: float64(h.used) * 100 / float64(h.total),
	}}
	obs, err := h.ev.Evaluate(context.Background())
	if err != nil {
		panic(err)
	}
	return obs
}

func TestDiskFillRate_NeedsThirtyMinutesOfHistory(t *testing.T) {
	h := newFillHarness()
	// 1 GiB/hour... fast enough to be full in <24h (50GiB free / 4GiB/h = 12.5h).
	perMin := uint64(4<<30) / 60
	var obs []Observation
	for i := 0; i < 29; i++ {
		obs = h.step(perMin)
	}
	if len(obs) != 0 {
		t.Fatalf("29 minutes of history produced a verdict: %+v", obs)
	}
	obs = h.step(perMin) // 30 samples spanning 29min... still short
	obs = h.step(perMin)
	if len(obs) != 1 || !obs[0].Failing {
		t.Fatalf("after >=30min of growth want one failing obs, got %+v", obs)
	}
	if obs[0].Severity != "warning" {
		t.Fatalf("12.5h to full must be warning, got %s", obs[0].Severity)
	}
	if obs[0].Attributes["unit"] != "hours" {
		t.Fatalf("attrs = %v", obs[0].Attributes)
	}
}

func TestDiskFillRate_CriticalUnderFourHours(t *testing.T) {
	h := newFillHarness()
	perMin := uint64(20<<30) / 60 // 50GiB free / 20GiB/h = 2.5h
	var obs []Observation
	for i := 0; i < 32; i++ {
		obs = h.step(perMin)
	}
	if len(obs) != 1 || !obs[0].Failing || obs[0].Severity != "critical" {
		t.Fatalf("obs = %+v, want failing critical", obs)
	}
}

func TestDiskFillRate_SlowGrowthDoesNotFire(t *testing.T) {
	h := newFillHarness()
	perMin := uint64(1<<30) / 60 // 50h to full
	var obs []Observation
	for i := 0; i < 40; i++ {
		obs = h.step(perMin)
	}
	if len(obs) != 1 || obs[0].Failing {
		t.Fatalf("50h-to-full must not fire: %+v", obs)
	}
}

func TestDiskFillRate_NoiseIsNotATrend(t *testing.T) {
	h := newFillHarness()
	var obs []Observation
	for i := 0; i < 60; i++ {
		// +/-30MiB wobble around a flat level, net growth ~0.
		if i%2 == 0 {
			obs = h.step(30 << 20)
		} else {
			h.used -= 30 << 20 // step() re-adds grow=0 below
			obs = h.step(0)
		}
	}
	for _, o := range obs {
		if o.Failing {
			t.Fatalf("noise fired: %+v", o)
		}
	}
}

func TestDiskFillRate_TinyGrowthOnHugeDiskIgnored(t *testing.T) {
	h := newFillHarness()
	h.total, h.used = 10<<40, 10<<40-(2<<30) // 2GiB free on a 10TiB disk
	perMin := uint64(2<<20) / 1              // 2MiB/min -> 120MiB/h: full in ~17h, but growth over 35min is ~70MiB
	var obs []Observation
	for i := 0; i < 35; i++ {
		obs = h.step(perMin)
	}
	for _, o := range obs {
		if o.Failing {
			t.Fatalf("growth below the materiality floor fired: %+v", o)
		}
	}
}

func TestDiskFillRate_RecoversWithHysteresisAndResetsAfterPurge(t *testing.T) {
	h := newFillHarness()
	perMin := uint64(20<<30) / 60
	for i := 0; i < 32; i++ {
		h.step(perMin)
	}
	h.held[key(KindDiskFillRate, "/")] = true
	// A purge drops usage by >2% of capacity: history is discarded and the
	// next verdict is healthy immediately, not stuck failing while warming.
	h.used -= 20 << 30
	obs := h.step(0)
	if len(obs) != 1 || obs[0].Failing {
		t.Fatalf("after purge want one healthy obs, got %+v", obs)
	}
}

// --- cert_expiry --------------------------------------------------------------

func TestCertExpiry_Boundaries(t *testing.T) {
	clk := newClock()
	host := newFakeHost()
	held := heldSet{}
	ev := &CertEvaluator{Host: host, Held: held, Now: clk.now,
		Defs: newDefs(Definition{Kind: KindCertExpiry, Target: "example.com", Severity: "warning"})}

	cases := []struct {
		name     string
		left     time.Duration
		held     bool
		failing  bool
		severity string
	}{
		{"15d ok", 15*24*time.Hour + time.Hour, false, false, "warning"},
		{"just under 14d warns", 14*24*time.Hour - time.Minute, false, true, "warning"},
		{"hysteresis holds at 14.5d", 14*24*time.Hour + 12*time.Hour, true, true, "warning"},
		{"recovers at 15d+", 15*24*time.Hour + time.Hour, true, false, "warning"},
		{"under 3d critical", 3*24*time.Hour - time.Hour, false, true, "critical"},
		{"expired critical", -time.Hour, false, true, "critical"},
	}
	for _, c := range cases {
		host.certs["example.com:443"] = clk.now().Add(c.left)
		host.certHits = 0
		clk.advance(2 * time.Hour) // force a re-check every case
		host.certs["example.com:443"] = clk.now().Add(c.left)
		held[key(KindCertExpiry, "example.com")] = c.held
		o := evalOne(t, ev)
		if o.Failing != c.failing || o.Severity != c.severity {
			t.Errorf("%s: failing=%v severity=%s, want %v/%s (%s)", c.name, o.Failing, o.Severity, c.failing, c.severity, o.Summary)
		}
	}
}

func TestCertExpiry_DialsAtMostHourlyAndKeepsLastKnownOnError(t *testing.T) {
	clk := newClock()
	host := newFakeHost()
	host.certs["example.com:443"] = clk.now().Add(10 * 24 * time.Hour)
	ev := &CertEvaluator{Host: host, Held: heldSet{}, Now: clk.now,
		Defs: newDefs(Definition{Kind: KindCertExpiry, Target: "example.com"})}
	evalOne(t, ev)
	for i := 0; i < 100; i++ {
		clk.advance(30 * time.Second)
		evalOne(t, ev)
	}
	if host.certHits != 1 {
		t.Fatalf("dials in ~50min = %d, want 1", host.certHits)
	}
	clk.advance(30 * time.Minute) // > 1h since first dial
	host.certErr = errors.New("connection refused")
	o := evalOne(t, ev) // dial fails: last known expiry still reported
	if !o.Failing {
		t.Fatal("last known 10d expiry should still warn")
	}
	if host.certHits != 2 {
		t.Fatalf("dials = %d, want 2", host.certHits)
	}
}

func TestCertExpiry_DialErrorWithNoHistoryIsSilent(t *testing.T) {
	host := newFakeHost()
	host.certErr = errors.New("no route")
	ev := &CertEvaluator{Host: host, Held: heldSet{}, Now: newClock().now,
		Defs: newDefs(Definition{Kind: KindCertExpiry, Target: "example.com:8443"})}
	obs, err := ev.Evaluate(context.Background())
	if err != nil || len(obs) != 0 {
		t.Fatalf("obs=%v err=%v, want silence", obs, err)
	}
}

func testCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertExpiry_FileTarget(t *testing.T) {
	clk := newClock()
	host := newFakeHost()
	path := "/etc/ssl/site.pem"
	ev := &CertEvaluator{Host: host, Held: heldSet{}, Now: clk.now,
		Defs: newDefs(Definition{Kind: KindCertExpiry, Target: path})}

	o := evalOne(t, ev) // missing file
	if !o.Failing || !strings.Contains(o.Summary, "cannot read") {
		t.Fatalf("missing file: %+v", o)
	}
	host.contents[path] = testCertPEM(t, clk.now().Add(2*24*time.Hour))
	o = evalOne(t, ev)
	if !o.Failing || o.Severity != "critical" {
		t.Fatalf("2d left: %+v", o)
	}
	host.contents[path] = testCertPEM(t, clk.now().Add(60*24*time.Hour))
	if o = evalOne(t, ev); o.Failing {
		t.Fatalf("60d left: %+v", o)
	}
}

// --- systemd_timer_failed -----------------------------------------------------

func timerHost(state, result string) *fakeHost {
	h := newFakeHost()
	h.runOut["systemctl list-units"] = "backup.timer loaded active waiting Backup\n"
	h.runOut["systemctl show --no-pager -p Id -p Unit"] = "Id=backup.timer\nUnit=backup.service\n"
	h.runOut["systemctl show --no-pager -p Id -p ActiveState"] = "Id=backup.service\nActiveState=" + state + "\nResult=" + result + "\n"
	return h
}

func TestSystemdTimerFailed(t *testing.T) {
	for _, c := range []struct {
		state, result string
		failing       bool
	}{
		{"inactive", "success", false},
		{"failed", "exit-code", true},
		{"inactive", "exit-code", true},
		{"active", "success", false},
	} {
		ev := &TimerEvaluator{Systemd: &fakeSystemd{}, Host: timerHost(c.state, c.result),
			Defs: newDefs(Definition{Kind: KindSystemdTimerFailed, Target: wildcardTarget, Severity: "warning"})}
		o := evalOne(t, ev)
		if o.Target != "backup.timer" || o.Failing != c.failing {
			t.Errorf("%s/%s: %+v, want failing=%v", c.state, c.result, o, c.failing)
		}
	}
}

func TestSystemdTimerFailed_DisabledTargetSkipped(t *testing.T) {
	defs := newDefs(Definition{Kind: KindSystemdTimerFailed, Target: wildcardTarget})
	off := defs.defs[key(KindSystemdTimerFailed, wildcardTarget)]
	off.Enabled = false
	defs.defs[key(KindSystemdTimerFailed, "backup.timer")] = off
	ev := &TimerEvaluator{Systemd: &fakeSystemd{}, Host: timerHost("failed", "exit-code"), Defs: defs}
	obs, err := ev.Evaluate(context.Background())
	if err != nil || len(obs) != 0 {
		t.Fatalf("obs=%v err=%v, want none", obs, err)
	}
}

// --- job_freshness ----------------------------------------------------------------

func TestJobFreshness_AgeAndSizeBoundaries(t *testing.T) {
	clk := newClock()
	host := newFakeHost()
	ev := &JobFreshnessEvaluator{Host: host, Now: clk.now, Defs: newDefs(Definition{
		Kind: KindJobFreshness, Target: "/backups/db-*.tgz", Severity: "critical",
		Params: map[string]string{"max_age": "26h", "min_size_bytes": "1000"},
	})}

	if o := evalOne(t, ev); !o.Failing || !strings.Contains(o.Summary, "missing") {
		t.Fatalf("no file: %+v", o)
	}
	host.files["/backups/db-old.tgz"] = fakeFileInfo{mod: clk.now().Add(-72 * time.Hour), size: 5000}
	host.files["/backups/db-new.tgz"] = fakeFileInfo{mod: clk.now().Add(-26 * time.Hour), size: 5000}
	if o := evalOne(t, ev); o.Failing {
		t.Fatalf("newest file exactly at max age must pass: %+v", o)
	}
	host.files["/backups/db-new.tgz"] = fakeFileInfo{mod: clk.now().Add(-26*time.Hour - time.Second), size: 5000}
	if o := evalOne(t, ev); !o.Failing {
		t.Fatalf("1s past max age must fail: %+v", o)
	}
	host.files["/backups/db-new.tgz"] = fakeFileInfo{mod: clk.now().Add(-time.Hour), size: 999}
	if o := evalOne(t, ev); !o.Failing || !strings.Contains(o.Summary, "bytes") {
		t.Fatalf("undersized backup must fail: %+v", o)
	}
	host.files["/backups/db-new.tgz"] = fakeFileInfo{mod: clk.now().Add(-time.Hour), size: 1000}
	if o := evalOne(t, ev); o.Failing {
		t.Fatalf("fresh adequate backup must pass: %+v", o)
	}
}

func TestJobFreshness_DefaultMaxAgeAndDaySuffix(t *testing.T) {
	clk := newClock()
	host := newFakeHost()
	host.files["/var/run/heartbeat"] = fakeFileInfo{mod: clk.now().Add(-24 * time.Hour)}
	ev := &JobFreshnessEvaluator{Host: host, Now: clk.now, Defs: newDefs(Definition{Kind: KindJobFreshness, Target: "/var/run/heartbeat"})}
	if evalOne(t, ev).Failing {
		t.Fatal("24h old with default 25h max must pass")
	}
	ev.Defs = newDefs(Definition{Kind: KindJobFreshness, Target: "/var/run/heartbeat", Params: map[string]string{"max_age": "1d"}})
	if evalOne(t, ev).Failing {
		t.Fatal("24h old with 1d max must pass")
	}
	host.files["/var/run/heartbeat"] = fakeFileInfo{mod: clk.now().Add(-25 * time.Hour)}
	if !evalOne(t, ev).Failing {
		t.Fatal("25h old with 1d max must fail")
	}
}

func TestParseAge(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90m": 90 * time.Minute, "26h": 26 * time.Hour, "2d": 48 * time.Hour, "1d12h": 36 * time.Hour,
	} {
		got, err := ParseAge(in)
		if err != nil || got != want {
			t.Errorf("ParseAge(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "-1d", "d", "1x"} {
		if d, err := ParseAge(bad); err == nil && d > 0 {
			t.Errorf("ParseAge(%q) = %v, want error or non-positive", bad, d)
		}
	}
}

// --- port_listening -------------------------------------------------------------

type fakeSockets struct {
	socks []firewall.Socket
	err   error
}

func (f *fakeSockets) Listening(context.Context) ([]firewall.Socket, error) { return f.socks, f.err }

func TestPortListening(t *testing.T) {
	socks := &fakeSockets{socks: []firewall.Socket{
		{Protocol: firewall.ProtoTCP, Address: "127.0.0.1", Port: 5432},
		{Protocol: firewall.ProtoTCP, Address: "[::]", Port: 443},
		{Protocol: firewall.ProtoUDP, Address: "0.0.0.0", Port: 53},
	}}
	defs := newDefs(
		Definition{Kind: KindPortListening, Target: ":443"},
		Definition{Kind: KindPortListening, Target: "127.0.0.1:5432"},
		Definition{Kind: KindPortListening, Target: "10.0.0.5:5432"},
		Definition{Kind: KindPortListening, Target: "localhost:5432"},
		Definition{Kind: KindPortListening, Target: "80"},
		Definition{Kind: KindPortListening, Target: ":53"},
	)

	ev := &PortEvaluator{Sockets: socks, Defs: defs}
	obs, err := ev.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, o := range obs {
		got[o.Target] = o.Failing
	}
	want := map[string]bool{
		":443": false, "127.0.0.1:5432": false, "10.0.0.5:5432": true,
		"localhost:5432": false, "80": true, ":53": true, // default protocol is tcp
	}
	for target, failing := range want {
		if got[target] != failing {
			t.Errorf("%s failing=%v, want %v", target, got[target], failing)
		}
	}
}

func TestPortListening_UDPParamAndReaderError(t *testing.T) {
	socks := &fakeSockets{socks: []firewall.Socket{{Protocol: firewall.ProtoUDP, Address: "0.0.0.0", Port: 53}}}
	ev := &PortEvaluator{Sockets: socks, Defs: newDefs(Definition{Kind: KindPortListening, Target: ":53", Params: map[string]string{"protocol": "udp"}})}
	if evalOne(t, ev).Failing {
		t.Fatal("udp/53 listening must pass with protocol=udp")
	}
	socks.err = errors.New("ss missing")
	if _, err := ev.Evaluate(context.Background()); err == nil {
		t.Fatal("reader error must surface, not read as 'not listening'")
	}
}

func TestParsePortTarget(t *testing.T) {
	for in, want := range map[string]struct {
		host string
		port int
	}{"80": {"", 80}, ":8080": {"", 8080}, "db:5432": {"db", 5432}, "[::1]:443": {"::1", 443}} {
		h, p, err := ParsePortTarget(in)
		if err != nil || h != want.host || p != want.port {
			t.Errorf("ParsePortTarget(%q) = %q,%d,%v", in, h, p, err)
		}
	}
	for _, bad := range []string{"", "abc", ":0", ":70000", "host:"} {
		if _, _, err := ParsePortTarget(bad); err == nil {
			t.Errorf("ParsePortTarget(%q) should fail", bad)
		}
	}
}

// --- process_running --------------------------------------------------------------

type fakeProcs struct {
	procs []ProcessInfo
	err   error
}

func (f *fakeProcs) Running(context.Context) ([]ProcessInfo, error) { return f.procs, f.err }

func TestProcessRunning(t *testing.T) {
	procs := &fakeProcs{procs: []ProcessInfo{
		{Command: "nginx: master process /usr/sbin/nginx -g daemon off;", ExePath: "/usr/sbin/nginx"},
		{Command: "/usr/bin/python3 /srv/worker.py"},
		{Command: "postgres"},
	}}
	ev := &ProcessEvaluator{Procs: procs, Defs: newDefs(
		Definition{Kind: KindProcessRunning, Target: "nginx"},
		Definition{Kind: KindProcessRunning, Target: "postgres"},
		Definition{Kind: KindProcessRunning, Target: "worker.py", Params: map[string]string{"match": "contains"}},
		Definition{Kind: KindProcessRunning, Target: "redis-server"},
		Definition{Kind: KindProcessRunning, Target: "python"},
	)}
	obs, err := ev.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, o := range obs {
		got[o.Target] = o.Failing
	}
	for target, failing := range map[string]bool{
		"nginx": false, "postgres": false, "worker.py": false, "redis-server": true, "python": true,
	} {
		if got[target] != failing {
			t.Errorf("%s failing=%v, want %v", target, got[target], failing)
		}
	}
}

// --- reboot_detected ---------------------------------------------------------------

type fakeBoot struct {
	vals   map[string]string
	putErr error
}

func (f *fakeBoot) GetAgentSetting(k string) (string, error) {
	v, ok := f.vals[k]
	if !ok {
		return "", store.ErrNotFound
	}
	return v, nil
}

func (f *fakeBoot) PutAgentSetting(k, v string) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.vals[k] = v
	return nil
}

func TestRebootDetected_OneEventPerReboot(t *testing.T) {
	host := newFakeHost()
	host.bootID = "boot-1"
	boot := &fakeBoot{vals: map[string]string{}}
	ev := &RebootEvaluator{Host: host, Boot: boot, Defs: newDefs(Definition{Kind: KindRebootDetected})}

	if evalOne(t, ev).Failing {
		t.Fatal("first-ever boot id must be recorded silently")
	}
	if evalOne(t, ev).Failing {
		t.Fatal("same boot id must stay healthy")
	}
	host.bootID = "boot-2"
	o := evalOne(t, ev)
	if !o.Failing || o.Attributes["boot_id"] != "boot-2" {
		t.Fatalf("reboot: %+v", o)
	}
	if evalOne(t, ev).Failing {
		t.Fatal("reboot must be reported for exactly one evaluation")
	}
	// A fresh evaluator (agent restart) with the persisted id sees no reboot.
	ev2 := &RebootEvaluator{Host: host, Boot: boot, Defs: newDefs(Definition{Kind: KindRebootDetected})}
	if evalOne(t, ev2).Failing {
		t.Fatal("agent restart without reboot must not alert")
	}
}

func TestRebootDetected_PersistFailureRetriesInsteadOfRepeating(t *testing.T) {
	host := newFakeHost()
	host.bootID = "b1"
	boot := &fakeBoot{vals: map[string]string{bootIDKey: "b0"}, putErr: errors.New("disk full")}
	ev := &RebootEvaluator{Host: host, Boot: boot, Defs: newDefs(Definition{Kind: KindRebootDetected})}
	if _, err := ev.Evaluate(context.Background()); err == nil {
		t.Fatal("persist error must be returned")
	}
	boot.putErr = nil
	if o := evalOne(t, ev); !o.Failing {
		t.Fatal("reboot must be reported once persistence works")
	}
	if evalOne(t, ev).Failing {
		t.Fatal("must not repeat")
	}
}

func TestParseDarwinBootTime(t *testing.T) {
	id, err := parseDarwinBootTime("{ sec = 1700000000, usec = 123 } Tue Nov 14 22:13:20 2023\n")
	if err != nil || id != "boottime-1700000000" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if _, err := parseDarwinBootTime("garbage"); err == nil {
		t.Fatal("garbage must fail")
	}
}

// Through the engine: one reboot -> exactly one firing and one resolved event.
type bootStateStore struct {
	*fakeStateStore
	*fakeBoot
}

func TestRebootDetected_EngineEmitsSingleFiringThenResolved(t *testing.T) {
	sender := &fakeSender{}
	host := newFakeHost()
	host.bootID = "b1"
	st := bootStateStore{newFakeStateStore(), &fakeBoot{vals: map[string]string{}}}
	clk := newClock()
	m, err := New(Config{
		Infra: &fakeInfra{}, Store: st, Client: sender, Host: host, Sockets: &fakeSockets{}, Processes: &fakeProcs{},
		Now: clk.now, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	tick := func() { m.Evaluate(context.Background()); clk.advance(30 * time.Second) }
	tick()
	host.bootID = "b2"
	for i := 0; i < 6; i++ {
		tick()
	}
	if sender.countTo("firing") != 1 || sender.countTo("resolved") != 1 {
		t.Fatalf("events: firing=%d resolved=%d, want 1/1: %+v", sender.countTo("firing"), sender.countTo("resolved"), sender.events)
	}
	if sender.events[0].MonitorKind != "reboot_detected" || sender.events[0].Severity != "warning" {
		t.Fatalf("event = %+v", sender.events[0])
	}
}

// --- log_error_spike ---------------------------------------------------------------

func TestLogErrorSpike_FileThresholdAndBaseline(t *testing.T) {
	clk := newClock()
	host := newFakeHost()
	logPath := "/var/log/app.log"
	host.logs[logPath] = &strings.Builder{}
	held := heldSet{}
	ev := &LogSpikeEvaluator{Host: host, Held: held, Now: clk.now, Defs: newDefs(Definition{
		Kind: KindLogErrorSpike, Target: logPath, FiringThreshold: 50, RecoveryValue: 25,
	})}
	write := func(errors, infos int) {
		for i := 0; i < errors; i++ {
			host.logs[logPath].WriteString("2026 ERROR something broke\n")
		}
		for i := 0; i < infos; i++ {
			host.logs[logPath].WriteString("2026 INFO fine\n")
		}
	}
	run := func() []Observation {
		clk.advance(time.Minute)
		obs, err := ev.Evaluate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return obs
	}

	if obs := run(); len(obs) != 0 { // first read only records the file size
		t.Fatalf("warm-up produced %+v", obs)
	}
	// Quiet baseline (2 errors/min = ~10 per 5m) for 16 minutes: no verdicts
	// before 3 baseline samples exist, never failing afterwards.
	var sawVerdict bool
	for i := 0; i < 16; i++ {
		write(2, 20)
		for _, o := range run() {
			sawVerdict = true
			if o.Failing {
				t.Fatalf("baseline traffic fired: %+v", o)
			}
		}
	}
	if !sawVerdict {
		t.Fatal("no verdict after warm-up")
	}
	// Burst: 100 errors in one minute. Window count ~ 110 > 50 and > 3x baseline(~10).
	write(100, 0)
	obs := run()
	if len(obs) != 1 || !obs[0].Failing {
		t.Fatalf("spike: %+v", obs)
	}
	if obs[0].Attributes["unit"] != "count" || obs[0].Attributes["threshold"] != "50.0" {
		t.Fatalf("attrs = %v", obs[0].Attributes)
	}
	// Mid-episode, with the burst still inside the 5-minute window, counts
	// stay >= recovery (25) so it holds.
	held[key(KindLogErrorSpike, logPath)] = true
	if obs = run(); !obs[0].Failing {
		t.Fatalf("still in window should hold: %+v", obs)
	}
	for i := 0; i < 6; i++ { // burst ages out of the window
		write(0, 5)
		obs = run()
	}
	if obs[0].Failing {
		t.Fatalf("after burst aged out should recover: %+v", obs[0])
	}
}

func TestLogErrorSpike_NeedsBothAbsoluteAndRelative(t *testing.T) {
	clk := newClock()
	host := newFakeHost()
	logPath := "/var/log/noisy.log"
	host.logs[logPath] = &strings.Builder{}
	ev := &LogSpikeEvaluator{Host: host, Held: heldSet{}, Now: clk.now,
		Defs: newDefs(Definition{Kind: KindLogErrorSpike, Target: logPath})}
	run := func(errs int) []Observation {
		for i := 0; i < errs; i++ {
			host.logs[logPath].WriteString("error again\n")
		}
		clk.advance(time.Minute)
		obs, _ := ev.Evaluate(context.Background())
		return obs
	}
	run(0)
	// Chronically noisy: 40 errors/min (~200 per 5m window) -> over 50, but
	// no more than 3x its own baseline.
	var last []Observation
	for i := 0; i < 25; i++ {
		last = run(40)
	}
	if len(last) != 1 || last[0].Failing {
		t.Fatalf("steady noise must not fire: %+v", last)
	}
}

func TestLogErrorSpike_JournalBoundedAndCustomPattern(t *testing.T) {
	clk := newClock()
	host := newFakeHost()
	host.runOut["journalctl"] = "timeout talking to db\nok\nTIMEOUT again\n"
	ev := &LogSpikeEvaluator{Host: host, Held: heldSet{}, Now: clk.now, Defs: newDefs(Definition{
		Kind: KindLogErrorSpike, Target: "nginx.service", Params: map[string]string{"pattern": "(?i)timeout"},
	})}
	ev.Evaluate(context.Background())
	if len(host.runCalls) != 1 {
		t.Fatalf("calls = %v", host.runCalls)
	}
	c := host.runCalls[0]
	for _, want := range []string{"-u nginx.service", "--since @", "--until @", "-n 20000"} {
		if !strings.Contains(c, want) {
			t.Errorf("journalctl call %q missing %q", c, want)
		}
	}
	clk.advance(10 * time.Second)
	ev.Evaluate(context.Background())
	if len(host.runCalls) != 1 {
		t.Fatalf("journal re-read within 60s: %v", host.runCalls)
	}
	if n := countMatches(host.runOut["journalctl"], regexp.MustCompile(`(?i)timeout`)); n != 2 {
		t.Fatalf("countMatches = %d, want 2", n)
	}
}

func TestLogErrorSpike_ReadErrorSurfaces(t *testing.T) {
	host := newFakeHost()
	host.runErr = errors.New("permission denied")
	ev := &LogSpikeEvaluator{Host: host, Held: heldSet{}, Now: newClock().now,
		Defs: newDefs(Definition{Kind: KindLogErrorSpike, Target: "x.service"})}
	if _, err := ev.Evaluate(context.Background()); err == nil {
		t.Fatal("journalctl failure must surface")
	}
}

// --- definitions -------------------------------------------------------------------

func TestDefaultDefinitions_NewKindsAreQuietByDefault(t *testing.T) {
	byKind := map[Kind]Definition{}
	for _, d := range DefaultDefinitions() {
		byKind[d.Kind] = d
	}
	for _, k := range []Kind{KindCertExpiry, KindJobFreshness, KindPortListening, KindProcessRunning, KindLogErrorSpike} {
		if _, ok := byKind[k]; ok {
			t.Errorf("%s needs operator configuration and must not be a built-in default", k)
		}
	}
	cpu := byKind[KindCPUPressure]
	if cpu.FiringThreshold != 95 || cpu.RecoveryValue != 80 || cpu.FailureThreshold < 10 || cpu.Severity != "warning" {
		t.Errorf("cpu default = %+v", cpu)
	}
	load := byKind[KindLoadPerCore]
	if load.FiringThreshold != 2 || load.RecoveryValue != 1.5 || load.Severity != "warning" {
		t.Errorf("load default = %+v", load)
	}
	if r := byKind[KindRebootDetected]; r.FailureThreshold != 1 || r.RecoveryThreshold != 1 {
		t.Errorf("reboot default = %+v", r)
	}
}
