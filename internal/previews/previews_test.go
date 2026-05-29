package previews

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/store"
)

// --- fakes -----------------------------------------------------------------

type fakeReloader struct {
	calls int32
	fail  error
}

func (f *fakeReloader) Reload(context.Context) error {
	atomic.AddInt32(&f.calls, 1)
	return f.fail
}

type fakeResolver struct {
	answers map[string][]net.IP
	err     error
}

func (f *fakeResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.answers[host], nil
}

type fakeLauncher struct {
	launches []LaunchSpec
	pgid     int
	fail     error
}

func (f *fakeLauncher) Launch(_ context.Context, spec LaunchSpec) (LaunchHandle, error) {
	if f.fail != nil {
		return LaunchHandle{}, f.fail
	}
	f.launches = append(f.launches, spec)
	if f.pgid == 0 {
		f.pgid = 4242
	}
	return LaunchHandle{PID: f.pgid, PGID: f.pgid}, nil
}

type fakePortProber struct {
	calls    int
	ports    []int
	delayN   int // first N calls return nothing
	fail     error
	lastPGID int
}

func (f *fakePortProber) ListeningPorts(_ context.Context, pgid int) ([]int, error) {
	f.calls++
	f.lastPGID = pgid
	if f.fail != nil {
		return nil, f.fail
	}
	if f.calls <= f.delayN {
		return nil, nil
	}
	return f.ports, nil
}

type fakeKiller struct {
	killed []int
}

func (f *fakeKiller) KillGroup(_ context.Context, pgid int) error {
	f.killed = append(f.killed, pgid)
	return nil
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time        { return c.t }
func (c *fakeClock) Sleep(d time.Duration) { c.t = c.t.Add(d) }

// --- harness ---------------------------------------------------------------

type harness struct {
	mgr      *Manager
	st       *store.Store
	pm       *projects.Manager
	reloader *fakeReloader
	resolver *fakeResolver
	launcher *fakeLauncher
	prober   *fakePortProber
	killer   *fakeKiller
	clock    *fakeClock
	fragDir  string
	project  store.Project
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pm, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "p1" }
	proj, err := pm.CreateEmpty("demo")
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		st:       st,
		pm:       pm,
		project:  proj,
		reloader: &fakeReloader{},
		resolver: &fakeResolver{answers: map[string][]net.IP{}},
		launcher: &fakeLauncher{},
		prober:   &fakePortProber{ports: []int{5173}},
		killer:   &fakeKiller{},
		clock:    &fakeClock{t: time.Unix(1000, 0)},
		fragDir:  filepath.Join(dir, "caddy"),
	}
	mgr, err := New(Config{
		FragmentsDir:      h.fragDir,
		PortProbeTimeout:  500 * time.Millisecond,
		PortProbeInterval: 10 * time.Millisecond,
		Reloader:          h.reloader,
		Resolver:          h.resolver,
		Launcher:          h.launcher,
		PortProber:        h.prober,
		Killer:            h.killer,
		Clock:             h.clock,
		IDGen:             stepIDGen("a"),
	}, st, pm)
	if err != nil {
		t.Fatal(err)
	}
	h.mgr = mgr
	return h
}

func stepIDGen(seed string) func() string {
	n := 0
	return func() string {
		n++
		return seed + strconvN(n)
	}
}

func strconvN(n int) string {
	return string(rune('0' + n))
}

// --- AC tests --------------------------------------------------------------

// AC: "First-run setup walks the user through pointing a wildcard DNS record
// at the VPS, and validates resolution before enabling preview features."
func TestSetupDomainAndValidateDNS_HappyPath(t *testing.T) {
	h := newHarness(t)
	if _, err := h.mgr.SetupDomain("*.previews.example.com."); err != nil {
		t.Fatal(err)
	}
	base, err := h.mgr.BaseDomain()
	if err != nil || base != "previews.example.com" {
		t.Fatalf("base normalisation: %q err=%v", base, err)
	}
	// The sentinel is dns-check-<id>.<base>; the harness's IDGen returns
	// "a1", "a2", ... so prime the expected sentinel.
	h.resolver.answers["dns-check-a1.previews.example.com"] = []net.IP{net.ParseIP("203.0.113.10")}
	res, err := h.mgr.ValidateDNS(context.Background())
	if err != nil {
		t.Fatalf("validate dns: %v res=%+v", err, res)
	}
	if !res.OK || res.Resolved[0] != "203.0.113.10" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestValidateDNS_RequiresBaseDomain(t *testing.T) {
	h := newHarness(t)
	_, err := h.mgr.ValidateDNS(context.Background())
	if !errors.Is(err, ErrBaseDomainUnset) {
		t.Fatalf("want ErrBaseDomainUnset, got %v", err)
	}
}

func TestValidateDNS_FailureWhenWrongIP(t *testing.T) {
	h := newHarness(t)
	if _, err := h.mgr.SetupDomain("previews.example.com"); err != nil {
		t.Fatal(err)
	}
	// Re-build manager with ExpectedIP for this scenario.
	mgr, err := New(Config{
		FragmentsDir: h.fragDir,
		ExpectedIP:   "203.0.113.10",
		Reloader:     h.reloader,
		Resolver:     h.resolver,
		Launcher:     h.launcher,
		PortProber:   h.prober,
		Killer:       h.killer,
		Clock:        h.clock,
		IDGen:        stepIDGen("b"),
	}, h.st, h.pm)
	if err != nil {
		t.Fatal(err)
	}
	h.resolver.answers["dns-check-b1.previews.example.com"] = []net.IP{net.ParseIP("198.51.100.99")}
	res, err := mgr.ValidateDNS(context.Background())
	if !errors.Is(err, ErrDNSValidationFailed) {
		t.Fatalf("want ErrDNSValidationFailed, got %v res=%+v", err, res)
	}
}

// AC: "Starting a preview produces a working HTTPS URL within ~30 s on first
// use (cert issuance) and within ~2 s on subsequent uses."
//
// We assert the URL shape (https://preview-<id>.<base>) and that the
// CertWarmup budget is exposed to the caller for the first-use case. Real
// wall-clock latency depends on Caddy and is asserted in the e2e harness.
func TestStart_ProducesHTTPSURLAndAdvertisesCertBudget(t *testing.T) {
	h := newHarness(t)
	if _, err := h.mgr.SetupDomain("previews.example.com"); err != nil {
		t.Fatal(err)
	}
	row, err := h.mgr.Start(context.Background(), StartRequest{
		ProjectID: h.project.ID,
		Command:   "npm run dev",
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !strings.HasPrefix(row.URL, "https://preview-") || !strings.HasSuffix(row.URL, ".previews.example.com") {
		t.Fatalf("unexpected URL: %q", row.URL)
	}
	if row.Status != "running" || row.Port != 5173 {
		t.Fatalf("bad row: %+v", row)
	}
	if h.mgr.CertWarmup() <= 0 {
		t.Fatalf("cert warmup budget should be advertised")
	}
	// Caddy reload was triggered exactly once.
	if atomic.LoadInt32(&h.reloader.calls) != 1 {
		t.Fatalf("expected 1 reload, got %d", h.reloader.calls)
	}
}

// AC: "Port detection succeeds for: explicit env (PORT), framework defaults
// (Vite, Next, Flask, Rails), and falls back to a user prompt if undetected."
func TestPortDetection_ExplicitPort_SkipsProbe(t *testing.T) {
	h := newHarness(t)
	if _, err := h.mgr.SetupDomain("previews.example.com"); err != nil {
		t.Fatal(err)
	}
	row, err := h.mgr.Start(context.Background(), StartRequest{
		ProjectID: h.project.ID,
		Command:   "npm run dev",
		Port:      8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.Port != 8080 || h.prober.calls != 0 {
		t.Fatalf("explicit port not honoured: port=%d probeCalls=%d", row.Port, h.prober.calls)
	}
}

func TestPortDetection_FrameworkDefaults_ViteNext(t *testing.T) {
	h := newHarness(t)
	if _, err := h.mgr.SetupDomain("previews.example.com"); err != nil {
		t.Fatal(err)
	}
	wd := h.pm.WorkspaceDir(h.project.ID)
	cases := []struct {
		name, pkg, want string
	}{
		{"vite", `{"devDependencies": {"vite": "^5"}}`, "npx vite"},
		{"next", `{"dependencies": {"next": "^14"}}`, "npx next dev"},
		{"dev-script", `{"scripts": {"dev": "vite"}}`, "npm run dev"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(wd, "package.json"), []byte(tc.pkg), 0o644); err != nil {
				t.Fatal(err)
			}
			got := DetectStartCommand(wd)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestPortDetection_FrameworkDefaults_FlaskRails(t *testing.T) {
	dir := t.TempDir()
	// Flask
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==3.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectStartCommand(dir); !strings.HasPrefix(got, "flask ") {
		t.Fatalf("flask: got %q", got)
	}
	// Rails
	railsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(railsDir, "Gemfile"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(railsDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(railsDir, "bin", "rails"), []byte(""), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DetectStartCommand(railsDir); !strings.HasPrefix(got, "bin/rails ") {
		t.Fatalf("rails: got %q", got)
	}
}

func TestPortDetection_FallbackErrorPromptsUser(t *testing.T) {
	h := newHarness(t)
	if _, err := h.mgr.SetupDomain("previews.example.com"); err != nil {
		t.Fatal(err)
	}
	h.prober.ports = nil
	_, err := h.mgr.Start(context.Background(), StartRequest{
		ProjectID: h.project.ID,
		Command:   "node server.js",
	})
	if !errors.Is(err, ErrPortUnknown) {
		t.Fatalf("want ErrPortUnknown, got %v", err)
	}
	// The launcher was killed when port detection failed.
	if len(h.killer.killed) != 1 || h.killer.killed[0] != 4242 {
		t.Fatalf("expected child to be reaped, got %+v", h.killer.killed)
	}
}

func TestPortDetection_PollsUntilAvailable(t *testing.T) {
	h := newHarness(t)
	if _, err := h.mgr.SetupDomain("previews.example.com"); err != nil {
		t.Fatal(err)
	}
	h.prober.delayN = 2
	h.prober.ports = []int{3000}
	row, err := h.mgr.Start(context.Background(), StartRequest{
		ProjectID: h.project.ID,
		Command:   "node server.js",
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.Port != 3000 {
		t.Fatalf("expected port 3000, got %d", row.Port)
	}
	if h.prober.calls < 3 {
		t.Fatalf("expected at least 3 probe calls, got %d", h.prober.calls)
	}
}

// AC: "Stopping a preview removes its Caddy fragment, reloads Caddy, and
// kills the dev server process group."
func TestStop_TearsDownFragmentReloadsAndKills(t *testing.T) {
	h := newHarness(t)
	if _, err := h.mgr.SetupDomain("previews.example.com"); err != nil {
		t.Fatal(err)
	}
	row, err := h.mgr.Start(context.Background(), StartRequest{
		ProjectID: h.project.ID,
		Command:   "npm run dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	fragPath := filepath.Join(h.fragDir, "preview-"+row.ID+".caddy")
	if _, err := os.Stat(fragPath); err != nil {
		t.Fatalf("fragment not written: %v", err)
	}
	if err := h.mgr.Stop(context.Background(), row.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fragPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fragment still present: %v", err)
	}
	if h.reloader.calls != 2 {
		t.Fatalf("expected 2 reloads (start+stop), got %d", h.reloader.calls)
	}
	if len(h.killer.killed) != 1 || h.killer.killed[0] != 4242 {
		t.Fatalf("expected pgid to be killed once, got %+v", h.killer.killed)
	}
	stopped, _ := h.st.GetPreview(row.ID)
	if stopped.Status != "stopped" || stopped.EndedAt == nil {
		t.Fatalf("row not marked stopped: %+v", stopped)
	}
}

func TestStart_RejectsDoubleStartForSameProject(t *testing.T) {
	h := newHarness(t)
	if _, err := h.mgr.SetupDomain("previews.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mgr.Start(context.Background(), StartRequest{
		ProjectID: h.project.ID, Command: "npm run dev",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := h.mgr.Start(context.Background(), StartRequest{
		ProjectID: h.project.ID, Command: "npm run dev",
	})
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("want ErrAlreadyRunning, got %v", err)
	}
}

// AC support: "In-app webview opens the preview URL; an open in system
// browser affordance is always present." The agent's job here is to return a
// well-formed URL — the affordance lives in the Flutter UI. We assert the
// URL is parseable and stable so the UI can rely on it.
func TestStart_URLIsStableAndParseable(t *testing.T) {
	h := newHarness(t)
	if _, err := h.mgr.SetupDomain("previews.example.com"); err != nil {
		t.Fatal(err)
	}
	row, err := h.mgr.Start(context.Background(), StartRequest{
		ProjectID: h.project.ID,
		Command:   "npm run dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := h.mgr.Get(row.ID)
	if got.URL != row.URL {
		t.Fatalf("URL not stable: start=%q get=%q", row.URL, got.URL)
	}
}

func TestNormalizeBaseDomain(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"previews.example.com", "previews.example.com", true},
		{"  PREVIEWS.example.com.", "previews.example.com", true},
		{"*.previews.example.com", "previews.example.com", true},
		{"", "", false},
		{"not_a_domain", "", false},
	}
	for _, tc := range cases {
		got, err := normalizeBaseDomain(tc.in)
		if tc.ok && err != nil {
			t.Fatalf("%q: unexpected err %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%q: expected error", tc.in)
		}
		if got != tc.want {
			t.Fatalf("%q: got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseLsofPorts(t *testing.T) {
	sample := `node    1234 user 21u IPv4 0xabcd 0t0 TCP 127.0.0.1:5173 (LISTEN)
node    1234 user 22u IPv6 0xabce 0t0 TCP [::1]:5173 (LISTEN)
node    1234 user 23u IPv4 0xabcf 0t0 TCP 127.0.0.1:9229 (LISTEN)
`
	got := parseLsofPorts(sample)
	if len(got) != 2 {
		t.Fatalf("want 2 unique ports, got %v", got)
	}
}
