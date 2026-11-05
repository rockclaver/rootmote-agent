package inventory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/webserver"
)

// --- fakes -----------------------------------------------------------------

type fakeInfraSampler struct{ sample infra.HostMetrics }

func (f fakeInfraSampler) Sample(context.Context) infra.HostMetrics { return f.sample }

type fakeDockerSource struct {
	status         docker.Status
	containers     []docker.ContainerSummary
	containersErr  error
	details        map[string]docker.ContainerDetail
	detailErr      error
	containerCalls []string
}

func (f *fakeDockerSource) Status(context.Context) docker.Status { return f.status }
func (f *fakeDockerSource) Containers(context.Context) ([]docker.ContainerSummary, error) {
	return f.containers, f.containersErr
}
func (f *fakeDockerSource) Container(_ context.Context, id string) (docker.ContainerDetail, error) {
	f.containerCalls = append(f.containerCalls, id)
	if f.detailErr != nil {
		return docker.ContainerDetail{}, f.detailErr
	}
	if d, ok := f.details[id]; ok {
		return d, nil
	}
	return docker.ContainerDetail{}, nil
}

type fakeSystemdSource struct {
	units []systemd.Unit
	err   error
}

func (f fakeSystemdSource) List(context.Context) ([]systemd.Unit, error) { return f.units, f.err }

type fakeWebserverSource struct{ snap webserver.Snapshot }

func (f fakeWebserverSource) List(context.Context) webserver.Snapshot { return f.snap }

// fakeRun dispatches by "name arg1 arg2 ..." key so tests can script exactly
// the commands the collectors are expected to issue.
type fakeRun struct {
	responses map[string]string
	errs      map[string]error
	calls     []string
}

func newFakeRun() *fakeRun {
	return &fakeRun{responses: map[string]string{}, errs: map[string]error{}}
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, key)
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	if out, ok := f.responses[key]; ok {
		return []byte(out), nil
	}
	return nil, fmt.Errorf("fakeRun: no response scripted for %q", key)
}

type fakeReadFile struct {
	files map[string][]byte
	errs  map[string]error
}

func newFakeReadFile() *fakeReadFile {
	return &fakeReadFile{files: map[string][]byte{}, errs: map[string]error{}}
}

func (f *fakeReadFile) read(path string) ([]byte, error) {
	if err, ok := f.errs[path]; ok {
		return nil, err
	}
	if b, ok := f.files[path]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("fakeReadFile: no file scripted for %q", path)
}

type fakeGlob struct {
	matches map[string][]string
	errs    map[string]error
}

func newFakeGlob() *fakeGlob {
	return &fakeGlob{matches: map[string][]string{}, errs: map[string]error{}}
}

func (f *fakeGlob) glob(pattern string) ([]string, error) {
	if err, ok := f.errs[pattern]; ok {
		return nil, err
	}
	return f.matches[pattern], nil
}

// baseOSStubs scripts every command/file the "os" collector may issue on
// either linux or darwin, so tests don't need to special-case the host the
// suite happens to run on.
func baseOSStubs(run *fakeRun, rf *fakeReadFile) {
	run.responses["uname -r"] = "6.8.0-generic\n"
	run.responses["uname -m"] = "arm64\n"
	run.responses["sw_vers -productName"] = "macOS\n"
	run.responses["sw_vers -productVersion"] = "26.0\n"
	rf.files["/etc/os-release"] = []byte("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n")
}

func systemctlShowKey(unit string) string {
	return fmt.Sprintf("systemctl show -p NRestarts -p ActiveEnterTimestamp --value %s", unit)
}

// --- AC5: every section is populated ---------------------------------------

func TestDiscover_ReturnsEverySection(t *testing.T) {
	run := newFakeRun()
	rf := newFakeReadFile()
	glob := newFakeGlob()
	baseOSStubs(run, rf)

	run.responses["ss -ltnpH"] = strings.Join([]string{
		`LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=6))`,
		`LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=900,fd=7))`,
	}, "\n")

	docker := &fakeDockerSource{
		status: docker.Status{Available: true, Version: "27.0"},
		containers: []docker.ContainerSummary{
			{ID: "c1", Name: "api", Image: "api:1", State: "running", Health: "healthy",
				ComposeProject: "shop", ComposeService: "api"},
			{ID: "c2", Name: "shop-db", Image: "postgres:16", State: "running"},
		},
		details: map[string]docker.ContainerDetail{
			"c1": {RestartCount: 2, Ports: []docker.PortSummary{{PrivatePort: 8080, PublicPort: 8080}}},
			"c2": {RestartCount: 0},
		},
	}

	run.responses[systemctlShowKey("nginx.service")] = "1\nWed 2026-08-05 10:00:00 UTC\n"
	sysd := fakeSystemdSource{units: []systemd.Unit{
		{Name: "nginx.service", Description: "nginx", ActiveState: "active", SubState: "running", EnabledOnBoot: "enabled"},
	}}

	web := fakeWebserverSource{snap: webserver.Snapshot{
		Available: true,
		Webservers: []webserver.Instance{
			{Kind: webserver.KindNginx, Unit: "nginx.service", ActiveState: "active",
				Domains: []webserver.Domain{{Host: "a.example"}}},
		},
	}}

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	priv := newFakePriv()
	priv.out["certs-list"] = `[{"name":"a.example","expiresAt":"` + now.AddDate(0, 0, 42).Format(time.RFC3339) + `"}]`

	sample := infra.HostMetrics{
		Memory: infra.MemoryMetric{TotalBytes: 8_000_000_000},
		Swap:   infra.MemoryMetric{TotalBytes: 2_000_000_000},
		Load:   infra.LoadMetric{One: 0.4},
		Disks: []infra.DiskMetric{
			{Mountpoint: "/", Filesystem: "ext4", TotalBytes: 100_000_000_000, UsedBytes: 41_000_000_000,
				Percent: 41.2, InodePercent: 9.0, Available: true},
		},
	}

	d := NewDiscoverer(DiscoveryConfig{
		Infra: fakeInfraSampler{sample: sample}, Docker: docker, Systemd: sysd, Webserver: web,
		Run: run.run, ReadFile: rf.read, Glob: glob.glob, Priv: priv.run, Now: func() time.Time { return now },
	})
	report := d.Discover(context.Background())

	if report.CapturedAt != now {
		t.Fatalf("CapturedAt = %v, want %v", report.CapturedAt, now)
	}
	if report.OS.Platform != runtime.GOOS {
		t.Fatalf("OS.Platform = %q, want %q", report.OS.Platform, runtime.GOOS)
	}
	if report.OS.Kernel == "" || report.OS.Arch == "" {
		t.Fatalf("OS section incomplete: %+v", report.OS)
	}
	if report.Capacity.CPUCores <= 0 || report.Capacity.MemoryTotalBytes == 0 || report.Capacity.LoadOne == 0 {
		t.Fatalf("capacity section incomplete: %+v", report.Capacity)
	}
	if len(report.Disks) != 1 || report.Disks[0].Mountpoint != "/" {
		t.Fatalf("disks section = %+v, want one entry for /", report.Disks)
	}
	if !report.Docker.Available || len(report.Docker.Containers) != 2 {
		t.Fatalf("docker section = %+v, want 2 containers", report.Docker)
	}
	if got := report.Docker.Containers[0].RestartCount; got != 2 {
		t.Fatalf("api restartCount = %d, want 2", got)
	}
	if !reflectStringsEqual(report.Docker.ComposeProjects, []string{"shop"}) {
		t.Fatalf("composeProjects = %v, want [shop]", report.Docker.ComposeProjects)
	}
	if len(report.SystemdUnits) != 1 || report.SystemdUnits[0].RestartCount != 1 {
		t.Fatalf("systemdUnits = %+v, want one unit with 1 restart", report.SystemdUnits)
	}
	if len(report.ReverseProxies) != 1 || len(report.ReverseProxies[0].Domains) != 1 {
		t.Fatalf("reverseProxies = %+v", report.ReverseProxies)
	}
	if len(report.ListeningPorts) != 2 {
		t.Fatalf("listeningPorts = %+v, want 2", report.ListeningPorts)
	}
	if len(report.Databases) == 0 {
		t.Fatal("databases section is empty")
	}
	if !reflectStringsEqual(report.PublicDomains, []string{"a.example"}) {
		t.Fatalf("publicDomains = %v, want [a.example]", report.PublicDomains)
	}
	if len(report.TLSCertificates) != 1 || report.TLSCertificates[0].Domain != "a.example" {
		t.Fatalf("tlsCertificates = %+v", report.TLSCertificates)
	}
	if report.TLSCertificates[0].DaysRemaining < 41 || report.TLSCertificates[0].DaysRemaining > 42 {
		t.Fatalf("tls daysRemaining = %d, want ~42", report.TLSCertificates[0].DaysRemaining)
	}
	if len(report.RestartHistory) != 2 {
		t.Fatalf("restartHistory = %+v, want 2 entries (docker api + systemd nginx)", report.RestartHistory)
	}
	want := []string{"docker/api", "systemd/nginx.service", "https://a.example"}
	if !reflectStringsEqual(report.ProductionCritical, want) {
		t.Fatalf("productionCritical = %v, want %v", report.ProductionCritical, want)
	}
}

func reflectStringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- independent per-collector degradation ----------------------------------

func TestDiscover_DegradesPerCollector(t *testing.T) {
	run := newFakeRun()
	rf := newFakeReadFile()
	glob := newFakeGlob()
	// Every seam fails.
	failErr := errors.New("boom")
	run.errs["uname -r"] = failErr
	run.errs["uname -m"] = failErr
	run.errs["sw_vers -productName"] = failErr
	run.errs["sw_vers -productVersion"] = failErr
	rf.errs["/etc/os-release"] = failErr
	run.errs["ss -ltnpH"] = failErr
	run.errs["netstat -an"] = failErr
	glob.errs["/etc/letsencrypt/live/*/fullchain.pem"] = failErr
	glob.errs["/var/lib/caddy/.local/share/caddy/certificates/**/*.crt"] = failErr

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	d := NewDiscoverer(DiscoveryConfig{
		// Infra, Docker, Systemd, Webserver left nil.
		Run: run.run, ReadFile: rf.read, Glob: glob.glob, Now: func() time.Time { return now },
	})
	report := d.Discover(context.Background())

	if report.OS.Platform != runtime.GOOS {
		t.Fatalf("OS.Platform = %q, want %q even when other os fields fail", report.OS.Platform, runtime.GOOS)
	}
	if report.OS.Kernel != "" || report.OS.Name != "" {
		t.Fatalf("OS section should have degraded to empty name/kernel: %+v", report.OS)
	}
	if report.Capacity.MemoryTotalBytes != 0 || report.Capacity.LoadOne != 0 {
		t.Fatalf("capacity should be empty without an infra sampler: %+v", report.Capacity)
	}
	if len(report.Disks) != 0 {
		t.Fatalf("disks should be empty without an infra sampler: %+v", report.Disks)
	}
	if report.Docker.Available {
		t.Fatalf("docker.available should be false without a docker source")
	}
	if len(report.Docker.Containers) != 0 {
		t.Fatalf("docker containers should be empty: %+v", report.Docker.Containers)
	}
	if len(report.SystemdUnits) != 0 {
		t.Fatalf("systemdUnits should be empty without a systemd source: %+v", report.SystemdUnits)
	}
	if len(report.ReverseProxies) != 0 || len(report.PublicDomains) != 0 {
		t.Fatalf("reverseProxies/publicDomains should be empty without a webserver source")
	}
	if len(report.ListeningPorts) != 0 {
		t.Fatalf("listeningPorts should be empty when both ss and netstat fail: %+v", report.ListeningPorts)
	}
	if len(report.Databases) != 0 {
		t.Fatalf("databases should be empty with nothing to infer from: %+v", report.Databases)
	}
	if len(report.TLSCertificates) != 0 {
		t.Fatalf("tlsCertificates should be empty when both globs fail: %+v", report.TLSCertificates)
	}
	if len(report.RestartHistory) != 0 || len(report.ProductionCritical) != 0 {
		t.Fatalf("restartHistory/productionCritical should be empty: %+v / %+v", report.RestartHistory, report.ProductionCritical)
	}
	// Every failing seam contributed a warning, and the scan itself never errors.
	if len(report.Warnings) == 0 {
		t.Fatal("expected warnings for every degraded collector")
	}
	wantSubstrings := []string{
		"capacity unavailable", "docker unavailable", "systemd unavailable",
		"reverse proxies unavailable", "listening ports unavailable", "tls certificate glob",
	}
	for _, sub := range wantSubstrings {
		found := false
		for _, w := range report.Warnings {
			if strings.Contains(w, sub) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("warnings missing %q: %v", sub, report.Warnings)
		}
	}
}

// --- listening ports ---------------------------------------------------

func TestDiscover_ParsesListeningPortsFromSs(t *testing.T) {
	run := newFakeRun()
	rf := newFakeReadFile()
	glob := newFakeGlob()
	baseOSStubs(run, rf)
	run.responses["ss -ltnpH"] = `LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=6))`

	d := NewDiscoverer(DiscoveryConfig{Run: run.run, ReadFile: rf.read, Glob: glob.glob})
	report := d.Discover(context.Background())

	if len(report.ListeningPorts) != 1 {
		t.Fatalf("listeningPorts = %+v, want 1 entry", report.ListeningPorts)
	}
	got := report.ListeningPorts[0]
	want := ListeningPortInfo{Address: "0.0.0.0", Port: 443, Protocol: "tcp", Process: "nginx", PID: 812}
	if got != want {
		t.Fatalf("listeningPorts[0] = %+v, want %+v", got, want)
	}
	for _, call := range run.calls {
		if call == "netstat -an" {
			t.Fatal("netstat should not be invoked when ss succeeds")
		}
	}
}

func TestDiscover_FallsBackToNetstat(t *testing.T) {
	run := newFakeRun()
	rf := newFakeReadFile()
	glob := newFakeGlob()
	baseOSStubs(run, rf)
	run.errs["ss -ltnpH"] = errors.New("exec: \"ss\": executable file not found in $PATH")
	run.responses["netstat -an"] = strings.Join([]string{
		"Active Internet connections",
		"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)",
		"tcp4       0      0  *.443                  *.*                    LISTEN",
	}, "\n")

	d := NewDiscoverer(DiscoveryConfig{Run: run.run, ReadFile: rf.read, Glob: glob.glob})
	report := d.Discover(context.Background())

	if len(report.ListeningPorts) != 1 {
		t.Fatalf("listeningPorts = %+v, want 1 entry parsed from netstat", report.ListeningPorts)
	}
	got := report.ListeningPorts[0]
	if got.Address != "0.0.0.0" || got.Port != 443 || got.Protocol != "tcp" {
		t.Fatalf("listeningPorts[0] = %+v, want address 0.0.0.0 port 443", got)
	}
}

// --- database inference -----------------------------------------------

func TestDiscover_InfersDatabasesFromDockerSystemdAndPorts(t *testing.T) {
	run := newFakeRun()
	rf := newFakeReadFile()
	glob := newFakeGlob()
	baseOSStubs(run, rf)
	run.responses["ss -ltnpH"] = `LISTEN 0 128 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=42,fd=3))`

	docker := &fakeDockerSource{
		status: docker.Status{Available: true},
		containers: []docker.ContainerSummary{
			{ID: "c1", Name: "shop-db", Image: "postgres:16", State: "running"},
		},
		details: map[string]docker.ContainerDetail{},
	}
	run.responses[systemctlShowKey("mysql.service")] = "0\nn/a\n"
	sysd := fakeSystemdSource{units: []systemd.Unit{{Name: "mysql.service", ActiveState: "active"}}}

	d := NewDiscoverer(DiscoveryConfig{
		Docker: docker, Systemd: sysd, Run: run.run, ReadFile: rf.read, Glob: glob.glob,
	})
	report := d.Discover(context.Background())

	byEngine := map[string]DatabaseInfo{}
	for _, db := range report.Databases {
		byEngine[db.Engine+"/"+db.Source] = db
	}
	if got, ok := byEngine["postgres/docker"]; !ok || got.Target != "shop-db" {
		t.Fatalf("expected postgres inferred from docker image, got %+v", report.Databases)
	}
	if got, ok := byEngine["mysql/systemd"]; !ok || got.Target != "mysql.service" {
		t.Fatalf("expected mysql inferred from systemd unit, got %+v", report.Databases)
	}
	if got, ok := byEngine["redis/port"]; !ok || got.Port != 6379 {
		t.Fatalf("expected redis inferred from listening port 6379, got %+v", report.Databases)
	}
	if len(report.Databases) != 3 {
		t.Fatalf("databases = %+v, want exactly 3 deduplicated entries", report.Databases)
	}
}

// --- TLS certificate expiry ---------------------------------------------

// fakePriv scripts the privileged helper by "action arg1 arg2" key.
type fakePriv struct {
	out   map[string]string
	errs  map[string]error
	calls []string
}

func newFakePriv() *fakePriv {
	return &fakePriv{out: map[string]string{}, errs: map[string]error{}}
}

func (f *fakePriv) run(_ context.Context, action string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(action + " " + strings.Join(args, " "))
	f.calls = append(f.calls, key)
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	if s, ok := f.out[key]; ok {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("fakePriv: no response scripted for %q", key)
}

func hasWarning(report DiscoveryReport, substr string) bool {
	for _, w := range report.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestDiscover_LetsEncryptCertsViaHelper(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

	t.Run("success fills certs and legacy tlsCertificates", func(t *testing.T) {
		run := newFakeRun()
		rf := newFakeReadFile()
		glob := newFakeGlob()
		baseOSStubs(run, rf)
		priv := newFakePriv()
		priv.out["certs-list"] = `[{"name":"b.example","expiresAt":"2026-08-01T12:00:00Z"},{"name":"a.example","expiresAt":"2026-08-12T12:00:00Z"}]`

		d := NewDiscoverer(DiscoveryConfig{Run: run.run, ReadFile: rf.read, Glob: glob.glob, Priv: priv.run, Now: func() time.Time { return now }})
		report := d.Discover(context.Background())

		if len(report.Certs) != 2 || report.Certs[0].Name != "a.example" || report.Certs[0].ExpiresAt != "2026-08-12T12:00:00Z" {
			t.Fatalf("certs = %+v", report.Certs)
		}
		if len(report.TLSCertificates) != 2 {
			t.Fatalf("tlsCertificates = %+v", report.TLSCertificates)
		}
		a := report.TLSCertificates[0]
		if a.Domain != "a.example" || a.DaysRemaining != 7 || a.ChainError != "" ||
			a.Path != "/etc/letsencrypt/live/a.example/fullchain.pem" || !a.NotAfter.Equal(time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)) {
			t.Fatalf("legacy entry = %+v", a)
		}
		if b := report.TLSCertificates[1]; b.Domain != "b.example" || b.ChainError == "" {
			t.Fatalf("expired entry = %+v, want a chainError", b)
		}
		if hasWarning(report, "Let's Encrypt") {
			t.Fatalf("unexpected warning: %v", report.Warnings)
		}
	})

	t.Run("helper failure warns plainly", func(t *testing.T) {
		run := newFakeRun()
		rf := newFakeReadFile()
		baseOSStubs(run, rf)
		priv := newFakePriv()
		priv.errs["certs-list"] = errors.New("exit status 1")

		d := NewDiscoverer(DiscoveryConfig{Run: run.run, ReadFile: rf.read, Glob: newFakeGlob().glob, Priv: priv.run, Now: func() time.Time { return now }})
		report := d.Discover(context.Background())

		if !hasWarning(report, "Let's Encrypt certificates could not be read") {
			t.Fatalf("warnings = %v", report.Warnings)
		}
		if len(report.Certs) != 0 || len(report.TLSCertificates) != 0 {
			t.Fatalf("certs = %+v tls = %+v, want empty", report.Certs, report.TLSCertificates)
		}
	})

	t.Run("nil helper warns plainly", func(t *testing.T) {
		run := newFakeRun()
		rf := newFakeReadFile()
		baseOSStubs(run, rf)

		d := NewDiscoverer(DiscoveryConfig{Run: run.run, ReadFile: rf.read, Glob: newFakeGlob().glob, Now: func() time.Time { return now }})
		report := d.Discover(context.Background())

		if !hasWarning(report, "Let's Encrypt certificates could not be read") {
			t.Fatalf("warnings = %v", report.Warnings)
		}
	})
}

func TestDiscover_ParsesCaddyCertificateFiles(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	const caddyGlob = "/var/lib/caddy/.local/share/caddy/certificates/**/*.crt"

	t.Run("valid certificate reports days remaining", func(t *testing.T) {
		run := newFakeRun()
		rf := newFakeReadFile()
		glob := newFakeGlob()
		baseOSStubs(run, rf)
		glob.matches[caddyGlob] = []string{"/caddy/a.example.crt"}
		rf.files["/caddy/a.example.crt"] = generateTestCert(t, "a.example", "Let's Encrypt", now.AddDate(0, 0, 7))

		d := NewDiscoverer(DiscoveryConfig{Run: run.run, ReadFile: rf.read, Glob: glob.glob, Now: func() time.Time { return now }})
		report := d.Discover(context.Background())

		if len(report.TLSCertificates) != 1 {
			t.Fatalf("tlsCertificates = %+v, want 1 entry", report.TLSCertificates)
		}
		cert := report.TLSCertificates[0]
		if cert.Domain != "a.example" || cert.Issuer != "Let's Encrypt" || cert.DaysRemaining != 7 || cert.ChainError != "" {
			t.Fatalf("cert = %+v", cert)
		}
	})

	t.Run("expired certificate reports a chain error", func(t *testing.T) {
		run := newFakeRun()
		rf := newFakeReadFile()
		glob := newFakeGlob()
		baseOSStubs(run, rf)
		glob.matches[caddyGlob] = []string{"/caddy/old.example.crt"}
		rf.files["/caddy/old.example.crt"] = generateTestCert(t, "old.example", "Let's Encrypt", now.AddDate(0, 0, -3))

		d := NewDiscoverer(DiscoveryConfig{Run: run.run, ReadFile: rf.read, Glob: glob.glob, Now: func() time.Time { return now }})
		report := d.Discover(context.Background())

		if len(report.TLSCertificates) != 1 || report.TLSCertificates[0].ChainError == "" || report.TLSCertificates[0].Domain != "old.example" {
			t.Fatalf("tlsCertificates = %+v", report.TLSCertificates)
		}
	})

	t.Run("unparseable file reports a chain error and path", func(t *testing.T) {
		run := newFakeRun()
		rf := newFakeReadFile()
		glob := newFakeGlob()
		baseOSStubs(run, rf)
		glob.matches[caddyGlob] = []string{"/caddy/broken.crt"}
		rf.files["/caddy/broken.crt"] = []byte("not a pem file")

		d := NewDiscoverer(DiscoveryConfig{Run: run.run, ReadFile: rf.read, Glob: glob.glob, Now: func() time.Time { return now }})
		report := d.Discover(context.Background())

		if len(report.TLSCertificates) != 1 || report.TLSCertificates[0].ChainError == "" || report.TLSCertificates[0].Path == "" {
			t.Fatalf("tlsCertificates = %+v", report.TLSCertificates)
		}
	})
}

// --- stack discovery: PM2, PHP-FPM, supervisor, database units -----------

const testPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
deploy:x:1001:1001::/home/deploy:/bin/bash
app:x:1000:1000::/home/app:/bin/zsh
svc:x:1002:1002::/home/svc:/usr/sbin/nologin
nohome:x:1003:1003::: /bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`

func TestDiscover_PM2AppsPerUserWithOneFailing(t *testing.T) {
	run := newFakeRun()
	rf := newFakeReadFile()
	baseOSStubs(run, rf)
	rf.files["/etc/passwd"] = []byte(testPasswd)
	priv := newFakePriv()
	priv.out["pm2-list app"] = `[{"app":"api","status":"online","restarts":0},{"app":"worker","status":"stopped","restarts":3}]`
	priv.errs["pm2-list deploy"] = errors.New("exit status 1")
	priv.out["certs-list"] = `[]`

	d := NewDiscoverer(DiscoveryConfig{Run: run.run, ReadFile: rf.read, Glob: newFakeGlob().glob, Priv: priv.run})
	report := d.Discover(context.Background())

	want := []PM2AppInfo{{User: "app", App: "api", Status: "online"}, {User: "app", App: "worker", Status: "stopped"}}
	if len(report.PM2Apps) != 2 || report.PM2Apps[0] != want[0] || report.PM2Apps[1] != want[1] {
		t.Fatalf("pm2Apps = %+v, want %+v", report.PM2Apps, want)
	}
	if !hasWarning(report, "user deploy") {
		t.Fatalf("warnings = %v, want one for user deploy", report.Warnings)
	}
	var pm2Calls []string
	for _, c := range priv.calls {
		if strings.HasPrefix(c, "pm2-list") {
			pm2Calls = append(pm2Calls, c)
		}
	}
	if strings.Join(pm2Calls, ",") != "pm2-list app,pm2-list deploy" {
		t.Fatalf("pm2 calls = %v, want only app and deploy, sorted", pm2Calls)
	}
}

func TestDiscover_StackUnitsAndSupervisor(t *testing.T) {
	run := newFakeRun()
	rf := newFakeReadFile()
	baseOSStubs(run, rf)
	names := []string{
		"php8.3-fpm.service", "php-fpm.service", "php8.2-fpm.service", "phpfoo.service",
		"mysql.service", "mariadb.service", "postgresql.service", "postgresql@16-main.service",
		"redis-server.service", "redis.service", "redis-exporter.service", "supervisor.service", "nginx.service",
	}
	var units []systemd.Unit
	for _, n := range names {
		units = append(units, systemd.Unit{Name: n, ActiveState: "active"})
		run.responses[systemctlShowKey(n)] = "0\nn/a\n"
	}
	priv := newFakePriv()
	priv.out["supervisor-status"] = `[{"name":"queue-worker:queue-worker_00","state":"RUNNING"}]`
	priv.out["certs-list"] = `[]`

	d := NewDiscoverer(DiscoveryConfig{Systemd: fakeSystemdSource{units: units}, Run: run.run, ReadFile: rf.read, Glob: newFakeGlob().glob, Priv: priv.run})
	report := d.Discover(context.Background())

	if got := strings.Join(report.PHPFPMUnits, ","); got != "php-fpm.service,php8.2-fpm.service,php8.3-fpm.service" {
		t.Fatalf("phpFpmUnits = %v", report.PHPFPMUnits)
	}
	want := []DatabaseUnitInfo{
		{"mariadb", "mariadb.service"},
		{"mysql", "mysql.service"},
		{"postgresql", "postgresql.service"},
		{"postgresql", "postgresql@16-main.service"},
		{"redis", "redis-server.service"},
		{"redis", "redis.service"},
	}
	if len(report.DatabaseUnits) != len(want) {
		t.Fatalf("databaseUnits = %+v, want %+v", report.DatabaseUnits, want)
	}
	for i := range want {
		if report.DatabaseUnits[i] != want[i] {
			t.Fatalf("databaseUnits[%d] = %+v, want %+v", i, report.DatabaseUnits[i], want[i])
		}
	}
	if len(report.SupervisorPrograms) != 1 || report.SupervisorPrograms[0] != (SupervisorProgramInfo{Name: "queue-worker:queue-worker_00", State: "RUNNING"}) {
		t.Fatalf("supervisorPrograms = %+v", report.SupervisorPrograms)
	}

	t.Run("supervisor helper failure is a warning", func(t *testing.T) {
		priv := newFakePriv()
		priv.errs["supervisor-status"] = errors.New("exit status 1")
		priv.out["certs-list"] = `[]`
		d := NewDiscoverer(DiscoveryConfig{Systemd: fakeSystemdSource{units: units}, Run: run.run, ReadFile: rf.read, Glob: newFakeGlob().glob, Priv: priv.run})
		report := d.Discover(context.Background())
		if !hasWarning(report, "supervisor programs could not be listed") || len(report.SupervisorPrograms) != 0 {
			t.Fatalf("warnings = %v programs = %+v", report.Warnings, report.SupervisorPrograms)
		}
	})
}

func TestDiscover_NewSlicesSerializeAsEmptyArrays(t *testing.T) {
	run := newFakeRun()
	rf := newFakeReadFile()
	baseOSStubs(run, rf)
	priv := newFakePriv()
	priv.out["certs-list"] = `[]`

	d := NewDiscoverer(DiscoveryConfig{Run: run.run, ReadFile: rf.read, Glob: newFakeGlob().glob, Priv: priv.run})
	raw, err := json.Marshal(d.Discover(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"pm2Apps", "phpFpmUnits", "supervisorPrograms", "databaseUnits", "certs", "tlsCertificates"} {
		if string(m[k]) != "[]" {
			t.Errorf("%s = %s, want []", k, m[k])
		}
	}
}

// --- production-critical suggestions (AC5) ------------------------------

func TestDiscover_SuggestsProductionCriticalWithoutEnablingAnything(t *testing.T) {
	run := newFakeRun()
	rf := newFakeReadFile()
	glob := newFakeGlob()
	baseOSStubs(run, rf)

	dockerSrc := &fakeDockerSource{
		status: docker.Status{Available: true},
		containers: []docker.ContainerSummary{
			{ID: "c1", Name: "web", Image: "web:1", State: "running"},
			{ID: "c2", Name: "worker", Image: "worker:1", State: "running"},
		},
		details: map[string]docker.ContainerDetail{
			"c1": {Ports: []docker.PortSummary{{PrivatePort: 80, PublicPort: 80}}},
			"c2": {}, // no published ports, no compose project -> not production critical
		},
	}
	run.responses[systemctlShowKey("nginx.service")] = "0\nn/a\n"
	run.responses[systemctlShowKey("postgresql.service")] = "0\nn/a\n"
	sysd := fakeSystemdSource{units: []systemd.Unit{
		{Name: "nginx.service", ActiveState: "active"},
		{Name: "postgresql.service", ActiveState: "active"},
	}}
	web := fakeWebserverSource{snap: webserver.Snapshot{
		Available: true,
		Webservers: []webserver.Instance{
			{Kind: webserver.KindNginx, Unit: "nginx.service", ActiveState: "active",
				Domains: []webserver.Domain{{Host: "web.example"}}},
		},
	}}

	d := NewDiscoverer(DiscoveryConfig{
		Docker: dockerSrc, Systemd: sysd, Webserver: web,
		Run: run.run, ReadFile: rf.read, Glob: glob.glob,
	})
	report := d.Discover(context.Background())

	want := []string{"docker/web", "systemd/nginx.service", "systemd/postgresql.service", "https://web.example"}
	sort.Strings(want)
	got := append([]string(nil), report.ProductionCritical...)
	sort.Strings(got)
	if !reflectStringsEqual(got, want) {
		t.Fatalf("productionCritical = %v, want %v", report.ProductionCritical, want)
	}
	for _, s := range report.ProductionCritical {
		if strings.Contains(s, "worker") {
			t.Fatalf("worker container has no published port or compose project and must not be suggested: %v", report.ProductionCritical)
		}
	}

	// The narrow DockerSource/SystemdSource interfaces the discoverer is
	// configured against expose only read methods (Status/Containers/
	// Container, List) -- there is no enable/apply/mutate method to call, so
	// nothing on the discovery path can enable a monitor. productionCritical
	// is data only; asserting its shape (above) together with the type
	// system's guarantee is the full proof.
	if len(dockerSrc.containerCalls) == 0 {
		t.Fatal("expected the discoverer to have read container details")
	}
}

// --- test cert helper -------------------------------------------------

// generateTestCert builds a minimal leaf certificate signed by a throwaway
// CA so Issuer and Subject differ, PEM-encoded for injection through the
// fake FileReader.
func generateTestCert(t *testing.T, domain, issuerCN string, notAfter time.Time) []byte {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCN},
		NotBefore:             notAfter.AddDate(-1, 0, 0),
		NotAfter:              notAfter.AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notAfter.AddDate(0, -3, 0),
		NotAfter:     notAfter,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}
