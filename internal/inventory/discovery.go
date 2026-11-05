package inventory

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/webserver"
)

// DiscoveryReport is a point-in-time, read-only inventory of everything the
// agent can observe about the host: OS/kernel, capacity, disks, Docker and
// Compose, systemd units, reverse proxies, listening ports, inferred
// databases, public domains, TLS certificates and their expiry, and recent
// restart history. It also carries a suggestion-only list of the services
// that look production-critical — nothing here enables a monitor.
type DiscoveryReport struct {
	CapturedAt         time.Time               `json:"capturedAt"`
	OS                 OSInfo                  `json:"os"`
	Capacity           CapacityInfo            `json:"capacity"`
	Disks              []DiskInfo              `json:"disks"`
	Docker             DockerInfo              `json:"docker"`
	SystemdUnits       []SystemdUnitInfo       `json:"systemdUnits"`
	ReverseProxies     []ReverseProxyInfo      `json:"reverseProxies"`
	ListeningPorts     []ListeningPortInfo     `json:"listeningPorts"`
	Databases          []DatabaseInfo          `json:"databases"`
	DatabaseUnits      []DatabaseUnitInfo      `json:"databaseUnits"`
	PM2Apps            []PM2AppInfo            `json:"pm2Apps"`
	PHPFPMUnits        []string                `json:"phpFpmUnits"`
	SupervisorPrograms []SupervisorProgramInfo `json:"supervisorPrograms"`
	Certs              []CertInfo              `json:"certs"`
	PublicDomains      []string                `json:"publicDomains"`
	TLSCertificates    []TLSCertificateInfo    `json:"tlsCertificates"`
	RestartHistory     []RestartEntry          `json:"restartHistory"`
	ProductionCritical []string                `json:"productionCritical"`
	Warnings           []string                `json:"warnings"`
}

// OSInfo describes the host operating system.
type OSInfo struct {
	Platform string `json:"platform"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// CapacityInfo is the coarse capacity summary derived from the infra sample.
type CapacityInfo struct {
	CPUCores         int     `json:"cpuCores"`
	MemoryTotalBytes uint64  `json:"memoryTotalBytes"`
	SwapTotalBytes   uint64  `json:"swapTotalBytes"`
	LoadOne          float64 `json:"loadOne"`
}

// DiskInfo is one mounted filesystem's usage.
type DiskInfo struct {
	Mountpoint   string  `json:"mountpoint"`
	Filesystem   string  `json:"filesystem,omitempty"`
	TotalBytes   uint64  `json:"totalBytes"`
	UsedBytes    uint64  `json:"usedBytes"`
	Percent      float64 `json:"percent"`
	InodePercent float64 `json:"inodePercent"`
}

// DockerContainerInfo is one container's discovery-relevant subset.
type DockerContainerInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Image          string `json:"image"`
	State          string `json:"state"`
	Health         string `json:"health,omitempty"`
	RestartCount   int    `json:"restartCount"`
	ComposeProject string `json:"composeProject,omitempty"`
	ComposeService string `json:"composeService,omitempty"`
}

// DockerInfo is the Docker/Compose section of the report.
type DockerInfo struct {
	Available       bool                  `json:"available"`
	Version         string                `json:"version,omitempty"`
	Containers      []DockerContainerInfo `json:"containers"`
	ComposeProjects []string              `json:"composeProjects"`
}

// SystemdUnitInfo is one systemd unit's discovery-relevant subset.
type SystemdUnitInfo struct {
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	ActiveState     string    `json:"activeState,omitempty"`
	SubState        string    `json:"subState,omitempty"`
	EnabledOnBoot   bool      `json:"enabledOnBoot"`
	RestartCount    int       `json:"restartCount"`
	ActiveEnteredAt time.Time `json:"activeEnteredAt"`
}

// ReverseProxyInfo is one detected reverse-proxy installation.
type ReverseProxyInfo struct {
	Kind        string   `json:"kind"`
	Unit        string   `json:"unit,omitempty"`
	ActiveState string   `json:"activeState,omitempty"`
	Domains     []string `json:"domains"`
}

// ListeningPortInfo is one TCP listener discovered on the host.
type ListeningPortInfo struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Process  string `json:"process,omitempty"`
	PID      int    `json:"pid,omitempty"`
}

// DatabaseInfo is one inferred database instance.
type DatabaseInfo struct {
	Engine string `json:"engine"`
	Source string `json:"source"`
	Target string `json:"target"`
	Port   int    `json:"port,omitempty"`
}

// TLSCertificateInfo is one discovered TLS certificate's expiry state.
type TLSCertificateInfo struct {
	Domain        string    `json:"domain,omitempty"`
	Issuer        string    `json:"issuer,omitempty"`
	NotAfter      time.Time `json:"notAfter"`
	DaysRemaining int       `json:"daysRemaining"`
	Path          string    `json:"path"`
	ChainError    string    `json:"chainError,omitempty"`
}

// RestartEntry is one docker container or systemd unit with a nonzero
// restart count.
type RestartEntry struct {
	Kind          string    `json:"kind"`
	Target        string    `json:"target"`
	Restarts      int       `json:"restarts"`
	LastRestartAt time.Time `json:"lastRestartAt,omitempty"`
}

// Runner executes a host command and returns its combined output. It is the
// injectable seam for every exec.Command call the discovery scan makes.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// FileReader reads a file's contents. It is the injectable seam for every
// direct file read the discovery scan makes (os-release, TLS certificates).
type FileReader func(path string) ([]byte, error)

// Globber expands a glob pattern to matching paths. It is the injectable
// seam used to locate TLS certificate files.
type Globber func(pattern string) ([]string, error)

// InfraSampler is the narrow view of *infra.Manager the discovery scan needs.
type InfraSampler interface {
	Sample(ctx context.Context) infra.HostMetrics
}

// DockerSource is the narrow view of *docker.Manager the discovery scan
// needs. Container is used per-container to read restart counts and
// published ports, which Manager.Containers does not include.
type DockerSource interface {
	Status(ctx context.Context) docker.Status
	Containers(ctx context.Context) ([]docker.ContainerSummary, error)
	Container(ctx context.Context, id string) (docker.ContainerDetail, error)
}

// SystemdSource is the narrow view of *systemd.Manager the discovery scan
// needs.
type SystemdSource interface {
	List(ctx context.Context) ([]systemd.Unit, error)
}

// WebserverSource is the narrow view of *webserver.Manager the discovery
// scan needs.
type WebserverSource interface {
	List(ctx context.Context) webserver.Snapshot
}

// DiscoveryConfig wires the discovery scan's data sources and exec/file
// seams. Docker, Systemd, and Webserver are optional (nil-safe): a missing
// source degrades into a warning rather than a panic.
type DiscoveryConfig struct {
	Infra     InfraSampler
	Docker    DockerSource
	Systemd   SystemdSource
	Webserver WebserverSource
	Run       Runner
	ReadFile  FileReader
	Glob      Globber
	Now       func() time.Time
	// Priv runs `rootmote-agent priv <action> <args...>` and returns its
	// stdout. Nil means the helper is not available.
	Priv func(ctx context.Context, action string, args ...string) ([]byte, error)
}

// Discoverer runs the read-only host discovery scan.
type Discoverer struct {
	cfg DiscoveryConfig
}

// NewDiscoverer constructs a Discoverer, defaulting Run/ReadFile/Glob/Now to
// their real host implementations.
func NewDiscoverer(cfg DiscoveryConfig) *Discoverer {
	if cfg.Run == nil {
		cfg.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	if cfg.ReadFile == nil {
		cfg.ReadFile = os.ReadFile
	}
	if cfg.Glob == nil {
		cfg.Glob = filepath.Glob
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Discoverer{cfg: cfg}
}

// Discover runs every collector and returns the assembled report. The scan
// is strictly read-only: no writes, no installs, no service actions. Every
// collector degrades independently into warnings rather than failing the
// whole scan.
func (d *Discoverer) Discover(ctx context.Context) DiscoveryReport {
	report := DiscoveryReport{
		CapturedAt:         d.cfg.Now().UTC(),
		Disks:              []DiskInfo{},
		SystemdUnits:       []SystemdUnitInfo{},
		ReverseProxies:     []ReverseProxyInfo{},
		ListeningPorts:     []ListeningPortInfo{},
		Databases:          []DatabaseInfo{},
		DatabaseUnits:      []DatabaseUnitInfo{},
		PM2Apps:            []PM2AppInfo{},
		PHPFPMUnits:        []string{},
		SupervisorPrograms: []SupervisorProgramInfo{},
		Certs:              []CertInfo{},
		PublicDomains:      []string{},
		TLSCertificates:    []TLSCertificateInfo{},
		RestartHistory:     []RestartEntry{},
		ProductionCritical: []string{},
		Warnings:           []string{},
	}
	report.Docker.Containers = []DockerContainerInfo{}
	report.Docker.ComposeProjects = []string{}

	d.discoverOS(ctx, &report)
	d.discoverCapacity(ctx, &report)
	details := d.discoverDocker(ctx, &report)
	d.discoverSystemd(ctx, &report)
	d.discoverWebserver(ctx, &report)
	d.discoverListeningPorts(ctx, &report)
	d.discoverDatabases(&report)
	d.discoverStack(ctx, &report)
	d.discoverTLS(ctx, &report)
	d.discoverRestartHistory(&report)
	d.discoverProductionCritical(&report, details)

	return report
}

func (d *Discoverer) warn(report *DiscoveryReport, format string, args ...any) {
	report.Warnings = append(report.Warnings, fmt.Sprintf(format, args...))
}

// --- os --------------------------------------------------------------------

func (d *Discoverer) discoverOS(ctx context.Context, report *DiscoveryReport) {
	info := OSInfo{Platform: runtime.GOOS}

	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	} else {
		d.warn(report, "hostname unavailable: %v", err)
	}

	switch runtime.GOOS {
	case "linux":
		if b, err := d.cfg.ReadFile("/etc/os-release"); err == nil {
			info.Name, info.Version = parseOSRelease(b)
		} else {
			d.warn(report, "os-release unavailable: %v", err)
		}
	case "darwin":
		if out, err := d.cfg.Run(ctx, "sw_vers", "-productName"); err == nil {
			info.Name = strings.TrimSpace(string(out))
		} else {
			d.warn(report, "sw_vers product name unavailable: %v", err)
		}
		if out, err := d.cfg.Run(ctx, "sw_vers", "-productVersion"); err == nil {
			info.Version = strings.TrimSpace(string(out))
		} else {
			d.warn(report, "sw_vers product version unavailable: %v", err)
		}
	}

	if out, err := d.cfg.Run(ctx, "uname", "-r"); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	} else {
		d.warn(report, "kernel version unavailable: %v", err)
	}
	if out, err := d.cfg.Run(ctx, "uname", "-m"); err == nil {
		info.Arch = strings.TrimSpace(string(out))
	} else {
		d.warn(report, "architecture unavailable: %v", err)
	}

	report.OS = info
}

func parseOSRelease(b []byte) (name, version string) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "NAME="):
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		case strings.HasPrefix(line, "VERSION_ID="):
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	return name, version
}

// --- capacity + disks --------------------------------------------------

func (d *Discoverer) discoverCapacity(ctx context.Context, report *DiscoveryReport) {
	report.Capacity.CPUCores = runtime.NumCPU()
	if d.cfg.Infra == nil {
		d.warn(report, "capacity unavailable: infra sampler not configured")
		return
	}
	sample := d.cfg.Infra.Sample(ctx)
	report.Capacity.MemoryTotalBytes = sample.Memory.TotalBytes
	report.Capacity.SwapTotalBytes = sample.Swap.TotalBytes
	report.Capacity.LoadOne = sample.Load.One

	disks := make([]DiskInfo, 0, len(sample.Disks))
	for _, disk := range sample.Disks {
		if !disk.Available {
			continue
		}
		disks = append(disks, DiskInfo{
			Mountpoint:   disk.Mountpoint,
			Filesystem:   disk.Filesystem,
			TotalBytes:   disk.TotalBytes,
			UsedBytes:    disk.UsedBytes,
			Percent:      disk.Percent,
			InodePercent: disk.InodePercent,
		})
	}
	report.Disks = disks
}

// --- docker ------------------------------------------------------------

// discoverDocker fills report.Docker and returns the per-container inspect
// detail (keyed by container id) collected along the way, so later
// collectors (production-critical) can read published ports without a
// second round of calls.
func (d *Discoverer) discoverDocker(ctx context.Context, report *DiscoveryReport) map[string]docker.ContainerDetail {
	if d.cfg.Docker == nil {
		d.warn(report, "docker unavailable: docker source not configured")
		return nil
	}
	status := d.cfg.Docker.Status(ctx)
	report.Docker.Available = status.Available
	report.Docker.Version = status.Version
	if !status.Available {
		if status.UnavailableMessage != "" {
			d.warn(report, "docker unavailable: %s", status.UnavailableMessage)
		} else {
			d.warn(report, "docker unavailable")
		}
		return nil
	}

	containers, err := d.cfg.Docker.Containers(ctx)
	if err != nil {
		d.warn(report, "docker containers unavailable: %v", err)
		return nil
	}

	details := make(map[string]docker.ContainerDetail, len(containers))
	detailFailed := false
	for _, c := range containers {
		detail, derr := d.cfg.Docker.Container(ctx, c.ID)
		if derr != nil {
			detailFailed = true
			continue
		}
		details[c.ID] = detail
	}
	if detailFailed {
		d.warn(report, "docker container restart counts unavailable for one or more containers")
	}

	projectSet := map[string]struct{}{}
	infos := make([]DockerContainerInfo, 0, len(containers))
	for _, c := range containers {
		restartCount := 0
		if detail, ok := details[c.ID]; ok {
			restartCount = detail.RestartCount
		}
		infos = append(infos, DockerContainerInfo{
			ID:             c.ID,
			Name:           c.Name,
			Image:          c.Image,
			State:          c.State,
			Health:         c.Health,
			RestartCount:   restartCount,
			ComposeProject: c.ComposeProject,
			ComposeService: c.ComposeService,
		})
		if c.ComposeProject != "" {
			projectSet[c.ComposeProject] = struct{}{}
		}
	}
	report.Docker.Containers = infos

	projects := make([]string, 0, len(projectSet))
	for p := range projectSet {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	report.Docker.ComposeProjects = projects

	return details
}

// --- systemd -------------------------------------------------------------

func (d *Discoverer) discoverSystemd(ctx context.Context, report *DiscoveryReport) {
	if d.cfg.Systemd == nil {
		d.warn(report, "systemd unavailable: systemd source not configured")
		return
	}
	units, err := d.cfg.Systemd.List(ctx)
	if err != nil {
		d.warn(report, "systemd units unavailable: %v", err)
		return
	}

	infos := make([]SystemdUnitInfo, 0, len(units))
	showFailed := false
	for _, u := range units {
		info := SystemdUnitInfo{
			Name:          u.Name,
			Description:   u.Description,
			ActiveState:   u.ActiveState,
			SubState:      u.SubState,
			EnabledOnBoot: u.EnabledOnBoot == "enabled",
		}
		restarts, enteredAt, serr := d.systemdUnitShow(ctx, u.Name)
		if serr != nil {
			showFailed = true
		} else {
			info.RestartCount = restarts
			info.ActiveEnteredAt = enteredAt
		}
		infos = append(infos, info)
	}
	if showFailed {
		d.warn(report, "systemd restart counts unavailable for one or more units")
	}
	report.SystemdUnits = infos
}

func (d *Discoverer) systemdUnitShow(ctx context.Context, unit string) (restarts int, enteredAt time.Time, err error) {
	out, err := d.cfg.Run(ctx, "systemctl", "show", "-p", "NRestarts", "-p", "ActiveEnterTimestamp", "--value", unit)
	if err != nil {
		return 0, time.Time{}, err
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) > 0 {
		if n, perr := strconv.Atoi(strings.TrimSpace(lines[0])); perr == nil {
			restarts = n
		}
	}
	if len(lines) > 1 {
		enteredAt = parseSystemdTimestamp(strings.TrimSpace(lines[1]))
	}
	return restarts, enteredAt, nil
}

func parseSystemdTimestamp(s string) time.Time {
	if s == "" || s == "n/a" {
		return time.Time{}
	}
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// --- reverse proxies + public domains -------------------------------------

func (d *Discoverer) discoverWebserver(ctx context.Context, report *DiscoveryReport) {
	if d.cfg.Webserver == nil {
		d.warn(report, "reverse proxies unavailable: webserver source not configured")
		return
	}
	snap := d.cfg.Webserver.List(ctx)
	if !snap.Available {
		if len(snap.Warnings) > 0 {
			d.warn(report, "reverse proxies unavailable: %s", strings.Join(snap.Warnings, "; "))
		} else {
			d.warn(report, "reverse proxies unavailable")
		}
		return
	}

	proxies := make([]ReverseProxyInfo, 0, len(snap.Webservers))
	domainSet := map[string]struct{}{}
	for _, inst := range snap.Webservers {
		domains := make([]string, 0, len(inst.Domains))
		for _, dom := range inst.Domains {
			domains = append(domains, dom.Host)
			domainSet[dom.Host] = struct{}{}
		}
		proxies = append(proxies, ReverseProxyInfo{
			Kind:        string(inst.Kind),
			Unit:        inst.Unit,
			ActiveState: inst.ActiveState,
			Domains:     domains,
		})
	}
	report.ReverseProxies = proxies

	domains := make([]string, 0, len(domainSet))
	for dom := range domainSet {
		domains = append(domains, dom)
	}
	sort.Strings(domains)
	report.PublicDomains = domains
}

// --- listening ports ---------------------------------------------------

var ssProcessRe = regexp.MustCompile(`\(\("([^"]+)",pid=(\d+)`)

func (d *Discoverer) discoverListeningPorts(ctx context.Context, report *DiscoveryReport) {
	out, err := d.cfg.Run(ctx, "ss", "-ltnpH")
	if err == nil {
		report.ListeningPorts = parseSSOutput(string(out))
		return
	}
	if out2, err2 := d.cfg.Run(ctx, "netstat", "-an"); err2 == nil {
		report.ListeningPorts = parseNetstatOutput(string(out2))
		return
	}
	d.warn(report, "listening ports unavailable: %v", err)
}

func parseSSOutput(raw string) []ListeningPortInfo {
	var ports []ListeningPortInfo
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		if info, ok := parseSSLine(sc.Text()); ok {
			ports = append(ports, info)
		}
	}
	return ports
}

func parseSSLine(line string) (ListeningPortInfo, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || !strings.EqualFold(fields[0], "LISTEN") {
		return ListeningPortInfo{}, false
	}
	addr, port, ok := splitHostPort(fields[3])
	if !ok {
		return ListeningPortInfo{}, false
	}
	info := ListeningPortInfo{Address: addr, Port: port, Protocol: "tcp"}
	if len(fields) >= 6 {
		info.Process, info.PID = parseSSProcess(fields[5])
	}
	return info, true
}

func parseSSProcess(s string) (string, int) {
	m := ssProcessRe.FindStringSubmatch(s)
	if m == nil {
		return "", 0
	}
	pid, _ := strconv.Atoi(m[2])
	return m[1], pid
}

func splitHostPort(s string) (string, int, bool) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", 0, false
	}
	host := strings.TrimSuffix(strings.TrimPrefix(s[:idx], "["), "]")
	port, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0, false
	}
	return host, port, true
}

func parseNetstatOutput(raw string) []ListeningPortInfo {
	var ports []ListeningPortInfo
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		if info, ok := parseNetstatLine(sc.Text()); ok {
			ports = append(ports, info)
		}
	}
	return ports
}

func parseNetstatLine(line string) (ListeningPortInfo, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return ListeningPortInfo{}, false
	}
	if !strings.HasPrefix(strings.ToLower(fields[0]), "tcp") {
		return ListeningPortInfo{}, false
	}
	if !strings.EqualFold(fields[len(fields)-1], "LISTEN") {
		return ListeningPortInfo{}, false
	}
	addr, port, ok := splitHostPortNetstat(fields[3])
	if !ok {
		return ListeningPortInfo{}, false
	}
	return ListeningPortInfo{Address: addr, Port: port, Protocol: "tcp"}, true
}

// splitHostPortNetstat accepts both Linux ("addr:port") and BSD-style
// ("addr.port", with "*" for the wildcard address) netstat local-address
// formats.
func splitHostPortNetstat(s string) (string, int, bool) {
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		if port, err := strconv.Atoi(s[idx+1:]); err == nil {
			return s[:idx], port, true
		}
	}
	if idx := strings.LastIndex(s, "."); idx >= 0 {
		if port, err := strconv.Atoi(s[idx+1:]); err == nil {
			host := s[:idx]
			if host == "*" {
				host = "0.0.0.0"
			}
			return host, port, true
		}
	}
	return "", 0, false
}

// --- databases -----------------------------------------------------------

var dbNamePatterns = []struct {
	pattern string
	engine  string
}{
	{"postgres", "postgres"},
	{"mysql", "mysql"},
	{"mariadb", "mariadb"},
	{"redis", "redis"},
	{"mongo", "mongo"},
}

var dbPorts = map[int]string{
	5432:  "postgres",
	3306:  "mysql",
	6379:  "redis",
	27017: "mongo",
}

func (d *Discoverer) discoverDatabases(report *DiscoveryReport) {
	type key struct{ engine, target string }
	seen := map[key]bool{}
	dbs := []DatabaseInfo{}
	add := func(engine, source, target string, port int) {
		k := key{engine, target}
		if seen[k] {
			return
		}
		seen[k] = true
		dbs = append(dbs, DatabaseInfo{Engine: engine, Source: source, Target: target, Port: port})
	}

	for _, c := range report.Docker.Containers {
		lower := strings.ToLower(c.Image)
		for _, p := range dbNamePatterns {
			if strings.Contains(lower, p.pattern) {
				add(p.engine, "docker", c.Name, 0)
				break
			}
		}
	}
	for _, u := range report.SystemdUnits {
		lower := strings.ToLower(u.Name)
		for _, p := range dbNamePatterns {
			if strings.Contains(lower, p.pattern) {
				add(p.engine, "systemd", u.Name, 0)
				break
			}
		}
	}
	for _, lp := range report.ListeningPorts {
		if engine, ok := dbPorts[lp.Port]; ok {
			add(engine, "port", lp.Address, lp.Port)
		}
	}

	sort.Slice(dbs, func(i, j int) bool {
		if dbs[i].Engine != dbs[j].Engine {
			return dbs[i].Engine < dbs[j].Engine
		}
		return dbs[i].Target < dbs[j].Target
	})
	report.Databases = dbs
}

// --- TLS certificates --------------------------------------------------

var tlsGlobPatterns = []string{
	"/var/lib/caddy/.local/share/caddy/certificates/**/*.crt",
}

func (d *Discoverer) discoverTLS(ctx context.Context, report *DiscoveryReport) {
	certs := d.discoverLetsEncrypt(ctx, report)
	if certs == nil {
		certs = []TLSCertificateInfo{}
	}

	var paths []string
	for _, pattern := range tlsGlobPatterns {
		matches, err := d.cfg.Glob(pattern)
		if err != nil {
			d.warn(report, "tls certificate glob %s failed: %v", pattern, err)
			continue
		}
		paths = append(paths, matches...)
	}
	sort.Strings(paths)

	for _, path := range paths {
		cert, err := d.parseCertFile(path)
		if err != nil {
			certs = append(certs, TLSCertificateInfo{Path: path, ChainError: err.Error()})
			continue
		}
		certs = append(certs, cert)
	}
	report.TLSCertificates = certs
}

func (d *Discoverer) parseCertFile(path string) (TLSCertificateInfo, error) {
	raw, err := d.cfg.ReadFile(path)
	if err != nil {
		return TLSCertificateInfo{}, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return TLSCertificateInfo{}, errors.New("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return TLSCertificateInfo{}, err
	}

	domain := cert.Subject.CommonName
	if len(cert.DNSNames) > 0 {
		domain = cert.DNSNames[0]
	}
	now := d.cfg.Now()
	info := TLSCertificateInfo{
		Domain:        domain,
		Issuer:        cert.Issuer.CommonName,
		NotAfter:      cert.NotAfter,
		DaysRemaining: int(cert.NotAfter.Sub(now).Hours() / 24),
		Path:          path,
	}
	if now.After(cert.NotAfter) {
		info.ChainError = "certificate expired"
	}
	return info, nil
}

// --- restart history -------------------------------------------------------

func (d *Discoverer) discoverRestartHistory(report *DiscoveryReport) {
	entries := []RestartEntry{}
	for _, c := range report.Docker.Containers {
		if c.RestartCount > 0 {
			entries = append(entries, RestartEntry{Kind: "docker", Target: c.Name, Restarts: c.RestartCount})
		}
	}
	for _, u := range report.SystemdUnits {
		if u.RestartCount > 0 {
			entries = append(entries, RestartEntry{
				Kind: "systemd", Target: u.Name, Restarts: u.RestartCount, LastRestartAt: u.ActiveEnteredAt,
			})
		}
	}
	report.RestartHistory = entries
}

// --- production-critical suggestions ----------------------------------

// discoverProductionCritical builds a SUGGESTION-only list of services that
// look production-critical: running docker containers that publish a port
// or belong to a compose project, active reverse-proxy and database systemd
// units, and every discovered public domain. Nothing here enables a
// monitor.
func (d *Discoverer) discoverProductionCritical(report *DiscoveryReport, details map[string]docker.ContainerDetail) {
	seen := map[string]bool{}
	out := []string{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	for _, c := range report.Docker.Containers {
		if c.State != "running" {
			continue
		}
		published := false
		if detail, ok := details[c.ID]; ok {
			for _, p := range detail.Ports {
				if p.PublicPort > 0 {
					published = true
					break
				}
			}
		}
		if published || c.ComposeProject != "" {
			add("docker/" + c.Name)
		}
	}

	proxyUnits := map[string]bool{}
	for _, rp := range report.ReverseProxies {
		if rp.Unit != "" {
			proxyUnits[rp.Unit] = true
		}
	}
	for _, u := range report.SystemdUnits {
		if u.ActiveState != "active" {
			continue
		}
		isDB := false
		lower := strings.ToLower(u.Name)
		for _, p := range dbNamePatterns {
			if strings.Contains(lower, p.pattern) {
				isDB = true
				break
			}
		}
		if isDB || proxyUnits[u.Name] {
			add("systemd/" + u.Name)
		}
	}

	for _, dom := range report.PublicDomains {
		add("https://" + dom)
	}

	report.ProductionCritical = out
}
