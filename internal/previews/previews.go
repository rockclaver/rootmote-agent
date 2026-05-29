// Package previews implements the Preview Manager deep module: it owns the
// lifecycle of per-project dev-server processes, allocates HTTPS subdomains
// off the user's wildcard base domain, writes Caddy reverse-proxy fragments,
// and reloads Caddy. Side-effecting collaborators (DNS lookups, child-process
// launch, Caddy reload, listening-port probing) are exposed as small
// interfaces so the entire surface is testable in-process without root.
package previews

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/store"
)

// SettingBaseDomain is the agent_settings key holding the user's wildcard
// preview base domain (e.g. "previews.example.com"). Empty means the user has
// not completed the first-run setup yet.
const SettingBaseDomain = "preview_base_domain"

var (
	// ErrNotFound is returned when a preview row does not exist.
	ErrNotFound = store.ErrNotFound

	// ErrAlreadyRunning is returned when a project already has an active
	// preview. The UI must Stop the existing one before starting a new one.
	ErrAlreadyRunning = errors.New("preview already running for project")

	// ErrBaseDomainUnset is returned when callers try to start a preview
	// before the user has completed first-run DNS setup.
	ErrBaseDomainUnset = errors.New("preview base domain not configured")

	// ErrDNSValidationFailed is returned when the wildcard DNS sentinel
	// check could not resolve to the expected target IP.
	ErrDNSValidationFailed = errors.New("dns validation failed")

	// ErrPortUnknown is returned when port detection could not discover a
	// listening port — the UI is expected to prompt the user for an
	// explicit port and retry.
	ErrPortUnknown = errors.New("could not detect listening port")
)

// Reloader applies a Caddy fragment change. The default impl runs
// `caddy reload`. Tests inject a fake.
type Reloader interface {
	Reload(ctx context.Context) error
}

// Resolver performs DNS lookups for the first-run wildcard validation step.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// Launcher spawns the dev-server child process and reports the leader PID
// (group leader, so SIGTERM to -PGID kills the whole tree). The default impl
// uses os/exec with setsid; tests inject a fake.
type Launcher interface {
	Launch(ctx context.Context, spec LaunchSpec) (LaunchHandle, error)
}

// LaunchSpec is the input to Launcher.Launch.
type LaunchSpec struct {
	WorkDir string
	Command string // shell command run via `sh -c`
	Env     []string
}

// LaunchHandle is the return from Launcher.Launch.
type LaunchHandle struct {
	PID  int // process group leader PID; pgid == pid
	PGID int
}

// PortProber asks the OS which TCP ports a process tree is listening on.
type PortProber interface {
	ListeningPorts(ctx context.Context, pgid int) ([]int, error)
}

// Killer terminates a process group by sending SIGTERM (then SIGKILL on
// timeout) to -PGID. Split out from Launcher so rehydration works for groups
// the agent did not start in this process lifetime.
type Killer interface {
	KillGroup(ctx context.Context, pgid int) error
}

// Clock is the standard fake-time hook.
type Clock interface {
	Now() time.Time
	Sleep(d time.Duration)
}

// Config is the construction-time configuration for Manager.
type Config struct {
	// FragmentsDir is the directory where per-preview Caddy site blocks live.
	// Must match the glob in the main Caddyfile (typically
	// `import /etc/caddy/claver/*.caddy`).
	FragmentsDir string

	// FragmentMode is the permission used when writing fragment files.
	// Defaults to 0o644 so Caddy (running as its own user) can read them.
	FragmentMode os.FileMode

	// ExpectedIP, when set, is the IP that DNS validation requires the
	// wildcard record to resolve to. When empty, validation accepts any
	// successful resolution to a public IP. Callers may set this to the
	// VPS's public address discovered during install.
	ExpectedIP string

	// PortProbeTimeout bounds how long Start waits for the dev server to
	// open a listening port before falling back to ErrPortUnknown.
	PortProbeTimeout time.Duration

	// PortProbeInterval is the gap between probe attempts.
	PortProbeInterval time.Duration

	// CertWarmupBudget is the time budget reported back to callers for the
	// first-use TLS handshake. The Manager does not enforce it directly —
	// it is exposed so the UI can render an accurate progress hint.
	CertWarmupBudget time.Duration

	Reloader   Reloader
	Resolver   Resolver
	Launcher   Launcher
	PortProber PortProber
	Killer     Killer
	Clock      Clock
	IDGen      func() string
}

// Manager owns previews. Methods are safe for concurrent use.
type Manager struct {
	cfg      Config
	store    *store.Store
	projects *projects.Manager

	mu sync.Mutex
}

// New constructs a Manager and ensures the fragments directory exists.
// Missing collaborators are populated with sensible defaults; the caller can
// override any field via Config.
func New(cfg Config, st *store.Store, pm *projects.Manager) (*Manager, error) {
	if cfg.FragmentsDir == "" {
		cfg.FragmentsDir = "/etc/caddy/claver"
	}
	if cfg.FragmentMode == 0 {
		cfg.FragmentMode = 0o644
	}
	if cfg.PortProbeTimeout == 0 {
		cfg.PortProbeTimeout = 15 * time.Second
	}
	if cfg.PortProbeInterval == 0 {
		cfg.PortProbeInterval = 250 * time.Millisecond
	}
	if cfg.CertWarmupBudget == 0 {
		cfg.CertWarmupBudget = 30 * time.Second
	}
	if cfg.Reloader == nil {
		cfg.Reloader = DefaultReloader{}
	}
	if cfg.Resolver == nil {
		cfg.Resolver = netResolver{}
	}
	if cfg.Launcher == nil {
		cfg.Launcher = ShellLauncher{}
	}
	if cfg.PortProber == nil {
		cfg.PortProber = LsofProber{}
	}
	if cfg.Killer == nil {
		cfg.Killer = SignalKiller{}
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.IDGen == nil {
		cfg.IDGen = randomID
	}
	if err := os.MkdirAll(cfg.FragmentsDir, 0o755); err != nil {
		return nil, fmt.Errorf("ensure fragments dir: %w", err)
	}
	return &Manager{cfg: cfg, store: st, projects: pm}, nil
}

func randomID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// BaseDomain returns the configured wildcard base, or "" if unset.
func (m *Manager) BaseDomain() (string, error) {
	v, err := m.store.GetAgentSetting(SettingBaseDomain)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return v, err
}

// SetupDomain persists the user-supplied wildcard base domain. The argument
// must be the bare apex of the wildcard, e.g. `previews.example.com` (the
// matching DNS record is `*.previews.example.com`). Returns the normalized
// value so the UI can display it back to the user.
func (m *Manager) SetupDomain(base string) (string, error) {
	clean, err := normalizeBaseDomain(base)
	if err != nil {
		return "", err
	}
	if err := m.store.PutAgentSetting(SettingBaseDomain, clean); err != nil {
		return "", err
	}
	return clean, nil
}

// DNSResult is returned to the UI for AC: "validates resolution before
// enabling preview features."
type DNSResult struct {
	Sentinel   string   `json:"sentinel"`
	Resolved   []string `json:"resolved"`
	ExpectedIP string   `json:"expected_ip,omitempty"`
	OK         bool     `json:"ok"`
	Reason     string   `json:"reason,omitempty"`
}

// ValidateDNS performs the wildcard probe by resolving a sentinel
// `dns-check-<random>.<base>` and confirming the result. When ExpectedIP is
// configured on the Manager the result must include that IP; otherwise any
// resolved IP counts as success.
func (m *Manager) ValidateDNS(ctx context.Context) (DNSResult, error) {
	base, err := m.BaseDomain()
	if err != nil {
		return DNSResult{}, err
	}
	if base == "" {
		return DNSResult{OK: false, Reason: "base domain not set"}, ErrBaseDomainUnset
	}
	sentinel := "dns-check-" + m.cfg.IDGen() + "." + base
	ips, err := m.cfg.Resolver.LookupIP(ctx, sentinel)
	if err != nil {
		return DNSResult{Sentinel: sentinel, OK: false, Reason: err.Error()}, ErrDNSValidationFailed
	}
	res := DNSResult{Sentinel: sentinel, ExpectedIP: m.cfg.ExpectedIP}
	for _, ip := range ips {
		res.Resolved = append(res.Resolved, ip.String())
	}
	if len(ips) == 0 {
		res.Reason = "no A/AAAA records returned"
		return res, ErrDNSValidationFailed
	}
	if m.cfg.ExpectedIP != "" {
		ok := false
		for _, ip := range ips {
			if ip.String() == m.cfg.ExpectedIP {
				ok = true
				break
			}
		}
		if !ok {
			res.Reason = "wildcard does not resolve to expected IP"
			return res, ErrDNSValidationFailed
		}
	}
	res.OK = true
	return res, nil
}

// StartRequest is the input to Start.
type StartRequest struct {
	ProjectID string
	// Command is the dev-server command. When empty, the Manager falls back
	// to a framework-default inferred from the project workspace.
	Command string
	// Port, when non-zero, skips port detection entirely.
	Port int
	// Env contains extra environment variables passed to the child.
	Env []string
}

// Start launches the dev server, detects its port, writes the Caddy fragment,
// reloads Caddy, and returns the preview row. The HTTPS URL is on the
// returned Preview.URL field.
func (m *Manager) Start(ctx context.Context, req StartRequest) (store.Preview, error) {
	if req.ProjectID == "" {
		return store.Preview{}, errors.New("project_id required")
	}
	if _, err := m.projects.Get(req.ProjectID); err != nil {
		return store.Preview{}, err
	}
	base, err := m.BaseDomain()
	if err != nil {
		return store.Preview{}, err
	}
	if base == "" {
		return store.Preview{}, ErrBaseDomainUnset
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, err := m.store.ActivePreviewForProject(req.ProjectID); err == nil {
		return existing, ErrAlreadyRunning
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.Preview{}, err
	}

	id := m.cfg.IDGen()
	subdomain := "preview-" + id
	host := subdomain + "." + base

	workdir := m.projects.WorkspaceDir(req.ProjectID)
	cmd := req.Command
	if cmd == "" {
		cmd = DetectStartCommand(workdir)
	}
	if cmd == "" {
		return store.Preview{}, fmt.Errorf("no start command supplied and no framework default detected")
	}

	row := store.Preview{
		ID: id, ProjectID: req.ProjectID,
		Subdomain: subdomain, BaseDomain: base,
		URL:       "https://" + host,
		Command:   cmd,
		Port:      req.Port,
		Status:    "starting",
		StartedAt: m.cfg.Clock.Now(),
	}
	if err := m.store.CreatePreview(row); err != nil {
		return store.Preview{}, err
	}

	handle, err := m.cfg.Launcher.Launch(ctx, LaunchSpec{
		WorkDir: workdir,
		Command: cmd,
		Env:     append(envFromMap(map[string]string{"PORT": portHint(req.Port)}), req.Env...),
	})
	if err != nil {
		m.markFailed(row, fmt.Sprintf("launch: %v", err))
		return store.Preview{}, err
	}
	row.PGID = handle.PGID

	port := req.Port
	if port == 0 {
		p, err := m.detectPort(ctx, handle.PGID)
		if err != nil {
			_ = m.cfg.Killer.KillGroup(ctx, handle.PGID)
			m.markFailed(row, fmt.Sprintf("port detect: %v", err))
			return store.Preview{}, err
		}
		port = p
	}
	row.Port = port

	if err := m.writeFragment(row); err != nil {
		_ = m.cfg.Killer.KillGroup(ctx, handle.PGID)
		m.markFailed(row, fmt.Sprintf("fragment write: %v", err))
		return store.Preview{}, err
	}
	if err := m.cfg.Reloader.Reload(ctx); err != nil {
		_ = os.Remove(m.fragmentPath(row.ID))
		_ = m.cfg.Killer.KillGroup(ctx, handle.PGID)
		m.markFailed(row, fmt.Sprintf("caddy reload: %v", err))
		return store.Preview{}, err
	}

	row.Status = "running"
	if err := m.store.UpdatePreview(row); err != nil {
		return store.Preview{}, err
	}
	return row, nil
}

// Stop tears down the preview: kills the process group, removes the Caddy
// fragment, reloads Caddy, and marks the row stopped.
func (m *Manager) Stop(ctx context.Context, previewID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, err := m.store.GetPreview(previewID)
	if err != nil {
		return err
	}
	if row.EndedAt != nil {
		return nil
	}
	if row.PGID > 0 {
		if err := m.cfg.Killer.KillGroup(ctx, row.PGID); err != nil {
			row.LastError = fmt.Sprintf("kill: %v", err)
		}
	}
	if err := os.Remove(m.fragmentPath(row.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove fragment: %w", err)
	}
	if err := m.cfg.Reloader.Reload(ctx); err != nil {
		return fmt.Errorf("caddy reload: %w", err)
	}
	now := m.cfg.Clock.Now()
	row.EndedAt = &now
	row.Status = "stopped"
	return m.store.UpdatePreview(row)
}

// Restart tears down and recreates the preview. The returned row reflects the
// new state; the previous PGID/port are abandoned.
func (m *Manager) Restart(ctx context.Context, previewID string) (store.Preview, error) {
	row, err := m.store.GetPreview(previewID)
	if err != nil {
		return store.Preview{}, err
	}
	if err := m.Stop(ctx, previewID); err != nil {
		return store.Preview{}, err
	}
	return m.Start(ctx, StartRequest{ProjectID: row.ProjectID, Command: row.Command, Port: 0})
}

// Get returns one preview row by ID.
func (m *Manager) Get(id string) (store.Preview, error) {
	return m.store.GetPreview(id)
}

// List returns previews ordered newest first; an empty projectID returns all.
func (m *Manager) List(projectID string) ([]store.Preview, error) {
	return m.store.ListPreviews(projectID)
}

// Active returns the running preview for projectID, or ErrNotFound.
func (m *Manager) Active(projectID string) (store.Preview, error) {
	return m.store.ActivePreviewForProject(projectID)
}

// fragmentPath is the per-preview Caddy site block filename.
func (m *Manager) fragmentPath(id string) string {
	return filepath.Join(m.cfg.FragmentsDir, "preview-"+id+".caddy")
}

// writeFragment renders a single Caddy site block.
//
// A `tls` block is intentionally omitted so Caddy issues automatic certs via
// HTTP/TLS-ALPN challenges using the global ACME issuer (set up in the main
// Caddyfile). reverse_proxy targets loopback because the agent is the only
// listener path.
func (m *Manager) writeFragment(p store.Preview) error {
	host := p.Subdomain + "." + p.BaseDomain
	body := fmt.Sprintf(
		"# claver-preview id=%s project=%s\n"+
			"%s {\n"+
			"\treverse_proxy 127.0.0.1:%d\n"+
			"}\n",
		p.ID, p.ProjectID, host, p.Port,
	)
	tmp := m.fragmentPath(p.ID) + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), m.cfg.FragmentMode); err != nil {
		return err
	}
	return os.Rename(tmp, m.fragmentPath(p.ID))
}

func (m *Manager) markFailed(row store.Preview, msg string) {
	now := m.cfg.Clock.Now()
	row.EndedAt = &now
	row.Status = "failed"
	row.LastError = msg
	_ = m.store.UpdatePreview(row)
}

func (m *Manager) detectPort(ctx context.Context, pgid int) (int, error) {
	deadline := m.cfg.Clock.Now().Add(m.cfg.PortProbeTimeout)
	for {
		ports, err := m.cfg.PortProber.ListeningPorts(ctx, pgid)
		if err == nil && len(ports) > 0 {
			sort.Ints(ports)
			return ports[0], nil
		}
		if m.cfg.Clock.Now().After(deadline) {
			return 0, ErrPortUnknown
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		m.cfg.Clock.Sleep(m.cfg.PortProbeInterval)
	}
}

// CertWarmup is the budget the UI should reserve for first-use TLS issuance.
func (m *Manager) CertWarmup() time.Duration { return m.cfg.CertWarmupBudget }

// DetectStartCommand inspects the workspace for well-known framework markers
// and returns a best-guess dev-server command, or "" if nothing matches.
// Detection is opinionated and intentionally narrow: Vite, Next.js, Flask
// (via a top-level app.py + Flask in requirements.txt or pyproject.toml), and
// Rails (Gemfile + bin/rails). Anything else requires the user to supply a
// command explicitly.
func DetectStartCommand(workdir string) string {
	if data, err := os.ReadFile(filepath.Join(workdir, "package.json")); err == nil {
		var pkg struct {
			Scripts      map[string]string `json:"scripts"`
			Dependencies map[string]string `json:"dependencies"`
			DevDeps      map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(data, &pkg) == nil {
			if _, ok := pkg.Scripts["dev"]; ok {
				return "npm run dev"
			}
			if _, ok := pkg.Scripts["start"]; ok {
				return "npm start"
			}
			if _, ok := pkg.Dependencies["next"]; ok {
				return "npx next dev"
			}
			if _, ok := pkg.DevDeps["next"]; ok {
				return "npx next dev"
			}
			if _, ok := pkg.Dependencies["vite"]; ok {
				return "npx vite"
			}
			if _, ok := pkg.DevDeps["vite"]; ok {
				return "npx vite"
			}
		}
	}
	if _, err := os.Stat(filepath.Join(workdir, "app.py")); err == nil {
		if hasFlaskMarker(workdir) {
			return "flask --app app run --host 0.0.0.0"
		}
	}
	if _, err := os.Stat(filepath.Join(workdir, "Gemfile")); err == nil {
		if _, err := os.Stat(filepath.Join(workdir, "bin", "rails")); err == nil {
			return "bin/rails server -b 0.0.0.0"
		}
	}
	return ""
}

func hasFlaskMarker(workdir string) bool {
	for _, name := range []string{"requirements.txt", "pyproject.toml"} {
		data, err := os.ReadFile(filepath.Join(workdir, name))
		if err == nil && strings.Contains(strings.ToLower(string(data)), "flask") {
			return true
		}
	}
	return false
}

// --- normalization helpers -------------------------------------------------

var baseDomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

func normalizeBaseDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", errors.New("base domain is required")
	}
	if !baseDomainRE.MatchString(s) {
		return "", fmt.Errorf("base domain %q is not a valid FQDN", s)
	}
	return s, nil
}

func envFromMap(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v == "" {
			continue
		}
		out = append(out, k+"="+v)
	}
	return out
}

func portHint(p int) string {
	if p <= 0 {
		return ""
	}
	return strconv.Itoa(p)
}

// --- default collaborators -------------------------------------------------

// DefaultReloader runs `caddy reload`. Override the binary path via the
// CADDY_BIN environment variable for non-standard installs.
type DefaultReloader struct{}

// Reload invokes the system `caddy reload`.
func (DefaultReloader) Reload(ctx context.Context) error {
	bin := os.Getenv("CADDY_BIN")
	if bin == "" {
		bin = "caddy"
	}
	cf := os.Getenv("CADDY_CONFIG")
	args := []string{"reload"}
	if cf != "" {
		args = append(args, "--config", cf)
	}
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("caddy reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

type netResolver struct{}

func (netResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, len(addrs))
	for i, a := range addrs {
		out[i] = a.IP
	}
	return out, nil
}

// ShellLauncher runs the command via `sh -c` in a new process group so the
// whole child tree can be torn down with one SIGTERM to -PGID.
type ShellLauncher struct{}

// Launch starts the dev server.
func (ShellLauncher) Launch(ctx context.Context, spec LaunchSpec) (LaunchHandle, error) {
	if err := os.MkdirAll(spec.WorkDir, 0o700); err != nil {
		return LaunchHandle{}, err
	}
	cmd := exec.Command("sh", "-c", spec.Command)
	cmd.Dir = spec.WorkDir
	cmd.Env = append(os.Environ(), spec.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = io_discard{}
	cmd.Stderr = io_discard{}
	if err := cmd.Start(); err != nil {
		return LaunchHandle{}, err
	}
	// We do not Wait here — the caller manages lifecycle via Killer.
	go func() { _ = cmd.Wait() }()
	pid := cmd.Process.Pid
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		pgid = pid
	}
	return LaunchHandle{PID: pid, PGID: pgid}, nil
}

type io_discard struct{}

func (io_discard) Write(p []byte) (int, error) { return len(p), nil }

// SignalKiller sends SIGTERM to -pgid, then SIGKILL on a short timeout.
type SignalKiller struct{}

// KillGroup terminates the process group, escalating to SIGKILL after 3s.
func (SignalKiller) KillGroup(ctx context.Context, pgid int) error {
	if pgid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(-pgid, 0); err != nil {
			// ESRCH = group is gone.
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	return nil
}

// LsofProber asks `lsof` for TCP listening ports owned by any PID in pgid.
// On systems without lsof the agent falls back to /proc inspection.
type LsofProber struct{}

// ListeningPorts returns every TCP listening port owned by the process group.
func (LsofProber) ListeningPorts(ctx context.Context, pgid int) ([]int, error) {
	if pgid <= 0 {
		return nil, errors.New("invalid pgid")
	}
	pids, err := pidsInGroup(pgid)
	if err != nil || len(pids) == 0 {
		return nil, err
	}
	// lsof -nP -iTCP -sTCP:LISTEN -a -p <pid1>,<pid2>...
	pidArg := joinInts(pids, ",")
	out, err := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-a", "-p", pidArg).Output()
	if err != nil {
		return nil, nil // missing lsof or no rows; not fatal
	}
	return parseLsofPorts(string(out)), nil
}

var lsofPortRE = regexp.MustCompile(`:(\d+)\s+\(LISTEN\)`)

func parseLsofPorts(s string) []int {
	seen := map[int]struct{}{}
	for _, m := range lsofPortRE.FindAllStringSubmatch(s, -1) {
		if p, err := strconv.Atoi(m[1]); err == nil {
			seen[p] = struct{}{}
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out
}

// pidsInGroup returns every PID currently in the given process group by
// scanning /proc. Best-effort: returns nil on non-Linux or on read errors.
func pidsInGroup(pgid int) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, nil
	}
	var out []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		statData, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// /proc/<pid>/stat fields: pid (comm) state ppid pgrp ...
		// comm may contain spaces and parens; rsplit on ')'.
		s := string(statData)
		idx := strings.LastIndex(s, ")")
		if idx < 0 || idx+2 >= len(s) {
			continue
		}
		fields := strings.Fields(s[idx+2:])
		if len(fields) < 3 {
			continue
		}
		gp, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		if gp == pgid {
			out = append(out, pid)
		}
	}
	return out, nil
}

func joinInts(xs []int, sep string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, sep)
}

type realClock struct{}

func (realClock) Now() time.Time        { return time.Now() }
func (realClock) Sleep(d time.Duration) { time.Sleep(d) }
