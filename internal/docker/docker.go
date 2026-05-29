// Package docker implements the Docker Manager deep module. Phase 1 exposes
// only daemon-availability detection; later phases extend the same Manager
// with container/image/volume/network reads and guarded lifecycle actions.
//
// The Manager talks to Docker exclusively through a small Client interface so
// agent tests can drive every unavailable state (missing, daemon down,
// permission denied) without a real Docker socket.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Unavailable reason codes returned in Status.UnavailableReason. Stable
// machine-readable strings — the UI maps these to copy.
const (
	ReasonNotInstalled     = "not_installed"
	ReasonDaemonDown       = "daemon_down"
	ReasonPermissionDenied = "permission_denied"
	ReasonUnknown          = "unknown"
)

// Typed errors a Client may return. The Manager classifies any other error
// as ReasonUnknown.
var (
	ErrNotInstalled     = errors.New("docker: not installed")
	ErrDaemonDown       = errors.New("docker: daemon unreachable")
	ErrPermissionDenied = errors.New("docker: permission denied")
)

// VersionInfo is the subset of the Docker /version response the agent needs
// for Phase 1.
type VersionInfo struct {
	Version    string
	APIVersion string
}

// Client is the agent's narrow view of the Docker Engine. Real callers get a
// HTTP-over-unix-socket client; tests pass a fake.
type Client interface {
	Version(ctx context.Context) (VersionInfo, error)
	Containers(ctx context.Context) ([]ContainerSummary, error)
	Container(ctx context.Context, id string) (ContainerDetail, error)
}

// Status is the typed daemon status returned by Manager.Status.
type Status struct {
	Available          bool   `json:"available"`
	Version            string `json:"version,omitempty"`
	APIVersion         string `json:"api_version,omitempty"`
	UnavailableReason  string `json:"unavailable_reason,omitempty"`
	UnavailableMessage string `json:"unavailable_message,omitempty"`
}

// Config configures the Manager.
type Config struct {
	// Client probes the Docker daemon. Required.
	Client Client
	// ProjectRoot is the agent workspace root. When set, container mounts under
	// this directory are mapped back to a Claver project id on a best-effort
	// basis.
	ProjectRoot string
}

// Manager is the Docker deep module. Phase 1 exposes only Status; later
// phases bolt container/image/volume/network reads onto the same type.
type Manager struct {
	client      Client
	projectRoot string
}

// New constructs a Manager backed by client. client must be non-nil.
func New(cfg Config) (*Manager, error) {
	if cfg.Client == nil {
		return nil, errors.New("docker: Client is required")
	}
	return &Manager{client: cfg.Client, projectRoot: cfg.ProjectRoot}, nil
}

// Status probes the Docker daemon and returns a typed availability snapshot.
// It never returns an error: every failure mode collapses into an unavailable
// Status with a machine-readable reason.
func (m *Manager) Status(ctx context.Context) Status {
	v, err := m.client.Version(ctx)
	if err == nil {
		return Status{
			Available:  true,
			Version:    v.Version,
			APIVersion: v.APIVersion,
		}
	}
	return Status{
		Available:          false,
		UnavailableReason:  classify(err),
		UnavailableMessage: err.Error(),
	}
}

// ContainerSummary is the compact shape returned by Manager.Containers.
type ContainerSummary struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Image          string            `json:"image"`
	Status         string            `json:"status"`
	State          string            `json:"state"`
	Health         string            `json:"health,omitempty"`
	PortsSummary   string            `json:"ports_summary,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	ComposeProject string            `json:"compose_project,omitempty"`
	ComposeService string            `json:"compose_service,omitempty"`
	Managed        bool              `json:"managed"`
	ProjectID      string            `json:"project_id,omitempty"`
	Mounts         []MountSummary    `json:"-"`
}

// ContainerDetail is the safe inspect subset returned by Manager.Container.
type ContainerDetail struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	Command         string            `json:"command,omitempty"`
	Status          string            `json:"status"`
	State           string            `json:"state"`
	Health          string            `json:"health,omitempty"`
	Ports           []PortSummary     `json:"ports,omitempty"`
	Mounts          []MountSummary    `json:"mounts,omitempty"`
	RestartPolicy   string            `json:"restart_policy,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	ComposeProject  string            `json:"compose_project,omitempty"`
	ComposeService  string            `json:"compose_service,omitempty"`
	Managed         bool              `json:"managed"`
	ProjectID       string            `json:"project_id,omitempty"`
	EnvironmentVars []EnvSummary      `json:"environment_summary,omitempty"`
}

type PortSummary struct {
	PrivatePort int    `json:"private_port"`
	PublicPort  int    `json:"public_port,omitempty"`
	Type        string `json:"type,omitempty"`
	IP          string `json:"ip,omitempty"`
}

type MountSummary struct {
	Type        string `json:"type,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	ReadOnly    bool   `json:"read_only,omitempty"`
}

type EnvSummary struct {
	Key      string `json:"key"`
	Value    string `json:"value,omitempty"`
	Redacted bool   `json:"redacted"`
}

// Containers returns every local container from Docker, including stopped
// containers, with grouping fields derived only from labels/inspect metadata.
func (m *Manager) Containers(ctx context.Context) ([]ContainerSummary, error) {
	cs, err := m.client.Containers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range cs {
		m.enrichSummary(&cs[i])
	}
	return cs, nil
}

// Container returns a safe subset of docker inspect for a single container.
func (m *Manager) Container(ctx context.Context, id string) (ContainerDetail, error) {
	if strings.TrimSpace(id) == "" {
		return ContainerDetail{}, errors.New("docker: container id required")
	}
	d, err := m.client.Container(ctx, id)
	if err != nil {
		return ContainerDetail{}, err
	}
	m.enrichDetail(&d)
	return d, nil
}

func (m *Manager) enrichSummary(c *ContainerSummary) {
	c.ComposeProject = composeProject(c.Labels)
	c.ComposeService = composeService(c.Labels)
	c.Managed = c.ComposeProject != "" || c.ComposeService != ""
	c.ProjectID = projectID(c.Labels, m.projectRoot, c.Mounts)
}

func (m *Manager) enrichDetail(d *ContainerDetail) {
	d.ComposeProject = composeProject(d.Labels)
	d.ComposeService = composeService(d.Labels)
	d.Managed = d.ComposeProject != "" || d.ComposeService != ""
	d.ProjectID = projectID(d.Labels, m.projectRoot, d.Mounts)
}

func composeProject(labels map[string]string) string {
	if labels == nil {
		return ""
	}
	return labels["com.docker.compose.project"]
}

func composeService(labels map[string]string) string {
	if labels == nil {
		return ""
	}
	return labels["com.docker.compose.service"]
}

func projectID(labels map[string]string, root string, mounts []MountSummary) string {
	for _, key := range []string{"claver.project_id", "com.claver.project_id"} {
		if labels != nil && labels[key] != "" {
			return labels[key]
		}
	}
	root = strings.TrimRight(root, "/")
	if root == "" {
		return ""
	}
	prefix := root + "/"
	for _, m := range mounts {
		if strings.HasPrefix(m.Source, prefix) {
			rest := strings.TrimPrefix(m.Source, prefix)
			if id, _, ok := strings.Cut(rest, "/"); ok && id != "" {
				return id
			}
			if rest != "" {
				return rest
			}
		}
	}
	return ""
}

func classify(err error) string {
	switch {
	case errors.Is(err, ErrNotInstalled):
		return ReasonNotInstalled
	case errors.Is(err, ErrPermissionDenied):
		return ReasonPermissionDenied
	case errors.Is(err, ErrDaemonDown):
		return ReasonDaemonDown
	}
	return ReasonUnknown
}

// DefaultSocketPath is the Docker Engine unix socket on Linux installs.
const DefaultSocketPath = "/var/run/docker.sock"

// SocketClient is the production Client implementation. It speaks HTTP over a
// Unix socket. Errors are translated into the package-typed sentinels so the
// Manager can classify them.
type SocketClient struct {
	socketPath string
	httpc      *http.Client
}

// NewSocketClient returns a SocketClient bound to socketPath. If socketPath is
// empty, DefaultSocketPath is used.
func NewSocketClient(socketPath string) *SocketClient {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	return &SocketClient{
		socketPath: socketPath,
		httpc:      &http.Client{Transport: tr, Timeout: 5 * time.Second},
	}
}

// Version calls GET /version on the Docker socket and maps every connection
// failure mode into one of the package-typed errors.
func (c *SocketClient) Version(ctx context.Context) (VersionInfo, error) {
	// A missing socket is ambiguous: dockerd removes /var/run/docker.sock
	// when it stops, so ENOENT does not prove Docker is uninstalled. Only
	// claim "not installed" when neither the socket nor a `docker` binary
	// on PATH is present; otherwise prefer the daemon-down classification.
	if fi, err := os.Stat(c.socketPath); err != nil {
		switch {
		case errors.Is(err, os.ErrPermission):
			return VersionInfo{}, fmt.Errorf("%w: stat %s: %v", ErrPermissionDenied, c.socketPath, err)
		case os.IsNotExist(err):
			if _, lookErr := exec.LookPath("docker"); lookErr != nil {
				return VersionInfo{}, fmt.Errorf("%w: %s missing and docker binary not found", ErrNotInstalled, c.socketPath)
			}
			return VersionInfo{}, fmt.Errorf("%w: %s missing (daemon likely stopped)", ErrDaemonDown, c.socketPath)
		default:
			return VersionInfo{}, err
		}
	} else if fi.IsDir() {
		return VersionInfo{}, fmt.Errorf("%w: %s is a directory", ErrNotInstalled, c.socketPath)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/version", nil)
	if err != nil {
		return VersionInfo{}, err
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return VersionInfo{}, translateDialError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return VersionInfo{}, fmt.Errorf("%w: docker returned %d", ErrPermissionDenied, resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		return VersionInfo{}, fmt.Errorf("%w: docker returned %d", ErrDaemonDown, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return VersionInfo{}, fmt.Errorf("docker: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return VersionInfo{}, fmt.Errorf("docker: decode /version: %w", err)
	}
	return VersionInfo{Version: body.Version, APIVersion: body.APIVersion}, nil
}

// Containers calls GET /containers/json?all=1 and maps the Docker API payload
// into the agent's stable summary shape.
func (c *SocketClient) Containers(ctx context.Context) ([]ContainerSummary, error) {
	var raw []struct {
		ID      string        `json:"Id"`
		Names   []string      `json:"Names"`
		Image   string        `json:"Image"`
		Command string        `json:"Command"`
		State   string        `json:"State"`
		Status  string        `json:"Status"`
		Ports   []PortSummary `json:"Ports"`
		Mounts  []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
		Labels map[string]string `json:"Labels"`
	}
	if err := c.getJSON(ctx, "/containers/json?all=1", &raw); err != nil {
		return nil, err
	}
	out := make([]ContainerSummary, 0, len(raw))
	for _, r := range raw {
		mounts := make([]MountSummary, 0, len(r.Mounts))
		for _, m := range r.Mounts {
			mounts = append(mounts, MountSummary{
				Type:        m.Type,
				Source:      m.Source,
				Destination: m.Destination,
				ReadOnly:    !m.RW,
			})
		}
		out = append(out, ContainerSummary{
			ID:           r.ID,
			Name:         firstName(r.Names),
			Image:        r.Image,
			Status:       r.Status,
			State:        r.State,
			Health:       healthFromStatus(r.Status),
			PortsSummary: portsSummary(r.Ports),
			Labels:       composeLabels(r.Labels),
			Mounts:       mounts,
		})
	}
	return out, nil
}

// Container calls GET /containers/{id}/json and redacts environment values.
func (c *SocketClient) Container(ctx context.Context, id string) (ContainerDetail, error) {
	var raw struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Image  string            `json:"Image"`
			Cmd    []string          `json:"Cmd"`
			Env    []string          `json:"Env"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		State struct {
			Status string `json:"Status"`
			Health *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
		NetworkSettings struct {
			Ports map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"Ports"`
		} `json:"NetworkSettings"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
		HostConfig struct {
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
		} `json:"HostConfig"`
	}
	if err := c.getJSON(ctx, "/containers/"+id+"/json", &raw); err != nil {
		return ContainerDetail{}, err
	}
	ports := make([]PortSummary, 0, len(raw.NetworkSettings.Ports))
	for key, bindings := range raw.NetworkSettings.Ports {
		private, typ := parsePortKey(key)
		if len(bindings) == 0 {
			ports = append(ports, PortSummary{PrivatePort: private, Type: typ})
			continue
		}
		for _, b := range bindings {
			ports = append(ports, PortSummary{
				PrivatePort: private,
				PublicPort:  atoi(b.HostPort),
				Type:        typ,
				IP:          b.HostIP,
			})
		}
	}
	mounts := make([]MountSummary, 0, len(raw.Mounts))
	for _, m := range raw.Mounts {
		mounts = append(mounts, MountSummary{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Destination,
			ReadOnly:    !m.RW,
		})
	}
	health := ""
	if raw.State.Health != nil {
		health = raw.State.Health.Status
	}
	return ContainerDetail{
		ID:              raw.ID,
		Name:            strings.TrimPrefix(raw.Name, "/"),
		Image:           raw.Config.Image,
		Command:         strings.Join(raw.Config.Cmd, " "),
		Status:          raw.State.Status,
		State:           raw.State.Status,
		Health:          health,
		Ports:           ports,
		Mounts:          mounts,
		RestartPolicy:   raw.HostConfig.RestartPolicy.Name,
		Labels:          composeLabels(raw.Config.Labels),
		EnvironmentVars: redactEnv(raw.Config.Env),
	}, nil
}

func (c *SocketClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return translateDialError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w: docker returned %d", ErrPermissionDenied, resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("%w: docker returned %d", ErrDaemonDown, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("docker: unexpected status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("docker: decode %s: %w", path, err)
	}
	return nil
}

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

func composeLabels(labels map[string]string) map[string]string {
	keep := map[string]string{}
	for _, k := range []string{
		"com.docker.compose.project",
		"com.docker.compose.service",
		"com.docker.compose.oneoff",
		"claver.project_id",
		"com.claver.project_id",
	} {
		if labels != nil && labels[k] != "" {
			keep[k] = labels[k]
		}
	}
	if len(keep) == 0 {
		return nil
	}
	return keep
}

func portsSummary(ports []PortSummary) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		target := fmt.Sprintf("%d/%s", p.PrivatePort, p.Type)
		if p.PublicPort > 0 {
			target = fmt.Sprintf("%d->%s", p.PublicPort, target)
		}
		parts = append(parts, target)
	}
	return strings.Join(parts, ", ")
}

func healthFromStatus(status string) string {
	start := strings.Index(status, "(health: ")
	if start < 0 {
		return ""
	}
	rest := status[start+len("(health: "):]
	end := strings.Index(rest, ")")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func parsePortKey(key string) (int, string) {
	port, typ, _ := strings.Cut(key, "/")
	return atoi(port), typ
}

func atoi(s string) int {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func redactEnv(env []string) []EnvSummary {
	out := make([]EnvSummary, 0, len(env))
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		redacted := isSecretKey(key)
		if redacted {
			value = "REDACTED"
		}
		out = append(out, EnvSummary{Key: key, Value: value, Redacted: redacted})
	}
	return out
}

func isSecretKey(key string) bool {
	k := strings.ToUpper(key)
	for _, needle := range []string{"SECRET", "TOKEN", "PASSWORD", "PASS", "KEY", "CREDENTIAL"} {
		if strings.Contains(k, needle) {
			return true
		}
	}
	return false
}

func translateDialError(err error) error {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
		// A bare ENOENT at dial time also means a missing socket; treat
		// it as daemon-down to avoid mislabelling a stopped daemon as
		// uninstalled (see the os.Stat branch above for the reasoning).
		return fmt.Errorf("%w: %v", ErrDaemonDown, err)
	}
	// Fall back to substring sniffing for wrapped net errors that don't
	// preserve the underlying syscall through errors.Is.
	msg := err.Error()
	switch {
	case strings.Contains(msg, "permission denied"):
		return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
	case strings.Contains(msg, "no such file"),
		strings.Contains(msg, "connection refused"):
		return fmt.Errorf("%w: %v", ErrDaemonDown, err)
	}
	return err
}
