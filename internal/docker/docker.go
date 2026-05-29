// Package docker implements the Docker Manager deep module. Phase 1 exposes
// only daemon-availability detection; later phases extend the same Manager
// with container/image/volume/network reads and guarded lifecycle actions.
//
// The Manager talks to Docker exclusively through a small Client interface so
// agent tests can drive every unavailable state (missing, daemon down,
// permission denied) without a real Docker socket.
package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	Images(ctx context.Context) ([]ImageSummary, error)
	Image(ctx context.Context, id string) (ImageDetail, error)
	Volumes(ctx context.Context) ([]VolumeSummary, error)
	Networks(ctx context.Context) ([]NetworkSummary, error)
	Info(ctx context.Context) (DaemonInfo, error)
	ContainerLogs(ctx context.Context, id string, tail int) ([]LogEntry, error)
	ContainerLogStream(ctx context.Context, id string, since time.Time, emit func(LogEntry)) error
	ContainerStats(ctx context.Context, id string) (StatsSample, error)
	ContainerStatsStream(ctx context.Context, id string, emit func(StatsSample)) error
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

// ImageSummary is the read-only image inventory row.
type ImageSummary struct {
	ID         string            `json:"id"`
	Tags       []string          `json:"tags,omitempty"`
	Digests    []string          `json:"digests,omitempty"`
	Created    int64             `json:"created"`
	Size       int64             `json:"size"`
	Labels     map[string]string `json:"labels,omitempty"`
	Containers int               `json:"containers"`
}

// ImageDetail is the safe inspect subset for a single image.
type ImageDetail struct {
	ImageSummary
	Architecture string   `json:"architecture,omitempty"`
	OS           string   `json:"os,omitempty"`
	Author       string   `json:"author,omitempty"`
	Comment      string   `json:"comment,omitempty"`
	ParentID     string   `json:"parent_id,omitempty"`
	RepoDigests  []string `json:"repo_digests,omitempty"`
}

// VolumeSummary is the read-only volume inventory row.
type VolumeSummary struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint,omitempty"`
	Scope      string            `json:"scope,omitempty"`
	CreatedAt  string            `json:"created_at,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	// InUseCount is a best-effort hint computed from container mounts. -1
	// means the daemon did not report usage data.
	InUseCount int `json:"in_use_count"`
}

// NetworkSummary is the read-only network inventory row.
type NetworkSummary struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Driver        string            `json:"driver"`
	Scope         string            `json:"scope,omitempty"`
	Internal      bool              `json:"internal,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	AttachedCount int               `json:"attached_count"`
}

// DaemonInfo is the read-only daemon-level inventory snapshot.
type DaemonInfo struct {
	Containers        int    `json:"containers"`
	ContainersRunning int    `json:"containers_running"`
	ContainersPaused  int    `json:"containers_paused"`
	ContainersStopped int    `json:"containers_stopped"`
	Images            int    `json:"images"`
	ServerVersion     string `json:"server_version,omitempty"`
	OperatingSystem   string `json:"operating_system,omitempty"`
	Architecture      string `json:"architecture,omitempty"`
	KernelVersion     string `json:"kernel_version,omitempty"`
}

// LogEntry is one container log line with Docker stream/timestamp metadata when
// Docker exposes it. Timestamp is RFC3339Nano text to keep the wire format
// stable across Go/Dart.
type LogEntry struct {
	ContainerID string `json:"container_id"`
	Stream      string `json:"stream"`
	Timestamp   string `json:"timestamp,omitempty"`
	Line        string `json:"line"`
}

// StatsSample is one raw datapoint from Docker's /containers/{id}/stats stream.
// The Manager converts it into a StatsSnapshot; tests build samples by hand to
// exercise the calculation without Docker.
type StatsSample struct {
	Read     string                  `json:"read"`
	CPU      StatsCPU                `json:"cpu_stats"`
	PreCPU   StatsCPU                `json:"precpu_stats"`
	Memory   StatsMemory             `json:"memory_stats"`
	Networks map[string]StatsNetwork `json:"networks"`
}

// StatsCPU mirrors Docker's cpu_stats / precpu_stats subset the agent needs.
type StatsCPU struct {
	CPUUsage struct {
		TotalUsage  uint64   `json:"total_usage"`
		PercpuUsage []uint64 `json:"percpu_usage,omitempty"`
	} `json:"cpu_usage"`
	SystemCPUUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs     uint32 `json:"online_cpus"`
}

// StatsMemory mirrors Docker's memory_stats subset.
type StatsMemory struct {
	Usage uint64            `json:"usage"`
	Limit uint64            `json:"limit"`
	Stats map[string]uint64 `json:"stats,omitempty"`
}

// StatsNetwork mirrors per-interface rx/tx byte counters.
type StatsNetwork struct {
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// StatsSnapshot is the computed, wire-stable shape returned by Manager.Stats
// and emitted on every SubscribeStats tick. Available distinguishes "no
// stats available" (stopped container, missing memory limit) from a real
// zero-usage sample so the UI does not collapse the two.
type StatsSnapshot struct {
	ContainerID       string  `json:"container_id"`
	Timestamp         string  `json:"timestamp,omitempty"`
	Available         bool    `json:"available"`
	UnavailableReason string  `json:"unavailable_reason,omitempty"`
	CPUPercent        float64 `json:"cpu_percent"`
	MemUsageBytes     uint64  `json:"mem_usage_bytes"`
	MemLimitBytes     uint64  `json:"mem_limit_bytes"`
	MemPercent        float64 `json:"mem_percent"`
	NetRxBytes        uint64  `json:"net_rx_bytes"`
	NetTxBytes        uint64  `json:"net_tx_bytes"`
}

// StatsUnavailableStopped is the reason emitted when Docker returns a stats
// payload with a zero memory limit — the documented signal that the container
// is no longer running.
const StatsUnavailableStopped = "stopped"

// Stats samples Docker once and returns the computed snapshot. Samples are
// never persisted; the agent forwards each call straight to the daemon.
func (m *Manager) Stats(ctx context.Context, id string) (StatsSnapshot, error) {
	if strings.TrimSpace(id) == "" {
		return StatsSnapshot{}, errors.New("docker: container id required")
	}
	sample, err := m.client.ContainerStats(ctx, id)
	if err != nil {
		return StatsSnapshot{}, err
	}
	return computeStatsSnapshot(id, sample), nil
}

// SubscribeStats follows the Docker stats stream and invokes emit with a
// computed snapshot per Docker sample. The call returns when ctx is cancelled
// or the daemon closes the stream.
func (m *Manager) SubscribeStats(ctx context.Context, id string, emit func(StatsSnapshot)) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("docker: container id required")
	}
	if emit == nil {
		return errors.New("docker: stats emit callback required")
	}
	return m.client.ContainerStatsStream(ctx, id, func(sample StatsSample) {
		emit(computeStatsSnapshot(id, sample))
	})
}

// computeStatsSnapshot folds a raw Docker sample into the wire-stable
// snapshot shape. The CPU/memory math mirrors the algorithm used by the
// `docker stats` CLI so values match what operators see in a terminal.
func computeStatsSnapshot(id string, s StatsSample) StatsSnapshot {
	snap := StatsSnapshot{ContainerID: id, Timestamp: s.Read, Available: true}

	// Docker emits a stats body with limit=0 for stopped containers. Treat
	// that as the explicit "unavailable" signal rather than reporting zero
	// usage, so the UI can show a distinct message.
	if s.Memory.Limit == 0 {
		snap.Available = false
		snap.UnavailableReason = StatsUnavailableStopped
		return snap
	}

	cpuDelta := float64(s.CPU.CPUUsage.TotalUsage) - float64(s.PreCPU.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPU.SystemCPUUsage) - float64(s.PreCPU.SystemCPUUsage)
	online := float64(s.CPU.OnlineCPUs)
	if online == 0 {
		online = float64(len(s.CPU.CPUUsage.PercpuUsage))
	}
	if online == 0 {
		online = 1
	}
	if cpuDelta > 0 && sysDelta > 0 {
		snap.CPUPercent = (cpuDelta / sysDelta) * online * 100.0
	}

	used := s.Memory.Usage
	// Match the docker CLI: subtract page cache when reported. cgroup v1
	// exposes it as "cache"; cgroup v2 reports "inactive_file".
	if cache, ok := s.Memory.Stats["cache"]; ok && cache <= used {
		used -= cache
	} else if inactive, ok := s.Memory.Stats["inactive_file"]; ok && inactive <= used {
		used -= inactive
	}
	snap.MemUsageBytes = used
	snap.MemLimitBytes = s.Memory.Limit
	snap.MemPercent = float64(used) / float64(s.Memory.Limit) * 100.0

	for _, n := range s.Networks {
		snap.NetRxBytes += n.RxBytes
		snap.NetTxBytes += n.TxBytes
	}

	return snap
}

// Images returns every local image with safe metadata.
func (m *Manager) Images(ctx context.Context) ([]ImageSummary, error) {
	return m.client.Images(ctx)
}

// Image returns inspect-level safe metadata for a single image.
func (m *Manager) Image(ctx context.Context, id string) (ImageDetail, error) {
	if strings.TrimSpace(id) == "" {
		return ImageDetail{}, errors.New("docker: image id required")
	}
	return m.client.Image(ctx, id)
}

// Volumes returns every local volume with usage hints when available.
func (m *Manager) Volumes(ctx context.Context) ([]VolumeSummary, error) {
	return m.client.Volumes(ctx)
}

// Networks returns every local network with attached-container counts when
// the daemon reports them.
func (m *Manager) Networks(ctx context.Context) ([]NetworkSummary, error) {
	return m.client.Networks(ctx)
}

// Info returns the daemon-level inventory snapshot from Docker /info.
func (m *Manager) Info(ctx context.Context) (DaemonInfo, error) {
	return m.client.Info(ctx)
}

const (
	DefaultLogTail = 200
	MaxLogTail     = 500
)

// Logs returns a bounded recent log tail for a container.
func (m *Manager) Logs(ctx context.Context, id string, tail int) ([]LogEntry, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("docker: container id required")
	}
	if tail <= 0 {
		tail = DefaultLogTail
	}
	if tail > MaxLogTail {
		tail = MaxLogTail
	}
	return m.client.ContainerLogs(ctx, id, tail)
}

// SubscribeLogs streams follow-up log lines after the current view. Docker does
// not provide a durable sequence number, so resume is timestamp-based.
func (m *Manager) SubscribeLogs(ctx context.Context, id string, since time.Time, emit func(LogEntry)) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("docker: container id required")
	}
	if emit == nil {
		return errors.New("docker: log emit callback required")
	}
	return m.client.ContainerLogStream(ctx, id, since, emit)
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
	streamc    *http.Client
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
		streamc:    &http.Client{Transport: tr},
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

// ContainerLogs calls Docker's logs endpoint with a bounded tail. It requests
// stdout, stderr, and timestamps; stream tags are decoded from Docker's
// multiplexed log framing when available.
func (c *SocketClient) ContainerLogs(ctx context.Context, id string, tail int) ([]LogEntry, error) {
	entries := []LogEntry{}
	err := c.readLogs(ctx, id, logQuery(tail, false, time.Time{}), c.httpc, func(e LogEntry) {
		entries = append(entries, e)
	})
	return entries, err
}

// ContainerLogStream follows Docker logs from since until the response ends or
// ctx is cancelled.
func (c *SocketClient) ContainerLogStream(ctx context.Context, id string, since time.Time, emit func(LogEntry)) error {
	return c.readLogs(ctx, id, logQuery(0, true, since), c.streamc, emit)
}

func logQuery(tail int, follow bool, since time.Time) string {
	q := url.Values{}
	q.Set("stdout", "1")
	q.Set("stderr", "1")
	q.Set("timestamps", "1")
	if follow {
		q.Set("follow", "1")
		if !since.IsZero() {
			q.Set("since", fmt.Sprintf("%d", since.Unix()))
		}
	} else {
		q.Set("tail", fmt.Sprintf("%d", tail))
	}
	return q.Encode()
}

func (c *SocketClient) readLogs(ctx context.Context, id, query string, client *http.Client, emit func(LogEntry)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+id+"/logs?"+query, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
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
	return decodeDockerLogs(resp.Body, id, emit)
}

// ContainerStats calls Docker's stats endpoint in non-streaming mode and
// returns a single sample. The non-streaming endpoint already returns the
// previous-sample fields in precpu_stats, so callers can compute CPU%
// without keeping per-id state on the agent.
func (c *SocketClient) ContainerStats(ctx context.Context, id string) (StatsSample, error) {
	var sample StatsSample
	if err := c.getJSON(ctx, "/containers/"+id+"/stats?stream=0&one-shot=1", &sample); err != nil {
		return StatsSample{}, err
	}
	return sample, nil
}

// ContainerStatsStream follows /containers/{id}/stats until ctx is cancelled.
// Docker streams a newline-delimited JSON object per sample (~1 Hz); each one
// already carries precpu_stats so emit fires per Docker tick.
func (c *SocketClient) ContainerStatsStream(ctx context.Context, id string, emit func(StatsSample)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+id+"/stats?stream=1", nil)
	if err != nil {
		return err
	}
	resp, err := c.streamc.Do(req)
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
	dec := json.NewDecoder(resp.Body)
	for {
		var sample StatsSample
		if err := dec.Decode(&sample); err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		emit(sample)
	}
}

// Images calls GET /images/json and maps it into the agent's stable summary.
func (c *SocketClient) Images(ctx context.Context) ([]ImageSummary, error) {
	var raw []struct {
		ID          string            `json:"Id"`
		RepoTags    []string          `json:"RepoTags"`
		RepoDigests []string          `json:"RepoDigests"`
		Created     int64             `json:"Created"`
		Size        int64             `json:"Size"`
		Labels      map[string]string `json:"Labels"`
		Containers  int               `json:"Containers"`
	}
	// Pass all=1 so intermediate/child images (e.g. layers left from local
	// multi-stage builds) are included in the inventory rather than silently
	// omitted by the default top-level filter.
	if err := c.getJSON(ctx, "/images/json?all=1", &raw); err != nil {
		return nil, err
	}
	out := make([]ImageSummary, 0, len(raw))
	for _, r := range raw {
		containers := r.Containers
		// Docker reports -1 when usage data is not computed; keep the
		// sentinel so the UI can distinguish unknown from zero.
		out = append(out, ImageSummary{
			ID:         r.ID,
			Tags:       dropNoneTags(r.RepoTags),
			Digests:    r.RepoDigests,
			Created:    r.Created,
			Size:       r.Size,
			Labels:     r.Labels,
			Containers: containers,
		})
	}
	return out, nil
}

// Image calls GET /images/{id}/json for full inspect metadata.
func (c *SocketClient) Image(ctx context.Context, id string) (ImageDetail, error) {
	var raw struct {
		ID           string   `json:"Id"`
		RepoTags     []string `json:"RepoTags"`
		RepoDigests  []string `json:"RepoDigests"`
		Parent       string   `json:"Parent"`
		Comment      string   `json:"Comment"`
		Created      string   `json:"Created"`
		Author       string   `json:"Author"`
		Architecture string   `json:"Architecture"`
		Os           string   `json:"Os"`
		Size         int64    `json:"Size"`
		Config       struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := c.getJSON(ctx, "/images/"+id+"/json", &raw); err != nil {
		return ImageDetail{}, err
	}
	created, _ := time.Parse(time.RFC3339Nano, raw.Created)
	return ImageDetail{
		ImageSummary: ImageSummary{
			ID:      raw.ID,
			Tags:    dropNoneTags(raw.RepoTags),
			Digests: raw.RepoDigests,
			Created: created.Unix(),
			Size:    raw.Size,
			Labels:  raw.Config.Labels,
		},
		Architecture: raw.Architecture,
		OS:           raw.Os,
		Author:       raw.Author,
		Comment:      raw.Comment,
		ParentID:     raw.Parent,
		RepoDigests:  raw.RepoDigests,
	}, nil
}

// Volumes calls GET /volumes and folds in usage data when the daemon
// computes it; otherwise sets InUseCount to -1.
func (c *SocketClient) Volumes(ctx context.Context) ([]VolumeSummary, error) {
	var raw struct {
		Volumes []struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			Mountpoint string            `json:"Mountpoint"`
			CreatedAt  string            `json:"CreatedAt"`
			Scope      string            `json:"Scope"`
			Labels     map[string]string `json:"Labels"`
			UsageData  *struct {
				RefCount int64 `json:"RefCount"`
			} `json:"UsageData"`
		} `json:"Volumes"`
	}
	if err := c.getJSON(ctx, "/volumes", &raw); err != nil {
		return nil, err
	}
	out := make([]VolumeSummary, 0, len(raw.Volumes))
	for _, v := range raw.Volumes {
		count := -1
		if v.UsageData != nil {
			count = int(v.UsageData.RefCount)
		}
		out = append(out, VolumeSummary{
			Name:       v.Name,
			Driver:     v.Driver,
			Mountpoint: v.Mountpoint,
			Scope:      v.Scope,
			CreatedAt:  v.CreatedAt,
			Labels:     v.Labels,
			InUseCount: count,
		})
	}
	return out, nil
}

// Networks calls GET /networks and counts attached containers from the
// payload when present.
func (c *SocketClient) Networks(ctx context.Context) ([]NetworkSummary, error) {
	var raw []struct {
		ID         string                 `json:"Id"`
		Name       string                 `json:"Name"`
		Driver     string                 `json:"Driver"`
		Scope      string                 `json:"Scope"`
		Internal   bool                   `json:"Internal"`
		Labels     map[string]string      `json:"Labels"`
		Containers map[string]interface{} `json:"Containers"`
	}
	if err := c.getJSON(ctx, "/networks", &raw); err != nil {
		return nil, err
	}
	out := make([]NetworkSummary, 0, len(raw))
	for _, n := range raw {
		out = append(out, NetworkSummary{
			ID:            n.ID,
			Name:          n.Name,
			Driver:        n.Driver,
			Scope:         n.Scope,
			Internal:      n.Internal,
			Labels:        n.Labels,
			AttachedCount: len(n.Containers),
		})
	}
	return out, nil
}

// Info calls GET /info and maps the daemon-level inventory snapshot.
func (c *SocketClient) Info(ctx context.Context) (DaemonInfo, error) {
	var raw struct {
		Containers        int    `json:"Containers"`
		ContainersRunning int    `json:"ContainersRunning"`
		ContainersPaused  int    `json:"ContainersPaused"`
		ContainersStopped int    `json:"ContainersStopped"`
		Images            int    `json:"Images"`
		ServerVersion     string `json:"ServerVersion"`
		OperatingSystem   string `json:"OperatingSystem"`
		Architecture      string `json:"Architecture"`
		KernelVersion     string `json:"KernelVersion"`
	}
	if err := c.getJSON(ctx, "/info", &raw); err != nil {
		return DaemonInfo{}, err
	}
	return DaemonInfo{
		Containers:        raw.Containers,
		ContainersRunning: raw.ContainersRunning,
		ContainersPaused:  raw.ContainersPaused,
		ContainersStopped: raw.ContainersStopped,
		Images:            raw.Images,
		ServerVersion:     raw.ServerVersion,
		OperatingSystem:   raw.OperatingSystem,
		Architecture:      raw.Architecture,
		KernelVersion:     raw.KernelVersion,
	}, nil
}

func dropNoneTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := tags[:0:0]
	for _, t := range tags {
		if t == "<none>:<none>" || t == "" {
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func decodeDockerLogs(r io.Reader, containerID string, emit func(LogEntry)) error {
	br := bufio.NewReader(r)
	for {
		header, err := br.Peek(8)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return decodeRawLogLines(br, containerID, "stdout", emit)
		}
		stream := streamName(header[0])
		size := binary.BigEndian.Uint32(header[4:8])
		if stream == "" || size == 0 {
			return decodeRawLogLines(br, containerID, "stdout", emit)
		}
		if _, err := br.Discard(8); err != nil {
			return err
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			return err
		}
		emitLogChunk(containerID, stream, string(buf), emit)
	}
}

func decodeRawLogLines(r io.Reader, containerID, stream string, emit func(LogEntry)) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		emitLogChunk(containerID, stream, scanner.Text()+"\n", emit)
	}
	return scanner.Err()
}

func emitLogChunk(containerID, stream, chunk string, emit func(LogEntry)) {
	for _, line := range strings.SplitAfter(chunk, "\n") {
		if line == "" {
			continue
		}
		text := strings.TrimSuffix(line, "\n")
		timestamp := ""
		if ts, rest, ok := strings.Cut(text, " "); ok {
			if _, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				timestamp = ts
				text = rest
			}
		}
		emit(LogEntry{
			ContainerID: containerID,
			Stream:      stream,
			Timestamp:   timestamp,
			Line:        text,
		})
	}
}

func streamName(code byte) string {
	switch code {
	case 1:
		return "stdout"
	case 2:
		return "stderr"
	default:
		return ""
	}
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
	for _, needle := range []string{
		"SECRET",
		"TOKEN",
		"PASSWORD",
		"PASS",
		"KEY",
		"CREDENTIAL",
		"URL",
		"URI",
		"DSN",
	} {
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
