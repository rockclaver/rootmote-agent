package server

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/steps"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/webserver"
)

// StepsDeps are the host managers the step catalog runs against.
type StepsDeps struct {
	Systemd *systemd.Manager
	Docker  *docker.Manager
	// Priv runs privilege-helper actions for root steps.
	Priv steps.PrivCaller
	// URLs decides which web addresses check.http may request.
	URLs *URLAllowlist
}

// NewStepsEnv wires the production step environment.
func NewStepsEnv(d StepsDeps) *steps.Env {
	env := &steps.Env{
		Priv:  d.Priv,
		Procs: &steps.OSHost{},
		HTTP:  httpGetter{},
	}
	if d.Systemd != nil {
		env.Units = unitsAdapter{m: d.Systemd}
	}
	if d.Docker != nil {
		env.Docker = dockerAdapter{m: d.Docker}
	}
	if d.URLs != nil {
		env.AllowedURL = d.URLs.Allowed
	}
	env.DiskPercentAt = func(_ context.Context, path string) (float64, error) {
		return steps.DiskPercentAtPath(path)
	}
	return env
}

type unitsAdapter struct{ m *systemd.Manager }

func (u unitsAdapter) Action(ctx context.Context, unit, verb string) error {
	return u.m.Action(ctx, unit, systemd.Action(verb))
}

func (u unitsAdapter) Status(ctx context.Context, unit string) (steps.UnitStatus, error) {
	d, err := u.m.Get(ctx, unit)
	if err != nil {
		return steps.UnitStatus{}, err
	}
	return steps.UnitStatus{LoadState: d.LoadState, ActiveState: d.ActiveState, SubState: d.SubState, NRestarts: d.NRestarts}, nil
}

type dockerAdapter struct{ m *docker.Manager }

func (a dockerAdapter) Containers(ctx context.Context) ([]steps.ContainerInfo, error) {
	list, err := a.m.Containers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]steps.ContainerInfo, 0, len(list))
	for _, c := range list {
		info := steps.ContainerInfo{
			ID: c.ID, Name: c.Name, State: c.State, Health: c.Health,
			ComposeProject: c.ComposeProject, ComposeService: c.ComposeService, Labels: c.Labels,
		}
		if d, err := a.m.Container(ctx, c.ID); err == nil {
			info.RestartCount = d.RestartCount
		}
		out = append(out, info)
	}
	return out, nil
}

func (a dockerAdapter) Restart(ctx context.Context, id string) error {
	return a.m.ContainerAction(ctx, id, docker.ActionRestart)
}

func (a dockerAdapter) Start(ctx context.Context, id string) error {
	return a.m.ContainerAction(ctx, id, docker.ActionStart)
}

// RootDir asks Docker where it keeps its data (`docker info`).
func (a dockerAdapter) RootDir(ctx context.Context) (string, error) {
	info, err := a.m.Info(ctx)
	if err != nil {
		return "", err
	}
	return info.RootDir, nil
}

// PruneDangling removes dangling images and unused build cache. It never
// touches volumes or containers.
func (a dockerAdapter) PruneDangling(ctx context.Context) (int64, error) {
	var freed int64
	img, err := a.m.PruneImages(ctx)
	if err != nil {
		return 0, err
	}
	freed += img.FreedBytes
	cache, err := a.m.PruneBuildCache(ctx)
	if err != nil {
		return freed, err
	}
	return freed + cache.FreedBytes, nil
}

// httpGetter makes one GET request. Redirects are not followed, so a 3xx
// answer counts as "the address answers" and the request can never leave
// the allowed host.
type httpGetter struct{}

func (httpGetter) Get(ctx context.Context, rawURL string) (int, error) {
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// URLAllowlist decides which web addresses check.http may request: this
// machine itself (localhost, its host name), the domains its web servers
// serve (from discovery), and the hosts of the monitors the user configured.
type URLAllowlist struct {
	Webservers *webserver.Manager

	mu          sync.RWMutex
	monitors    map[string]bool
	monitorURLs []string
	hostname    string
}

// NewURLAllowlist builds an allowlist; ws may be nil.
func NewURLAllowlist(ws *webserver.Manager) *URLAllowlist {
	h, _ := os.Hostname()
	return &URLAllowlist{Webservers: ws, monitors: map[string]bool{}, hostname: strings.ToLower(h)}
}

// SetMonitorTargets replaces the monitor-derived hosts. Each target may be a
// URL or a bare host (with an optional port).
func (a *URLAllowlist) SetMonitorTargets(targets []string) {
	hosts := map[string]bool{}
	var urls []string
	for _, t := range targets {
		h := hostOf(t)
		if h == "" {
			continue
		}
		hosts[h] = true
		if strings.Contains(t, "://") {
			urls = append(urls, strings.TrimSpace(t))
		} else {
			urls = append(urls, "https://"+h+"/")
		}
	}
	a.mu.Lock()
	a.monitors = hosts
	a.monitorURLs = urls
	a.mu.Unlock()
}

// MonitorURLs returns the web addresses of the user's web monitors. A bare
// host becomes an https address.
func (a *URLAllowlist) MonitorURLs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.monitorURLs))
	out = append(out, a.monitorURLs...)
	return out
}

func hostOf(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if !strings.Contains(t, "://") {
		t = "//" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// Allowed reports whether rawURL points at this machine.
func (a *URLAllowlist) Allowed(rawURL string) bool {
	host := hostOf(rawURL)
	if host == "" {
		return false
	}
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	if host == a.hostname {
		return true
	}
	a.mu.RLock()
	ok := a.monitors[host]
	a.mu.RUnlock()
	if ok {
		return true
	}
	if a.Webservers != nil {
		for _, inst := range a.Webservers.List(context.Background()).Webservers {
			for _, d := range inst.Domains {
				if strings.EqualFold(d.Host, host) {
					return true
				}
			}
		}
	}
	return false
}
