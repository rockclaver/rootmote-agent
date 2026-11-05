package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/inventory"
	"github.com/rockclaver/rootmote-agent/internal/webserver"
)

// --- cached host discovery ---

// discoveryTTL keeps one discovery pass for a short time, so building the
// evidence and the inventory for one incident does not scan the host twice.
const discoveryTTL = 30 * time.Second

type discoveryCache struct {
	mu     sync.Mutex
	at     time.Time
	report inventory.DiscoveryReport
}

// cachedInventory returns a recent discovery report, scanning the host when
// there is none.
func (s *Server) cachedInventory(ctx context.Context) inventory.DiscoveryReport {
	s.discovery.mu.Lock()
	defer s.discovery.mu.Unlock()
	if !s.discovery.at.IsZero() && s.cfg.Now().Sub(s.discovery.at) < discoveryTTL {
		return s.discovery.report
	}
	report := s.discoverHostInventory(ctx)
	s.discovery.report = report
	s.discovery.at = s.cfg.Now()
	return report
}

// --- stack: PM2 apps and certificates ---

type stackSource struct{ s *Server }

func (a stackSource) Stack(ctx context.Context) diagnose.Stack {
	report := a.s.cachedInventory(ctx)
	var out diagnose.Stack
	for _, app := range report.PM2Apps {
		out.PM2Apps = append(out.PM2Apps, diagnose.PM2App{User: app.User, App: app.App, Status: app.Status})
	}
	for _, c := range report.Certs {
		at, err := time.Parse(time.RFC3339, c.ExpiresAt)
		if err != nil {
			continue
		}
		out.Certs = append(out.Certs, diagnose.Cert{Name: c.Name, ExpiresAt: at})
	}
	return out
}

// --- disk: biggest directories ---

type diskSource struct{}

// LargestDirs runs du on one filesystem and returns the n biggest
// directories that have no bigger directory inside them listed below. Output
// read before the time limit counts: a slow disk gives a partial answer.
func (diskSource) LargestDirs(ctx context.Context, mount string, n int) ([]diagnose.DirSize, error) {
	mount = filepath.Clean(mount)
	if !filepath.IsAbs(mount) {
		return nil, fmt.Errorf("%q is not an absolute path", mount)
	}
	cmd := exec.CommandContext(ctx, "du", "-x", "-k", "-d", "2", mount)
	out, err := cmd.Output()
	dirs := parseDu(out, mount, n)
	if len(dirs) == 0 && err != nil {
		return nil, fmt.Errorf("du %s: %w", mount, err)
	}
	return dirs, nil
}

// parseDu reads `du -k -d 2` output for mount.
func parseDu(out []byte, mount string, n int) []diagnose.DirSize {
	type entry struct {
		path string
		kb   float64
	}
	var entries []entry
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		kbText, path, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		kb, err := strconv.ParseFloat(strings.TrimSpace(kbText), 64)
		if err != nil || path == mount {
			continue
		}
		entries = append(entries, entry{path: path, kb: kb})
	}
	// Drop a directory when one of its children is listed: the child says
	// more about where the space went.
	hasChild := map[string]bool{}
	for _, e := range entries {
		parent := filepath.Dir(e.path)
		hasChild[parent] = true
	}
	var leaves []entry
	for _, e := range entries {
		if !hasChild[e.path] {
			leaves = append(leaves, e)
		}
	}
	sort.SliceStable(leaves, func(i, j int) bool { return leaves[i].kb > leaves[j].kb })
	if len(leaves) > n {
		leaves = leaves[:n]
	}
	out2 := make([]diagnose.DirSize, len(leaves))
	for i, e := range leaves {
		out2[i] = diagnose.DirSize{Path: e.path, SizeMB: e.kb / 1024}
	}
	return out2
}

// --- reverse proxy ---

type proxySource struct {
	s *Server
}

// webErrorsEntry is one log in the `web-errors` helper's answer.
type webErrorsEntry struct {
	Path string `json:"path"`
	Text string `json:"text"`
}

// ErrorLog returns the end of the web server error logs. The logs are not
// readable by the agent's own user, so they come from the read-only
// `web-errors` helper action, which reads only web server error logs.
func (p proxySource) ErrorLog(ctx context.Context, tail int) (string, error) {
	if p.s == nil || p.s.cfg.Priv == nil {
		return "", errors.New("the privilege helper is not available")
	}
	out, err := p.s.cfg.Priv.Call(ctx, "web-errors")
	if err != nil {
		return "", err
	}
	var logs []webErrorsEntry
	if err := json.Unmarshal(out, &logs); err != nil {
		return "", errors.New("could not read the web server error log answer")
	}
	if len(logs) == 0 {
		return "", errors.New("no web server error log found")
	}
	var lines []string
	for _, l := range logs {
		lines = append(lines, strings.Split(strings.TrimRight(l.Text, "\n"), "\n")...)
	}
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	return strings.Join(lines, "\n"), nil
}

// Upstreams finds the backends nginx forwards the address to, and the service
// on this host behind each one.
func (p proxySource) Upstreams(ctx context.Context, target string) ([]diagnose.Upstream, error) {
	if p.s.cfg.Webservers == nil {
		return nil, errors.New("web server discovery is not configured")
	}
	host := hostOf(target)
	var files [][]byte
	for _, inst := range p.s.cfg.Webservers.List(ctx).Webservers {
		if inst.Kind != webserver.KindNginx {
			continue
		}
		for _, path := range inst.ConfigPaths {
			if data, err := os.ReadFile(path); err == nil {
				files = append(files, data)
			}
		}
	}
	addrs := nginxBackends(files, host)
	if len(addrs) == 0 {
		return nil, nil
	}
	listeners := p.listeners(ctx)
	out := make([]diagnose.Upstream, 0, len(addrs))
	for _, addr := range addrs {
		up := diagnose.Upstream{Address: addr}
		if port := portOf(addr); port > 0 && isLocalAddr(addr) {
			up.Kind, up.Name = listeners.service(port)
		}
		out = append(out, up)
	}
	return out, nil
}

// listenerIndex ties host ports to the container or unit that owns them.
type listenerIndex struct {
	containers map[int]string
	units      map[int]string
}

func (l listenerIndex) service(port int) (kind, name string) {
	if c, ok := l.containers[port]; ok {
		return "container", c
	}
	if u, ok := l.units[port]; ok {
		return "unit", u
	}
	return "", ""
}

var publishedPortRe = regexp.MustCompile(`(\d+)->`)

func (p proxySource) listeners(ctx context.Context) listenerIndex {
	idx := listenerIndex{containers: map[int]string{}, units: map[int]string{}}
	if p.s.cfg.Docker != nil {
		if list, err := p.s.cfg.Docker.Containers(ctx); err == nil {
			for _, c := range list {
				idx.addContainer(c)
			}
		}
	}
	for _, lp := range p.s.cachedInventory(ctx).ListeningPorts {
		if lp.PID > 0 {
			if unit := unitOfPID(lp.PID); unit != "" {
				idx.units[lp.Port] = unit
			}
		}
	}
	return idx
}

func (l listenerIndex) addContainer(c docker.ContainerSummary) {
	for _, m := range publishedPortRe.FindAllStringSubmatch(c.PortsSummary, -1) {
		if port, err := strconv.Atoi(m[1]); err == nil {
			l.containers[port] = c.Name
		}
	}
}

// unitOfPID reads the systemd unit a process belongs to from its cgroup.
func unitOfPID(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	return unitFromCgroup(string(data))
}

func unitFromCgroup(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		segs := strings.Split(parts[2], "/")
		for i := len(segs) - 1; i >= 0; i-- {
			if strings.HasSuffix(segs[i], ".service") && !strings.Contains(segs[i], "@.") {
				return segs[i]
			}
		}
	}
	return ""
}

func portOf(addr string) int {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		return 0
	}
	return n
}

func isLocalAddr(addr string) bool {
	host := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[:i], ":") {
		host = host[:i]
	}
	switch host {
	case "127.0.0.1", "localhost", "::1", "0.0.0.0", "[::1]":
		return true
	}
	return strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "::1")
}

// --- nginx config reading ---

var (
	nginxComment    = regexp.MustCompile(`(?m)#.*$`)
	nginxServerName = regexp.MustCompile(`(?m)\bserver_name\s+([^;]+);`)
	nginxProxyPass  = regexp.MustCompile(`(?m)\bproxy_pass\s+([^;\s]+)\s*;`)
	nginxUpstreamTo = regexp.MustCompile(`\bserver\s+([^\s;]+)`)
)

// nginxBackends lists the backend addresses (host:port) that serve host in
// the given nginx config files. A proxy_pass naming an upstream block is
// replaced by that block's servers. When no server block names the host, it
// returns nothing rather than guessing.
func nginxBackends(files [][]byte, host string) []string {
	var text strings.Builder
	for _, f := range files {
		text.WriteString(nginxComment.ReplaceAllString(string(f), ""))
		text.WriteString("\n")
	}
	conf := text.String()
	upstreams := map[string][]string{}
	var serverBodies []string
	for _, blk := range nginxBlocks(conf) {
		switch {
		case blk.name == "server":
			serverBodies = append(serverBodies, blk.body)
		case strings.HasPrefix(blk.name, "upstream "):
			var addrs []string
			for _, m := range nginxUpstreamTo.FindAllStringSubmatch(blk.body, -1) {
				addrs = append(addrs, m[1])
			}
			upstreams[strings.TrimSpace(strings.TrimPrefix(blk.name, "upstream "))] = addrs
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, body := range serverBodies {
		if !serverNamed(body, host) {
			continue
		}
		for _, m := range nginxProxyPass.FindAllStringSubmatch(body, -1) {
			for _, addr := range resolveProxyPass(m[1], upstreams) {
				if !seen[addr] {
					seen[addr] = true
					out = append(out, addr)
				}
			}
		}
	}
	return out
}

func serverNamed(body, host string) bool {
	if host == "" {
		return false
	}
	for _, m := range nginxServerName.FindAllStringSubmatch(body, -1) {
		for _, name := range strings.Fields(m[1]) {
			if strings.EqualFold(name, host) {
				return true
			}
		}
	}
	return false
}

// resolveProxyPass turns a proxy_pass value into backend addresses.
func resolveProxyPass(value string, upstreams map[string][]string) []string {
	v := strings.TrimSpace(value)
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?"); i >= 0 {
		v = v[:i]
	}
	if v == "" || strings.HasPrefix(v, "unix:") || strings.Contains(v, "$") {
		return nil
	}
	if addrs, ok := upstreams[v]; ok {
		return addrs
	}
	return []string{v}
}

type nginxBlock struct {
	name string
	body string
}

// nginxBlocks returns the top-level blocks of a config with comments
// removed, descending into http { } and similar wrappers so server and
// upstream blocks are found wherever they sit.
func nginxBlocks(conf string) []nginxBlock {
	var out []nginxBlock
	var walk func(s string)
	walk = func(s string) {
		for {
			open := strings.IndexByte(s, '{')
			if open < 0 {
				return
			}
			head := s[:open]
			if i := strings.LastIndexAny(head, ";}"); i >= 0 {
				head = head[i+1:]
			}
			name := strings.Join(strings.Fields(head), " ")
			depth, end := 1, -1
			for i := open + 1; i < len(s); i++ {
				switch s[i] {
				case '{':
					depth++
				case '}':
					depth--
				}
				if depth == 0 {
					end = i
					break
				}
			}
			if end < 0 {
				return
			}
			body := s[open+1 : end]
			if name == "server" || strings.HasPrefix(name, "upstream ") {
				out = append(out, nginxBlock{name: name, body: body})
			} else {
				walk(body)
			}
			s = s[end+1:]
		}
	}
	walk(conf)
	return out
}
