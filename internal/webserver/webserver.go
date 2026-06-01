// Package webserver inventories host-installed reverse proxies and performs
// guarded operational actions on their backing systemd units.
package webserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rockclaver/claver-agent/internal/systemd"
)

type Kind string

const (
	KindCaddy  Kind = "caddy"
	KindNginx  Kind = "nginx"
	KindApache Kind = "apache"
)

type Domain struct {
	Host       string `json:"host"`
	SourcePath string `json:"source_path"`
	Line       int    `json:"line,omitempty"`
}

type Instance struct {
	ID            string   `json:"id"`
	Kind          Kind     `json:"kind"`
	Unit          string   `json:"unit,omitempty"`
	Description   string   `json:"description,omitempty"`
	ActiveState   string   `json:"active_state,omitempty"`
	EnabledOnBoot string   `json:"enabled_on_boot,omitempty"`
	Domains       []Domain `json:"domains"`
	ConfigPaths   []string `json:"config_paths"`
	Warnings      []string `json:"warnings,omitempty"`
}

type Snapshot struct {
	Available  bool       `json:"available"`
	Webservers []Instance `json:"webservers"`
	Warnings   []string   `json:"warnings,omitempty"`
}

type ValidationResult struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

type Systemd interface {
	Status(context.Context) systemd.Status
	List(context.Context) ([]systemd.Unit, error)
	Action(context.Context, string, systemd.Action) error
}

type Runner interface {
	Run(context.Context, string, ...string) (string, error)
}

type privilegedRunner interface {
	RunPrivileged(context.Context, string, ...string) (string, error)
}

type Config struct {
	Systemd Systemd
	Runner  Runner
	Paths   map[Kind][]string
}

type Manager struct {
	systemd Systemd
	runner  Runner
	paths   map[Kind][]string
}

func New(cfg Config) (*Manager, error) {
	if cfg.Systemd == nil {
		return nil, errors.New("webserver: Systemd is required")
	}
	runner := cfg.Runner
	if runner == nil {
		runner = shellRunner{}
	}
	paths := defaultPaths()
	for k, v := range cfg.Paths {
		paths[k] = append([]string(nil), v...)
	}
	return &Manager{systemd: cfg.Systemd, runner: runner, paths: paths}, nil
}

func defaultPaths() map[Kind][]string {
	return map[Kind][]string{
		KindCaddy: {
			"/etc/caddy/Caddyfile",
			"/etc/caddy/*.caddy",
			"/etc/caddy/conf.d/*.caddy",
			"/etc/caddy/claver/*.caddy",
		},
		KindNginx: {
			"/etc/nginx/sites-enabled/*",
			"/etc/nginx/conf.d/*.conf",
		},
		KindApache: {
			"/etc/apache2/sites-enabled/*",
			"/etc/httpd/conf.d/*.conf",
		},
	}
}

type shellRunner struct{}

func (shellRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	out, err := cmd.CombinedOutput()
	msg := strings.TrimSpace(string(out))
	if err != nil && msg == "" {
		msg = err.Error()
	}
	return msg, err
}

func (r shellRunner) RunPrivileged(ctx context.Context, name string, args ...string) (string, error) {
	if os.Geteuid() == 0 {
		return r.Run(ctx, name, args...)
	}
	path, err := exec.LookPath(name)
	if err != nil {
		path = fallbackBinaryPath(name)
		if path == "" {
			// Preserve the same error shape the direct exec path would have exposed.
			return "", err
		}
	}
	sudoArgs := append([]string{"-n", path}, args...)
	return r.Run(ctx, "sudo", sudoArgs...)
}

func fallbackBinaryPath(name string) string {
	candidates := map[string][]string{
		"nginx":      {"/usr/sbin/nginx", "/sbin/nginx"},
		"apache2ctl": {"/usr/sbin/apache2ctl", "/usr/bin/apache2ctl"},
		"apachectl":  {"/usr/sbin/apachectl", "/usr/bin/apachectl"},
		"httpd":      {"/usr/sbin/httpd", "/usr/bin/httpd", "/sbin/httpd"},
		"caddy":      {"/usr/bin/caddy", "/usr/local/bin/caddy"},
	}
	for _, p := range candidates[name] {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func runPrivileged(ctx context.Context, runner Runner, name string, args ...string) (string, error) {
	if pr, ok := runner.(privilegedRunner); ok {
		return pr.RunPrivileged(ctx, name, args...)
	}
	return runner.Run(ctx, name, args...)
}

type spec struct {
	kind        Kind
	units       []string
	description string
}

var specs = []spec{
	{kind: KindCaddy, units: []string{"caddy.service"}, description: "Caddy"},
	{kind: KindNginx, units: []string{"nginx.service"}, description: "Nginx"},
	{kind: KindApache, units: []string{"apache2.service", "httpd.service"}, description: "Apache"},
}

func (m *Manager) List(ctx context.Context) Snapshot {
	var warnings []string
	unitByName := map[string]systemd.Unit{}
	st := m.systemd.Status(ctx)
	if !st.Available {
		warnings = append(warnings, warn("systemd unavailable", st.UnavailableMessage))
	} else {
		units, err := m.systemd.List(ctx)
		if err != nil {
			warnings = append(warnings, "systemd unit list failed: "+err.Error())
		}
		for _, u := range units {
			unitByName[u.Name] = u
		}
	}

	var out []Instance
	for _, sp := range specs {
		roots, rootWarnings := collectPaths(m.paths[sp.kind])
		warnings = append(warnings, rootWarnings...)
		domains, parsedPaths, parseWarnings := parseKind(sp.kind, roots)
		instWarnings := append([]string(nil), parseWarnings...)

		var units []systemd.Unit
		for _, name := range sp.units {
			if u, ok := unitByName[name]; ok {
				units = append(units, u)
			}
		}
		if len(units) == 0 && len(roots) == 0 {
			continue
		}
		if len(units) == 0 {
			unit := sp.units[0]
			instWarnings = append(instWarnings, "systemd unit "+unit+" was not found")
			out = append(out, Instance{
				ID:          string(sp.kind) + ":" + unit,
				Kind:        sp.kind,
				Unit:        unit,
				Description: sp.description,
				Domains:     domains,
				ConfigPaths: parsedPaths,
				Warnings:    uniqueStrings(instWarnings),
			})
			continue
		}
		for _, u := range units {
			desc := u.Description
			if desc == "" {
				desc = sp.description
			}
			out = append(out, Instance{
				ID:            string(sp.kind) + ":" + u.Name,
				Kind:          sp.kind,
				Unit:          u.Name,
				Description:   desc,
				ActiveState:   u.ActiveState,
				EnabledOnBoot: u.EnabledOnBoot,
				Domains:       domains,
				ConfigPaths:   parsedPaths,
				Warnings:      uniqueStrings(instWarnings),
			})
		}
	}
	return Snapshot{Available: st.Available, Webservers: out, Warnings: uniqueStrings(warnings)}
}

func warn(prefix, msg string) string {
	if msg == "" {
		return prefix
	}
	return prefix + ": " + msg
}

func (m *Manager) Validate(ctx context.Context, id string) (ValidationResult, error) {
	inst, err := m.find(ctx, id)
	if err != nil {
		return ValidationResult{}, err
	}
	var name string
	var args []string
	switch inst.Kind {
	case KindCaddy:
		name = "caddy"
		args = []string{"validate"}
		if cfg := firstConfig(inst, "Caddyfile"); cfg != "" {
			args = append(args, "--config", cfg)
		}
	case KindNginx:
		name = "nginx"
		args = []string{"-t"}
	case KindApache:
		if inst.Unit == "httpd.service" {
			name = "httpd"
			args = []string{"-t"}
		} else {
			name = "apache2ctl"
			args = []string{"configtest"}
		}
	default:
		return ValidationResult{}, fmt.Errorf("webserver: unsupported kind %q", inst.Kind)
	}
	out, runErr := runPrivileged(ctx, m.runner, name, args...)
	return ValidationResult{ID: id, OK: runErr == nil, Output: out}, nil
}

func firstConfig(inst Instance, base string) string {
	for _, p := range inst.ConfigPaths {
		if filepath.Base(p) == base {
			return p
		}
	}
	if len(inst.ConfigPaths) > 0 {
		return inst.ConfigPaths[0]
	}
	return ""
}

func (m *Manager) Action(ctx context.Context, id, action string) (Instance, error) {
	if action != "reload" && action != "restart" {
		return Instance{}, fmt.Errorf("webserver: unsupported action %q", action)
	}
	inst, err := m.find(ctx, id)
	if err != nil {
		return Instance{}, err
	}
	if inst.Unit == "" {
		return Instance{}, fmt.Errorf("webserver: %s has no backing systemd unit", id)
	}
	if err := m.systemd.Action(ctx, inst.Unit, systemd.Action(action)); err != nil {
		return inst, err
	}
	return inst, nil
}

func (m *Manager) find(ctx context.Context, id string) (Instance, error) {
	if id == "" {
		return Instance{}, errors.New("webserver: id required")
	}
	for _, inst := range m.List(ctx).Webservers {
		if inst.ID == id {
			return inst, nil
		}
	}
	return Instance{}, fmt.Errorf("webserver: unknown id %q", id)
}

func collectPaths(patterns []string) ([]string, []string) {
	var paths, warnings []string
	for _, pattern := range patterns {
		if !hasGlob(pattern) {
			info, err := os.Stat(pattern)
			if err != nil {
				if os.IsNotExist(err) {
					warnings = append(warnings, "config path missing: "+pattern)
				} else {
					warnings = append(warnings, "config path unreadable: "+pattern+": "+err.Error())
				}
				continue
			}
			if !info.IsDir() {
				paths = append(paths, pattern)
			}
			continue
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			warnings = append(warnings, "config glob invalid: "+pattern+": "+err.Error())
			continue
		}
		for _, p := range matches {
			info, err := os.Stat(p)
			if err != nil {
				warnings = append(warnings, "config path unreadable: "+p+": "+err.Error())
				continue
			}
			if !info.IsDir() {
				paths = append(paths, p)
			}
		}
	}
	return uniqueSorted(paths), warnings
}

func hasGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

func parseKind(kind Kind, roots []string) ([]Domain, []string, []string) {
	seen := map[string]bool{}
	var domains []Domain
	var parsed []string
	var warnings []string
	for _, path := range roots {
		ds, includes, ws := parseFile(kind, path, true)
		warnings = append(warnings, ws...)
		parsed = append(parsed, path)
		domains = appendDomains(domains, ds, seen)
		for _, inc := range includes {
			ids, _, iws := parseFile(kind, inc, false)
			warnings = append(warnings, iws...)
			parsed = append(parsed, inc)
			domains = appendDomains(domains, ids, seen)
		}
	}
	sort.Slice(domains, func(i, j int) bool {
		if domains[i].SourcePath == domains[j].SourcePath {
			if domains[i].Line == domains[j].Line {
				return domains[i].Host < domains[j].Host
			}
			return domains[i].Line < domains[j].Line
		}
		return domains[i].SourcePath < domains[j].SourcePath
	})
	return domains, uniqueSorted(parsed), uniqueStrings(warnings)
}

func appendDomains(out, in []Domain, seen map[string]bool) []Domain {
	for _, d := range in {
		key := d.Host + "\x00" + d.SourcePath + "\x00" + fmt.Sprint(d.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	return out
}

func parseFile(kind Kind, path string, followIncludes bool) ([]Domain, []string, []string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, []string{"config unreadable: " + path + ": " + err.Error()}
	}
	defer f.Close()
	var domains []Domain
	var includes []string
	var warnings []string
	depth := 0
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := stripComment(sc.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth < 0 {
				depth = 0
			}
			continue
		}
		if incs, ws := includePaths(kind, path, trimmed, followIncludes); len(incs) > 0 || len(ws) > 0 {
			includes = append(includes, incs...)
			warnings = append(warnings, ws...)
		}
		switch kind {
		case KindCaddy:
			if depth == 0 {
				domains = append(domains, caddyDomains(path, lineNo, trimmed)...)
			}
		case KindNginx:
			domains = append(domains, nginxDomains(path, lineNo, trimmed)...)
		case KindApache:
			domains = append(domains, apacheDomains(path, lineNo, trimmed)...)
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth < 0 {
			depth = 0
		}
	}
	if err := sc.Err(); err != nil {
		warnings = append(warnings, "config read failed: "+path+": "+err.Error())
	}
	return domains, uniqueSorted(includes), warnings
}

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

func includePaths(kind Kind, source, line string, follow bool) ([]string, []string) {
	fields := strings.Fields(strings.TrimSuffix(line, ";"))
	if len(fields) < 2 {
		return nil, nil
	}
	var patterns []string
	switch kind {
	case KindCaddy:
		if fields[0] != "import" {
			return nil, nil
		}
		patterns = fields[1:]
	case KindNginx:
		if fields[0] != "include" {
			return nil, nil
		}
		patterns = fields[1:]
	case KindApache:
		if !strings.EqualFold(fields[0], "Include") && !strings.EqualFold(fields[0], "IncludeOptional") {
			return nil, nil
		}
		patterns = fields[1:]
	default:
		return nil, nil
	}
	if !follow {
		return nil, []string{"nested include ignored in " + source}
	}
	var out, warnings []string
	for _, pattern := range patterns {
		pattern = strings.Trim(pattern, `"'`)
		if pattern == "" || strings.HasPrefix(pattern, "(") {
			warnings = append(warnings, "unsupported include/import in "+source+": "+pattern)
			continue
		}
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(filepath.Dir(source), pattern)
		}
		matches, ws := collectPaths([]string{pattern})
		out = append(out, matches...)
		warnings = append(warnings, ws...)
	}
	return uniqueSorted(out), warnings
}

func caddyDomains(path string, line int, s string) []Domain {
	if !strings.Contains(s, "{") {
		return nil
	}
	labelPart := strings.TrimSpace(strings.SplitN(s, "{", 2)[0])
	if labelPart == "" || strings.HasPrefix(labelPart, "(") || strings.HasPrefix(labelPart, "@") {
		return nil
	}
	if isLikelyCaddyDirective(labelPart) {
		return nil
	}
	labelPart = strings.ReplaceAll(labelPart, ",", " ")
	var out []Domain
	for _, token := range strings.Fields(labelPart) {
		if host := cleanHost(token); host != "" {
			out = append(out, Domain{Host: host, SourcePath: path, Line: line})
		}
	}
	return out
}

func isLikelyCaddyDirective(s string) bool {
	first := strings.Fields(s)
	if len(first) == 0 {
		return false
	}
	switch first[0] {
	case "handle", "handle_path", "route", "respond", "reverse_proxy", "redir", "tls", "log", "encode", "header", "file_server":
		return true
	default:
		return false
	}
}

func nginxDomains(path string, line int, s string) []Domain {
	fields := strings.Fields(strings.TrimSuffix(s, ";"))
	if len(fields) < 2 || fields[0] != "server_name" {
		return nil
	}
	var out []Domain
	for _, token := range fields[1:] {
		if host := cleanHost(token); host != "" {
			out = append(out, Domain{Host: host, SourcePath: path, Line: line})
		}
	}
	return out
}

func apacheDomains(path string, line int, s string) []Domain {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return nil
	}
	name := fields[0]
	if !strings.EqualFold(name, "ServerName") && !strings.EqualFold(name, "ServerAlias") {
		return nil
	}
	var out []Domain
	for _, token := range fields[1:] {
		if host := cleanHost(token); host != "" {
			out = append(out, Domain{Host: host, SourcePath: path, Line: line})
		}
	}
	return out
}

func cleanHost(token string) string {
	token = strings.Trim(token, `"' ,;`)
	if token == "" || token == "_" || token == "*" || strings.HasPrefix(token, "~") || strings.Contains(token, "$") {
		return ""
	}
	token = strings.TrimPrefix(token, "http://")
	token = strings.TrimPrefix(token, "https://")
	if i := strings.IndexByte(token, '/'); i >= 0 {
		token = token[:i]
	}
	if host, _, err := net.SplitHostPort(token); err == nil {
		token = host
	} else if i := strings.LastIndexByte(token, ':'); i >= 0 && strings.Count(token, ":") == 1 {
		token = token[:i]
	}
	token = strings.TrimSuffix(strings.ToLower(token), ".")
	if token == "" || token == "localhost" || strings.HasPrefix(token, ":") {
		return ""
	}
	for _, r := range token {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '*' {
			continue
		}
		return ""
	}
	if !strings.Contains(token, ".") && !strings.Contains(token, "*") {
		return ""
	}
	return token
}

func uniqueSorted(in []string) []string {
	out := uniqueStrings(in)
	sort.Strings(out)
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
