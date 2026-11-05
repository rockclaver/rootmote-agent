package monitor

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/firewall"
	"github.com/rockclaver/rootmote-agent/internal/store"
)

// --- cert_expiry ---------------------------------------------------------

const (
	defaultCertWarnDays     = 14.0
	defaultCertCriticalDays = 3.0
	// certCheckEvery bounds network dials: a host target is dialed at most
	// once an hour, and the cached NotAfter drives every tick in between.
	certCheckEvery = time.Hour
	// certRetryEvery is how soon a failed dial is retried.
	certRetryEvery = 5 * time.Minute
)

type certCache struct {
	notAfter  time.Time
	haveValue bool
	checkedAt time.Time
	lastErr   error
}

// CertEvaluator evaluates cert_expiry for each configured target: a
// "host[:port]" TLS endpoint or an absolute PEM certificate file path.
type CertEvaluator struct {
	Host Host
	Defs DefinitionResolver
	Held WasFailingResolver
	Now  func() time.Time

	cache map[string]*certCache
}

func (e *CertEvaluator) Kind() Kind { return KindCertExpiry }

func (e *CertEvaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func isCertFile(target string) bool { return filepath.IsAbs(target) }

func (e *CertEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	if e.cache == nil {
		e.cache = map[string]*certCache{}
	}
	now := e.now()
	var out []Observation
	for _, target := range e.Defs.Targets(KindCertExpiry) {
		def, enabled := e.Defs.Resolve(KindCertExpiry, target)
		if !enabled {
			continue
		}
		var notAfter time.Time
		if isCertFile(target) {
			na, err := e.fileNotAfter(target)
			if err != nil {
				out = append(out, Observation{
					Target: target, Failing: true, Severity: severityOr(def, "warning"),
					Summary: fmt.Sprintf("cannot read certificate %s: %v", target, err),
				})
				continue
			}
			notAfter = na
		} else {
			c := e.cache[target]
			if c == nil {
				c = &certCache{}
				e.cache[target] = c
			}
			interval := certCheckEvery
			if c.lastErr != nil {
				interval = certRetryEvery
			}
			if c.checkedAt.IsZero() || now.Sub(c.checkedAt) >= interval {
				addr, sni := certAddr(target, def)
				na, err := e.Host.CertNotAfter(ctx, addr, sni)
				c.checkedAt, c.lastErr = now, err
				if err == nil {
					c.notAfter, c.haveValue = na, true
				}
			}
			// A transient dial failure says nothing about expiry: keep the
			// last known date, or stay silent if there never was one.
			if !c.haveValue {
				continue
			}
			notAfter = c.notAfter
		}

		days := notAfter.Sub(now).Hours() / 24
		warn, recover := def.thresholds(defaultCertWarnDays, defaultCertWarnDays+1, false)
		critical := def.paramFloat("critical_days", defaultCertCriticalDays)
		limit := warn
		if e.Held.WasFailing(KindCertExpiry, target) {
			limit = recover
		}
		failing := days < limit
		severity := severityOr(def, "warning")
		if failing && days < critical {
			severity = "critical"
		}
		summary := fmt.Sprintf("certificate %s expires in %.0f days (warns <%.0f)", target, days, warn)
		if days <= 0 {
			summary = fmt.Sprintf("certificate %s expired %s ago", target, now.Sub(notAfter).Round(time.Minute))
		}
		attrs := valueAttrs(days, warn, "days")
		attrs["not_after"] = notAfter.UTC().Format(time.RFC3339)
		out = append(out, Observation{Target: target, Failing: failing, Severity: severity, Summary: summary, Attributes: attrs})
	}
	return out, nil
}

// certAddr turns a target into a dialable host:port (default 443) and SNI.
func certAddr(target string, def Definition) (addr, serverName string) {
	serverName = def.param("server_name")
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target, serverName
	}
	return net.JoinHostPort(strings.Trim(target, "[]"), "443"), serverName
}

func (e *CertEvaluator) fileNotAfter(file string) (time.Time, error) {
	data, err := e.Host.ReadFile(file)
	if err != nil {
		return time.Time{}, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return time.Time{}, errors.New("no PEM certificate found")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		return cert.NotAfter, nil // first certificate is the leaf
	}
}

// --- systemd_timer_failed ------------------------------------------------

const maxTimers = 200

// TimerEvaluator evaluates systemd_timer_failed: for every timer unit, did
// the service it triggers end its last run in failure.
type TimerEvaluator struct {
	Systemd SystemdSource
	Host    Host
	Defs    DefinitionResolver
}

func (e *TimerEvaluator) Kind() Kind { return KindSystemdTimerFailed }

func (e *TimerEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	if !e.Systemd.Status(ctx).Available {
		return nil, nil
	}
	list, err := e.Host.Run(ctx, "systemctl", "list-units", "--type=timer", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("monitor: systemd_timer_failed: list timers: %w", err)
	}
	var timers []string
	defs := map[string]Definition{}
	for _, line := range strings.Split(string(list), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasSuffix(f[0], ".timer") {
			continue
		}
		def, enabled := e.Defs.Resolve(KindSystemdTimerFailed, f[0])
		if !enabled {
			continue
		}
		timers = append(timers, f[0])
		defs[f[0]] = def
		if len(timers) == maxTimers {
			break
		}
	}
	if len(timers) == 0 {
		return nil, nil
	}
	timerProps, err := e.show(ctx, timers, "Unit")
	if err != nil {
		return nil, err
	}
	var services []string
	svcOf := map[string]string{}
	for _, t := range timers {
		svc := timerProps[t]["Unit"]
		if svc == "" {
			svc = strings.TrimSuffix(t, ".timer") + ".service"
		}
		svcOf[t] = svc
		services = append(services, svc)
	}
	svcProps, err := e.show(ctx, services, "ActiveState", "Result")
	if err != nil {
		return nil, err
	}
	var out []Observation
	for _, t := range timers {
		svc := svcOf[t]
		props, ok := svcProps[svc]
		if !ok {
			continue
		}
		state, result := props["ActiveState"], props["Result"]
		failing := state == "failed" || (state == "inactive" && result != "" && result != "success")
		summary := fmt.Sprintf("%s: last run of %s succeeded", t, svc)
		if failing {
			summary = fmt.Sprintf("%s: last run of %s failed (%s)", t, svc, firstNonEmptyStr(result, state))
		}
		out = append(out, Observation{
			Target: t, Failing: failing, Severity: severityOr(defs[t], "warning"), Summary: summary,
			Attributes: map[string]string{"service": svc, "active_state": state, "result": result},
		})
	}
	return out, nil
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// show runs one `systemctl show` for all units and parses the blank-line
// separated blocks, keyed by Id.
func (e *TimerEvaluator) show(ctx context.Context, units []string, props ...string) (map[string]map[string]string, error) {
	args := []string{"show", "--no-pager", "-p", "Id"}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	args = append(args, units...)
	out, err := e.Host.Run(ctx, "systemctl", args...)
	if err != nil {
		return nil, fmt.Errorf("monitor: systemd_timer_failed: systemctl show: %w", err)
	}
	return parseSystemctlShow(string(out)), nil
}

func parseSystemctlShow(raw string) map[string]map[string]string {
	out := map[string]map[string]string{}
	cur := map[string]string{}
	flush := func() {
		if id := cur["Id"]; id != "" {
			out[id] = cur
		}
		cur = map[string]string{}
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[k] = v
		}
	}
	flush()
	return out
}

// --- job_freshness -------------------------------------------------------

const defaultJobMaxAge = 25 * time.Hour

// JobFreshnessEvaluator evaluates job_freshness: the newest file matching
// the target path/glob must exist, be at most max_age old, and (optionally)
// at least min_size_bytes large.
type JobFreshnessEvaluator struct {
	Host Host
	Defs DefinitionResolver
	Now  func() time.Time
}

func (e *JobFreshnessEvaluator) Kind() Kind { return KindJobFreshness }

func (e *JobFreshnessEvaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *JobFreshnessEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	now := e.now()
	var out []Observation
	for _, target := range e.Defs.Targets(KindJobFreshness) {
		def, enabled := e.Defs.Resolve(KindJobFreshness, target)
		if !enabled {
			continue
		}
		maxAge := def.paramDuration("max_age", defaultJobMaxAge)
		minSize := int64(def.paramInt("min_size_bytes", 0))
		obs := Observation{Target: target, Severity: severityOr(def, "critical")}

		paths := []string{target}
		if strings.ContainsAny(target, "*?[") {
			matches, err := e.Host.Glob(target)
			if err != nil {
				return nil, fmt.Errorf("monitor: job_freshness %s: %w", target, err)
			}
			paths = matches
		}
		var newestPath string
		var newestMod time.Time
		var newestSize int64
		for _, p := range paths {
			info, err := e.Host.Stat(p)
			if err != nil {
				continue
			}
			if newestPath == "" || info.ModTime().After(newestMod) {
				newestPath, newestMod, newestSize = p, info.ModTime(), info.Size()
			}
		}
		switch {
		case newestPath == "":
			obs.Failing = true
			obs.Summary = fmt.Sprintf("%s is missing", target)
		default:
			age := now.Sub(newestMod)
			obs.Attributes = valueAttrs(age.Seconds(), maxAge.Seconds(), "seconds")
			obs.Attributes["file"] = path.Base(filepath.ToSlash(newestPath))
			switch {
			case age > maxAge:
				obs.Failing = true
				obs.Summary = fmt.Sprintf("%s last updated %s ago (max %s)", newestPath, age.Round(time.Minute), maxAge)
			case newestSize < minSize:
				obs.Failing = true
				obs.Summary = fmt.Sprintf("%s is only %d bytes (min %d)", newestPath, newestSize, minSize)
			default:
				obs.Summary = fmt.Sprintf("%s updated %s ago (max %s)", newestPath, age.Round(time.Minute), maxAge)
			}
		}
		out = append(out, obs)
	}
	return out, nil
}

// --- port_listening ------------------------------------------------------

// SocketSource is the subset of firewall.SocketReader the port monitor needs.
type SocketSource = firewall.SocketReader

// PortEvaluator evaluates port_listening: a socket must be listening on the
// target's port (and, for an IP-literal host, that address or a wildcard).
type PortEvaluator struct {
	Sockets SocketSource
	Defs    DefinitionResolver
}

func (e *PortEvaluator) Kind() Kind { return KindPortListening }

func (e *PortEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	targets := e.Defs.Targets(KindPortListening)
	if len(targets) == 0 {
		return nil, nil
	}
	socks, err := e.Sockets.Listening(ctx)
	if err != nil {
		return nil, fmt.Errorf("monitor: port_listening: %w", err)
	}
	var out []Observation
	for _, target := range targets {
		def, enabled := e.Defs.Resolve(KindPortListening, target)
		if !enabled {
			continue
		}
		host, port, err := ParsePortTarget(target)
		if err != nil {
			continue // the relay rejects malformed targets
		}
		proto := strings.ToLower(def.param("protocol"))
		if proto == "" {
			proto = "tcp"
		}
		listening := false
		for _, s := range socks {
			if s.Port != port || (proto != "any" && string(s.Protocol) != proto) {
				continue
			}
			if socketMatchesHost(s.Address, host) {
				listening = true
				break
			}
		}
		summary := fmt.Sprintf("%s is listening", target)
		if !listening {
			summary = fmt.Sprintf("nothing is listening on %s (%s)", target, proto)
		}
		out = append(out, Observation{Target: target, Failing: !listening, Severity: severityOr(def, "critical"), Summary: summary})
	}
	return out, nil
}

// ParsePortTarget parses "host:port", ":port" or "port". Exported so the
// relay's validation and the agent agree on the grammar by test, not import.
func ParsePortTarget(target string) (host string, port int, err error) {
	target = strings.TrimSpace(target)
	portStr := target
	if strings.Contains(target, ":") {
		h, p, serr := net.SplitHostPort(target)
		if serr != nil {
			return "", 0, serr
		}
		host, portStr = h, p
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in %q", target)
	}
	return host, port, nil
}

func normAddr(a string) string {
	a = strings.Trim(a, "[]")
	if i := strings.Index(a, "%"); i >= 0 {
		a = a[:i]
	}
	return a
}

func isWildcardAddr(a string) bool {
	switch normAddr(a) {
	case "*", "0.0.0.0", "::", "":
		return true
	}
	return false
}

// socketMatchesHost reports whether a listening address serves host. An
// empty or non-IP host (other than "localhost") matches any address: a
// hostname cannot be mapped to a socket address without resolving it.
func socketMatchesHost(sockAddr, host string) bool {
	if host == "" || isWildcardAddr(sockAddr) {
		return true
	}
	sa := normAddr(sockAddr)
	host = normAddr(host)
	if host == "localhost" {
		return sa == "127.0.0.1" || sa == "::1"
	}
	want := net.ParseIP(host)
	if want == nil {
		return true
	}
	got := net.ParseIP(sa)
	return got != nil && got.Equal(want)
}

// --- process_running -----------------------------------------------------

// ProcessInfo is the part of a process listing the monitor reads.
type ProcessInfo struct {
	Command string
	ExePath string
}

// ProcessSource lists running processes.
type ProcessSource interface {
	Running(ctx context.Context) ([]ProcessInfo, error)
}

// ProcessEvaluator evaluates process_running: some process must match the
// target name.
type ProcessEvaluator struct {
	Procs ProcessSource
	Defs  DefinitionResolver
}

func (e *ProcessEvaluator) Kind() Kind { return KindProcessRunning }

func (e *ProcessEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	targets := e.Defs.Targets(KindProcessRunning)
	if len(targets) == 0 {
		return nil, nil
	}
	procs, err := e.Procs.Running(ctx)
	if err != nil {
		return nil, fmt.Errorf("monitor: process_running: %w", err)
	}
	var out []Observation
	for _, target := range targets {
		def, enabled := e.Defs.Resolve(KindProcessRunning, target)
		if !enabled {
			continue
		}
		contains := strings.EqualFold(def.param("match"), "contains")
		count := 0
		for _, p := range procs {
			if processMatches(p, target, contains) {
				count++
			}
		}
		summary := fmt.Sprintf("%s is running (%d)", target, count)
		if count == 0 {
			summary = fmt.Sprintf("no process named %s is running", target)
		}
		out = append(out, Observation{
			Target: target, Failing: count == 0, Severity: severityOr(def, "critical"), Summary: summary,
			Attributes: map[string]string{"count": strconv.Itoa(count)},
		})
	}
	return out, nil
}

func processMatches(p ProcessInfo, name string, contains bool) bool {
	if contains {
		return strings.Contains(p.Command, name) || strings.Contains(p.ExePath, name)
	}
	if p.ExePath != "" && path.Base(p.ExePath) == name {
		return true
	}
	first := p.Command
	if f := strings.Fields(p.Command); len(f) > 0 {
		first = f[0]
	}
	first = strings.TrimSuffix(first, ":")
	return path.Base(first) == name || p.Command == name
}

// --- reboot_detected -----------------------------------------------------

// bootIDKey is the agent setting holding the last boot identity the engine
// saw.
const bootIDKey = "monitor.boot_id"

// BootStore persists the last observed boot identity across agent restarts.
// *store.Store satisfies it.
type BootStore interface {
	GetAgentSetting(key string) (string, error)
	PutAgentSetting(key, value string) error
}

// RebootEvaluator evaluates reboot_detected. A changed boot ID yields exactly
// one failing observation; every other tick is healthy, so with the default
// 1/1 thresholds the engine emits one firing and one resolved event per
// reboot. The first boot ID ever seen is recorded without an event.
type RebootEvaluator struct {
	Host Host
	Defs DefinitionResolver
	Boot BootStore

	announce string // boot ID to report on the next evaluation
}

func (e *RebootEvaluator) Kind() Kind { return KindRebootDetected }

func (e *RebootEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	def, enabled := e.Defs.Resolve(KindRebootDetected, "")
	if !enabled {
		return nil, nil
	}
	id, err := e.Host.BootID(ctx)
	if err != nil {
		return nil, fmt.Errorf("monitor: reboot_detected: boot id: %w", err)
	}
	prev, err := e.Boot.GetAgentSetting(bootIDKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if err := e.Boot.PutAgentSetting(bootIDKey, id); err != nil {
			return nil, fmt.Errorf("monitor: reboot_detected: persist boot id: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("monitor: reboot_detected: load boot id: %w", err)
	case prev != id:
		// Persist before reporting: if the write fails we retry next tick
		// instead of announcing the same reboot repeatedly.
		if err := e.Boot.PutAgentSetting(bootIDKey, id); err != nil {
			return nil, fmt.Errorf("monitor: reboot_detected: persist boot id: %w", err)
		}
		e.announce = id
	}
	obs := Observation{
		Severity: severityOr(def, "warning"),
		Summary:  "host is up; no reboot since last check",
	}
	if e.announce != "" {
		obs.Failing = true
		obs.Summary = "host rebooted"
		obs.Attributes = map[string]string{"boot_id": e.announce}
		e.announce = ""
	}
	return []Observation{obs}, nil
}
