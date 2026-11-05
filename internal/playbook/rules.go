package playbook

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/steps"
)

// phpFPMUnit matches the units phpfpm.restart accepts.
var phpFPMUnit = regexp.MustCompile(`^php[0-9.]*-fpm(\.service)?$`)

// FromBundle builds the catalog playbook for an incident from its evidence,
// or reports false when no fixed rule fits. The highest-confidence signature
// that has a rule wins.
func FromBundle(f Facts) (Playbook, bool) {
	if f.Signatures == nil {
		f.Signatures = diagnose.Match(f.Bundle)
	}
	// Signatures about the incident itself decide the playbook. Host-wide
	// signatures (an OOM kill of some other process, a full disk somewhere
	// else) are often true but are not what this incident is about: they must
	// not hide "this unit is stopped", and they must not replace "the proxy
	// cannot reach its upstream" with an unrelated clean-up. They are used
	// only when nothing about the incident itself was found.
	relevant := false
	for _, sig := range f.Signatures {
		if relevantToIncident(sig, f.Bundle.Service) {
			relevant = true
			if pb, ok := FromSignature(sig, f); ok {
				return pb, true
			}
		}
	}
	if relevant {
		return Playbook{}, false
	}
	for _, sig := range f.Signatures {
		if pb, ok := FromSignature(sig, f); ok {
			return pb, true
		}
	}
	return Playbook{}, false
}

// FromSignature maps one deterministic signature to a playbook made only of
// catalog steps on things that exist in the inventory. It reports false when
// the signature has no rule or the thing it names is not on this server.
func FromSignature(sig diagnose.Signature, f Facts) (Playbook, bool) {
	var pb Playbook
	var ok bool
	switch sig.Type {
	case "container_restart_loop", "container_stopped":
		pb, ok = containerPlaybook(sig, f)
	case "unit_failed":
		pb, ok = unitPlaybook(sig, f)
	case "oom_kill":
		pb, ok = oomPlaybook(sig, f)
	case "disk_exhausted", "inode_exhausted":
		pb, ok = diskPlaybook(sig, f)
	case diagnose.SigCertExpiring:
		pb, ok = certPlaybook(sig, f)
	case "proxy_upstream_error":
		pb, ok = proxyPlaybook(sig, f)
	case diagnose.SigPM2AppStopped:
		pb, ok = pm2Playbook(sig, f)
	}
	if !ok {
		return Playbook{}, false
	}
	pb.Source = runbook.SourceCatalog
	if pb.Summary == "" {
		pb.Summary = sig.Title
	}
	return pb, true
}

func restartStep(unit string) Step {
	if phpFPMUnit.MatchString(unit) {
		return Step{Step: steps.PHPFPMRestartID, Params: steps.Params{"unit": unit}}
	}
	return Step{Step: steps.ServiceRestartID, Params: steps.Params{"unit": unit}}
}

// component finds the evidence component a signature cites.
func component(f Facts, sig diagnose.Signature, kind string) (diagnose.Component, bool) {
	for _, id := range sig.EvidenceIDs {
		for _, c := range f.Bundle.Components {
			if c.ID == id && c.Kind == kind {
				return c, true
			}
		}
	}
	return diagnose.Component{}, false
}

func hasSignature(f Facts, typ string) (diagnose.Signature, bool) {
	for _, s := range f.Signatures {
		if s.Type == typ {
			return s, true
		}
	}
	return diagnose.Signature{}, false
}

// --- containers ---

func containerPlaybook(sig diagnose.Signature, f Facts) (Playbook, bool) {
	name := sig.Subject
	if name == "" || !f.Inventory.hasContainer(name) {
		return Playbook{}, false
	}
	pb := Playbook{Summary: sig.Title}
	comp, _ := firstContainerComponent(f, name)
	project, service := comp.ComposeProject, comp.ComposeService
	if project != "" && service != "" && hasCompose(f.Inventory, project, service) {
		pb.Title = "Bring " + service + " back up"
		pb.Steps = []Step{{Step: steps.ComposeUpID, Params: steps.Params{"project": project, "service": service}}}
	} else {
		pb.Title = "Restart " + name
		pb.Steps = []Step{{Step: steps.ContainerRestartID, Params: steps.Params{"container": name}}}
	}
	if sig.Type == "container_restart_loop" {
		pb.Manual = append(pb.Manual, Manual{
			Text:    "If it keeps restarting, read the last lines of its log to see why it stops.",
			Command: "docker logs --tail 100 " + name,
		})
	}
	if dep, ok := hasSignature(f, "recent_deployment"); ok {
		text := "Check the last deploy."
		if dep.Detail != "" {
			text += " " + dep.Detail + "."
		}
		pb.Manual = append(pb.Manual, Manual{Text: text})
	}
	return pb, true
}

func firstContainerComponent(f Facts, name string) (diagnose.Component, bool) {
	for _, c := range f.Bundle.Components {
		if c.Kind == "docker_container" && c.Name == name {
			return c, true
		}
	}
	return diagnose.Component{}, false
}

func hasCompose(inv Inventory, project, service string) bool {
	for _, c := range inv.ComposeServices {
		if c.Project == project && c.Service == service {
			return true
		}
	}
	return false
}

// --- units ---

func unitPlaybook(sig diagnose.Signature, f Facts) (Playbook, bool) {
	unit := sig.Subject
	if unit == "" || !f.Inventory.hasUnit(unit) || steps.CheckUnitAllowed(unit) != nil {
		return Playbook{}, false
	}
	return Playbook{
		Title:   "Restart " + unit,
		Summary: sig.Title,
		Steps:   []Step{restartStep(unit)},
	}, true
}

// --- out of memory ---

// processUnitAliases lists the unit names a killed process usually runs
// under, for processes whose name differs from the unit's.
var processUnitAliases = map[string][]string{
	"mysqld":       {"mysql", "mysqld", "mariadb"},
	"mariadbd":     {"mariadb", "mysql"},
	"postgres":     {"postgresql"},
	"redis-server": {"redis-server", "redis"},
	"apache2":      {"apache2"},
	"httpd":        {"httpd"},
	"mongod":       {"mongod"},
}

// unitForProcess finds the one unit a killed process belongs to. It returns
// false when no unit, or more than one, matches.
func unitForProcess(proc string, inv Inventory) (string, bool) {
	proc = strings.ToLower(strings.TrimSpace(proc))
	if proc == "" {
		return "", false
	}
	candidates := map[string]bool{proc: true, strings.TrimSuffix(proc, "d"): true}
	for _, a := range processUnitAliases[proc] {
		candidates[a] = true
	}
	var found []string
	for _, u := range inv.Units {
		base := lowerBase(u)
		if candidates[base] || (strings.HasPrefix(proc, "php-fpm") && phpFPMUnit.MatchString(u)) {
			found = append(found, u)
		}
	}
	if len(found) != 1 {
		return "", false
	}
	return found[0], true
}

func metricValue(b diagnose.Bundle, name string) (float64, bool) {
	for _, m := range b.Metrics {
		if m.Name == name {
			return m.Value, true
		}
	}
	return 0, false
}

func oomPlaybook(sig diagnose.Signature, f Facts) (Playbook, bool) {
	pb := Playbook{Summary: sig.Title}
	proc := sig.Subject
	if sig.Detail != "" {
		pb.Summary = sig.Detail
	}
	if unit, ok := unitForProcess(proc, f.Inventory); ok && steps.CheckUnitAllowed(unit) == nil {
		pb.Title = "Restart " + unit + " after it ran out of memory"
		pb.Steps = []Step{restartStep(unit)}
	} else {
		pb.Title = "The server ran out of memory"
	}
	used, haveUsed := metricValue(f.Bundle, "memory_used_percent")
	total, haveTotal := metricValue(f.Bundle, "memory_total_mb")
	swapTotal, haveSwap := metricValue(f.Bundle, "swap_total_mb")
	swapUsed, haveSwapUsed := metricValue(f.Bundle, "swap_used_percent")
	var facts []string
	if haveUsed && haveTotal {
		facts = append(facts, fmt.Sprintf("Memory is %.0f%% used out of %.0f MB.", used, total))
	}
	if haveSwap {
		if swapTotal == 0 {
			facts = append(facts, "The server has no swap space.")
		} else if haveSwapUsed {
			facts = append(facts, fmt.Sprintf("Swap is %.0f%% used out of %.0f MB.", swapUsed, swapTotal))
		}
	}
	text := "Restarting only frees memory for a while. Find what uses the most memory, and add swap space or move to a server with more memory."
	if len(facts) > 0 {
		text = strings.Join(facts, " ") + " " + text
	}
	pb.Manual = append(pb.Manual, Manual{Text: text, Command: "ps aux --sort=-%mem | head -6"})
	if haveSwap && swapTotal == 0 {
		pb.Manual = append(pb.Manual, Manual{
			Text:    "To add 1 GB of swap space:",
			Command: "fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile",
		})
	}
	return pb, true
}

// --- disk and inodes ---

func diskPlaybook(sig diagnose.Signature, f Facts) (Playbook, bool) {
	pb := Playbook{Title: "Free up disk space", Summary: sig.Title}
	if sig.Type == "inode_exhausted" {
		pb.Title = "Free up file slots"
	}
	mount := sig.Subject
	if mount == "" {
		mount = "/"
	}
	// Each clean-up frees space in one known folder. It is offered only when
	// that folder is on the disk that ran out; on another disk it would do
	// nothing for this incident.
	var elsewhere bool
	offer := func(s Step) {
		if f.DiskMounts[s.Step] == mount {
			pb.Steps = append(pb.Steps, s)
		} else {
			elsewhere = true
		}
	}
	if f.Inventory.hasUnit("systemd-journald.service") {
		offer(Step{Step: steps.JournalVacuumID, Params: steps.Params{"size": "200M"}})
	}
	if len(f.Inventory.Containers) > 0 {
		offer(Step{Step: steps.DockerPruneID, Params: steps.Params{}})
	}
	if d := strings.ToLower(f.OS.Distro); d == "ubuntu" || d == "debian" {
		offer(Step{Step: steps.AptCleanID, Params: steps.Params{}})
	}
	if elsewhere && len(pb.Steps) == 0 {
		pb.Manual = append(pb.Manual, Manual{
			Text: "The usual automatic clean-ups (system logs, Docker data, package cache) free space on a different disk than " + mount + ", so they would not help here.",
		})
	}
	var dirs []string
	for _, s := range f.Bundle.Signals {
		if s.Type == "large_directory" && len(dirs) < 5 {
			dirs = append(dirs, fmt.Sprintf("%d. %s (%.0f MB)", len(dirs)+1, s.Subject, s.Value))
		}
	}
	if len(dirs) > 0 {
		pb.Manual = append(pb.Manual, Manual{
			Text: "The biggest folders on " + mount + " are: " + strings.Join(dirs, "; ") + ". Remove what you no longer need.",
		})
	} else {
		pb.Manual = append(pb.Manual, Manual{
			Text:    "Find the biggest folders on " + mount + " and remove what you no longer need.",
			Command: "du -xh --max-depth=2 " + mount + " 2>/dev/null | sort -rh | head -6",
		})
	}
	return pb, true
}

// --- certificates ---

func certPlaybook(sig diagnose.Signature, f Facts) (Playbook, bool) {
	name := sig.Subject
	if name == "" || !contains(f.Inventory.Certs, name) {
		return Playbook{}, false
	}
	return Playbook{
		Title:   "Renew the certificate for " + name,
		Summary: sig.Title,
		Steps:   []Step{{Step: steps.CertRenewID, Params: steps.Params{"name": name}}},
	}, true
}

// --- reverse proxy ---

func proxyPlaybook(sig diagnose.Signature, f Facts) (Playbook, bool) {
	kind, name, _ := strings.Cut(sig.Subject, ":")
	pb := Playbook{Summary: sig.Title}
	switch {
	case kind == "unit" && f.Inventory.hasUnit(name) && steps.CheckUnitAllowed(name) == nil:
		pb.Title = "Restart " + name
		pb.Steps = []Step{restartStep(name)}
	case kind == "container" && f.Inventory.hasContainer(name):
		pb.Title = "Restart " + name
		pb.Steps = []Step{{Step: steps.ContainerRestartID, Params: steps.Params{"container": name}}}
	default:
		return Playbook{}, false
	}
	if url, ok := checkURL(f); ok {
		pb.Steps = append(pb.Steps, Step{Step: steps.CheckHTTPID, Params: steps.Params{"url": url}})
	}
	return pb, true
}

// checkURL picks the address check.http should request: the incident's own
// target when it is a known address, else a known address on the same host.
func checkURL(f Facts) (string, bool) {
	if f.Target != "" && contains(f.Inventory.URLs, f.Target) {
		return f.Target, true
	}
	host := hostOf(f.Target)
	if host == "" {
		return "", false
	}
	for _, u := range f.Inventory.URLs {
		if hostOf(u) == host {
			return u, true
		}
	}
	return "", false
}

func hostOf(target string) string {
	t := strings.TrimSpace(target)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, ":"); i >= 0 {
		t = t[:i]
	}
	return strings.ToLower(t)
}

// --- PM2 ---

func pm2Playbook(sig diagnose.Signature, f Facts) (Playbook, bool) {
	comp, ok := component(f, sig, "pm2_app")
	if !ok {
		return Playbook{}, false
	}
	known := false
	for _, a := range f.Inventory.PM2Apps {
		if a.App == comp.Name && a.User == comp.Owner {
			known = true
		}
	}
	if !known {
		return Playbook{}, false
	}
	return Playbook{
		Title:   "Restart " + comp.Name,
		Summary: sig.Title,
		Steps:   []Step{{Step: steps.PM2RestartID, Params: steps.Params{"app": comp.Name, "user": comp.Owner}}},
	}, true
}

// relevantToIncident reports whether sig is about the incident's own subject:
// it names the incident's service, it is not a host-wide signature, or the
// incident is the monitor for that very resource.
func relevantToIncident(sig diagnose.Signature, svc diagnose.Service) bool {
	if svc.Name != "" && sig.Subject == svc.Name {
		return true
	}
	switch sig.Type {
	case "oom_kill":
		return svc.Kind == "memory_pressure"
	case "disk_exhausted":
		return svc.Kind == "disk_capacity" || svc.Kind == "disk_fill_rate"
	case "inode_exhausted":
		return svc.Kind == "inode_capacity"
	}
	return true
}
