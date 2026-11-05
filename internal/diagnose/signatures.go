package diagnose

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Signature is one deterministic diagnostic match against a collected
// Bundle.
type Signature struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	EvidenceIDs []string `json:"evidenceIds"`
	Confidence  float64  `json:"confidence"`
	// Subject names what the signature is about: a container, a unit, a
	// killed process, a mount point, a PM2 app or a certificate. For
	// proxy_upstream_error it is "unit:<name>" or "container:<name>" when the
	// backend is a service on this host, and empty when it is not known.
	Subject string `json:"subject,omitempty"`
	// Detail is the redacted evidence text behind the signature.
	Detail string `json:"detail,omitempty"`
}

// Signature types that have no numeric signal behind them.
const (
	SigPM2AppStopped = "pm2_app_stopped"
	SigCertExpiring  = "cert_expiring"
)

// Thresholds used by the deterministic checks below.
const (
	diskExhaustedPercent    = 90.0
	inodeExhaustedPercent   = 90.0
	memoryPressureAvailPct  = 10.0
	restartLoopConfidenceLo = 0.8
)

// proxyUpstreamErrorRe matches the common reverse-proxy upstream failure
// phrases (nginx/caddy/apache) that show up verbatim in access/error logs.
var proxyUpstreamErrorRe = regexp.MustCompile(`(?i)(502\s+bad\s+gateway|bad\s+gateway|upstream\s+(?:connect\s+error|timed?\s*out|prematurely\s+closed|unavailable|refused)|connect\(\)\s+failed)`)

// gatewayStatusRe matches a bare 502/503/504 in a monitor's own summary
// ("http check returned 502"), which has no proxy wording around it.
var gatewayStatusRe = regexp.MustCompile(`\b50[234]\b`)

// MonitorSummarySource is the log source name the collector uses for a
// monitor's own one-line summary.
const MonitorSummarySource = "monitor:summary"

// Match runs the deterministic PRD 3.2 checks against a collected bundle.
// It is pure: no I/O, no clock. Results are sorted by descending confidence
// then ID so the output is stable. Every Signature.EvidenceIDs entry is
// drawn directly from an element of b, so it is guaranteed to exist in
// b.EvidenceIDs().
func Match(b Bundle) []Signature {
	counts := map[string]int{}
	nextID := func(typ string) string {
		counts[typ]++
		if counts[typ] == 1 {
			return "sig_" + typ
		}
		return fmt.Sprintf("sig_%s_%d", typ, counts[typ])
	}

	var out []Signature

	for _, s := range b.Signals {
		switch s.Type {
		case "container_restart_loop":
			out = append(out, Signature{
				ID:          nextID("container_restart_loop"),
				Type:        "container_restart_loop",
				Title:       fmt.Sprintf("Container restarting repeatedly (%d restarts)", int(s.Value)),
				EvidenceIDs: []string{s.ID},
				Confidence:  restartLoopConfidence(s.Value),
				Subject:     s.Subject,
				Detail:      s.Detail,
			})
		case "oom_kill":
			out = append(out, Signature{
				ID:          nextID("oom_kill"),
				Type:        "oom_kill",
				Title:       "Kernel OOM-killed a process",
				EvidenceIDs: []string{s.ID},
				Confidence:  1.0,
				Subject:     s.Subject,
				Detail:      s.Detail,
			})
		}
	}

	for _, comp := range b.Components {
		switch {
		case comp.Kind == "docker_container" && isStoppedState(comp.State):
			out = append(out, Signature{
				ID:          nextID("container_stopped"),
				Type:        "container_stopped",
				Title:       fmt.Sprintf("%s is %s", comp.Name, comp.State),
				EvidenceIDs: []string{comp.ID},
				Confidence:  0.85,
				Subject:     comp.Name,
				Detail:      comp.Detail,
			})
		case comp.Kind == "systemd_unit" && isDownUnitState(comp.State):
			title, conf := fmt.Sprintf("%s failed", comp.Name), 0.9
			if !strings.EqualFold(comp.State, "failed") {
				title, conf = fmt.Sprintf("%s is %s", comp.Name, strings.ToLower(comp.State)), 0.85
			}
			out = append(out, Signature{
				ID:          nextID("unit_failed"),
				Type:        "unit_failed",
				Title:       title,
				EvidenceIDs: []string{comp.ID},
				Confidence:  conf,
				Subject:     comp.Name,
				Detail:      comp.Detail,
			})
		case comp.Kind == "pm2_app" && isStoppedPM2(comp.State):
			out = append(out, Signature{
				ID:          nextID(SigPM2AppStopped),
				Type:        SigPM2AppStopped,
				Title:       fmt.Sprintf("PM2 app %s is %s", comp.Name, comp.State),
				EvidenceIDs: []string{comp.ID},
				Confidence:  0.9,
				Subject:     comp.Name,
				Detail:      comp.Detail,
			})
		case comp.Kind == "certificate" && (comp.State == "expiring" || comp.State == "expired"):
			conf := 0.9
			if comp.State == "expired" {
				conf = 0.95
			}
			out = append(out, Signature{
				ID:          nextID(SigCertExpiring),
				Type:        SigCertExpiring,
				Title:       fmt.Sprintf("Certificate %s is %s", comp.Name, comp.State),
				EvidenceIDs: []string{comp.ID},
				Confidence:  conf,
				Subject:     comp.Name,
				Detail:      comp.Detail,
			})
		}
	}

	for _, m := range b.Metrics {
		switch m.Name {
		case "disk_used_percent":
			if m.Value >= diskExhaustedPercent {
				out = append(out, Signature{
					ID:          nextID("disk_exhausted"),
					Type:        "disk_exhausted",
					Title:       fmt.Sprintf("Disk usage at %.1f%%", m.Value),
					EvidenceIDs: []string{m.ID},
					Confidence:  overThresholdConfidence(m.Value, diskExhaustedPercent),
					Subject:     m.Subject,
				})
			}
		case "inode_used_percent":
			if m.Value >= inodeExhaustedPercent {
				out = append(out, Signature{
					ID:          nextID("inode_exhausted"),
					Type:        "inode_exhausted",
					Title:       fmt.Sprintf("Inode usage at %.1f%%", m.Value),
					EvidenceIDs: []string{m.ID},
					Confidence:  overThresholdConfidence(m.Value, inodeExhaustedPercent),
					Subject:     m.Subject,
				})
			}
		case "available_memory_percent":
			if m.Value <= memoryPressureAvailPct {
				out = append(out, Signature{
					ID:          nextID("memory_pressure"),
					Type:        "memory_pressure",
					Title:       fmt.Sprintf("Host memory pressure (%.1f%% available)", m.Value),
					EvidenceIDs: []string{m.ID},
					Confidence:  underThresholdConfidence(m.Value, memoryPressureAvailPct),
				})
			}
		}
	}

	for _, ch := range b.RecentChanges {
		out = append(out, Signature{
			ID:          nextID("recent_deployment"),
			Type:        "recent_deployment",
			Title:       fmt.Sprintf("Recent change: %s", ch.Detail),
			EvidenceIDs: []string{ch.ID},
			Confidence:  0.5,
			Detail:      ch.Detail,
		})
	}

	var proxyEvidence []string
	for _, l := range b.Logs {
		if proxyUpstreamErrorRe.MatchString(l.Content) || (l.Source == MonitorSummarySource && gatewayStatusRe.MatchString(l.Content)) {
			proxyEvidence = append(proxyEvidence, l.ID)
		}
	}
	if len(proxyEvidence) > 0 {
		upstream := upstreamSubject(b)
		out = append(out, Signature{
			ID:          nextID("proxy_upstream_error"),
			Type:        "proxy_upstream_error",
			Title:       "Proxy upstream error detected in logs",
			EvidenceIDs: proxyEvidence,
			Confidence:  0.8,
			Subject:     upstream,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// upstreamSubject returns "unit:<name>" or "container:<name>" for the first
// proxy backend the collector could tie to a service on this host.
func upstreamSubject(b Bundle) string {
	for _, comp := range b.Components {
		switch comp.Kind {
		case "upstream_unit":
			return "unit:" + comp.Name
		case "upstream_container":
			return "container:" + comp.Name
		}
	}
	return ""
}

// isDownUnitState reports whether a unit's active state means it is not
// running and not on its way up: failed, or stopped on purpose or by a crash.
func isDownUnitState(state string) bool {
	switch strings.ToLower(state) {
	case "failed", "inactive", "deactivating":
		return true
	default:
		return false
	}
}

func isStoppedPM2(state string) bool {
	switch strings.ToLower(state) {
	case "stopped", "errored", "restarting":
		return true
	default:
		return false
	}
}

func isStoppedState(state string) bool {
	switch strings.ToLower(state) {
	case "exited", "dead", "created", "removing":
		return true
	default:
		return false
	}
}

// restartLoopConfidence scales with restart count: more restarts observed,
// higher confidence this is a genuine crash loop rather than a one-off.
func restartLoopConfidence(restarts float64) float64 {
	switch {
	case restarts >= 10:
		return 0.95
	case restarts >= 5:
		return 0.9
	default:
		return restartLoopConfidenceLo
	}
}

// overThresholdConfidence scales confidence up the further value sits past
// threshold, clamped to [0.7, 0.95].
func overThresholdConfidence(value, threshold float64) float64 {
	c := 0.7 + (value-threshold)/100*0.5
	return clamp(c, 0.7, 0.95)
}

// underThresholdConfidence scales confidence up the further value sits
// below threshold (used for "available" style metrics where lower is
// worse), clamped to [0.7, 0.95].
func underThresholdConfidence(value, threshold float64) float64 {
	c := 0.7 + (threshold-value)/threshold*0.3
	return clamp(c, 0.7, 0.95)
}

func clamp(v, lo, hi float64) float64 {
	switch {
	case v < lo:
		return lo
	case v > hi:
		return hi
	default:
		return v
	}
}
