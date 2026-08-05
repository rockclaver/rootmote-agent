package diagnose

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Signature is one deterministic PRD 3.2 diagnostic match against a
// collected Bundle.
type Signature struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	EvidenceIDs []string `json:"evidenceIds"`
	Confidence  float64  `json:"confidence"`
}

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
			})
		case "oom_kill":
			out = append(out, Signature{
				ID:          nextID("oom_kill"),
				Type:        "oom_kill",
				Title:       "Kernel OOM-killed a process",
				EvidenceIDs: []string{s.ID},
				Confidence:  1.0,
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
			})
		case comp.Kind == "systemd_unit" && strings.EqualFold(comp.State, "failed"):
			out = append(out, Signature{
				ID:          nextID("unit_failed"),
				Type:        "unit_failed",
				Title:       fmt.Sprintf("%s failed", comp.Name),
				EvidenceIDs: []string{comp.ID},
				Confidence:  0.9,
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
		})
	}

	for _, l := range b.Logs {
		if proxyUpstreamErrorRe.MatchString(l.Content) {
			out = append(out, Signature{
				ID:          nextID("proxy_upstream_error"),
				Type:        "proxy_upstream_error",
				Title:       "Proxy upstream error detected in logs",
				EvidenceIDs: []string{l.ID},
				Confidence:  0.8,
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].ID < out[j].ID
	})
	return out
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
