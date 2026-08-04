package monitor

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

// WasFailingResolver exposes the engine's own state-machine view of whether
// (kind,target) is currently mid-episode (pending/firing/recovering),
// consulted only so a threshold evaluator picks the correct side of the
// hysteresis band -- firingThreshold before an episode starts, recoveryValue
// once one is under way -- never to short-circuit evaluation itself.
type WasFailingResolver interface {
	WasFailing(kind Kind, target string) bool
}

// evalThreshold applies firingThreshold/recoveryValue hysteresis: while no
// episode is under way, crossing firingThreshold starts failing; once an
// episode has started, the value must drop below recoveryValue to count as
// success again, so a value sitting in the band between the two (e.g.
// 85-90% for the default disk monitor) never flaps.
func evalThreshold(value float64, firingThreshold, recoveryValue float64, currentlyInEpisode bool) bool {
	if currentlyInEpisode {
		return value >= recoveryValue
	}
	return value >= firingThreshold
}

// InfraSampler is the subset of *infra.Manager the disk/inode/memory
// evaluators need.
type InfraSampler interface {
	Sample(ctx context.Context) infra.HostMetrics
	OOMEvents(ctx context.Context, since time.Time) ([]infra.OOMEvent, error)
}

// DiskEvaluator evaluates disk_capacity or inode_capacity for every
// mountpoint with a definition (default "/", plus any relay-synced
// mountpoint-specific monitor).
type DiskEvaluator struct {
	MonitorKind Kind // KindDiskCapacity or KindInodeCapacity
	Infra       InfraSampler
	Defs        DefinitionResolver
	Held        WasFailingResolver
}

func (e *DiskEvaluator) Kind() Kind { return e.MonitorKind }

func (e *DiskEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	targets := e.Defs.Targets(e.MonitorKind)
	if len(targets) == 0 {
		return nil, nil
	}
	sample := e.Infra.Sample(ctx)
	byMount := make(map[string]infra.DiskMetric, len(sample.Disks))
	for _, d := range sample.Disks {
		byMount[d.Mountpoint] = d
	}
	var out []Observation
	for _, target := range targets {
		def, enabled := e.Defs.Resolve(e.MonitorKind, target)
		if !enabled {
			continue
		}
		d, ok := byMount[target]
		if !ok || !d.Available {
			continue
		}
		var value float64
		var label string
		switch e.MonitorKind {
		case KindInodeCapacity:
			value, label = d.InodePercent, "inodes"
		default:
			value, label = d.Percent, "disk"
		}
		failing := evalThreshold(value, def.FiringThreshold, def.RecoveryValue, e.Held.WasFailing(e.MonitorKind, target))
		out = append(out, Observation{
			Target:   target,
			Failing:  failing,
			Severity: def.Severity,
			Summary:  fmt.Sprintf("%s %s at %.0f%% (fires >=%.0f%%)", label, target, value, def.FiringThreshold),
			Attributes: map[string]string{
				"percent": strconv.FormatFloat(value, 'f', 1, 64),
			},
		})
	}
	return out, nil
}

// MemoryEvaluator evaluates the single host-wide memory_pressure monitor:
// memory percent used, with any OOM kill in the last 5 minutes forcing a
// failing observation regardless of the percent threshold.
type MemoryEvaluator struct {
	Infra InfraSampler
	Defs  DefinitionResolver
	Held  WasFailingResolver
	Now   func() time.Time
}

func (e *MemoryEvaluator) Kind() Kind { return KindMemoryPressure }

func (e *MemoryEvaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// oomWindow is how far back MemoryEvaluator looks for OOM kills that force a
// failing observation, per the contract's "any OOM in last 5 minutes".
const oomWindow = 5 * time.Minute

func (e *MemoryEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	def, enabled := e.Defs.Resolve(KindMemoryPressure, "")
	if !enabled {
		return nil, nil
	}
	sample := e.Infra.Sample(ctx)
	memoryPercent := sample.Memory.Percent
	swapPercent := sample.Swap.Percent
	// Memory.Percent is derived from MemAvailable (not free pages), and swap
	// is an independent pressure signal. Whichever is worse drives the same
	// hysteresis thresholds; both values remain attached as evidence.
	value := max(memoryPercent, swapPercent)
	failing := evalThreshold(value, def.FiringThreshold, def.RecoveryValue, e.Held.WasFailing(KindMemoryPressure, ""))
	attrs := map[string]string{
		"percent":        strconv.FormatFloat(value, 'f', 1, 64),
		"memory_percent": strconv.FormatFloat(memoryPercent, 'f', 1, 64),
		"swap_percent":   strconv.FormatFloat(swapPercent, 'f', 1, 64),
	}
	summary := fmt.Sprintf("memory %.0f%%, swap %.0f%% (fires >=%.0f%%)", memoryPercent, swapPercent, def.FiringThreshold)
	events, err := e.Infra.OOMEvents(ctx, e.now().Add(-oomWindow))
	if err != nil {
		return nil, fmt.Errorf("monitor: memory_pressure: OOMEvents: %w", err)
	}
	if len(events) > 0 {
		failing = true
		last := events[len(events)-1]
		if last.Process != "" {
			attrs["oomProcess"] = last.Process
		}
		if last.ContainerID != "" {
			attrs["oomContainer"] = last.ContainerID
		}
		summary = fmt.Sprintf("memory %.0f%%, swap %.0f%%; OOM kill in last %s", memoryPercent, swapPercent, oomWindow)
	}
	return []Observation{{Target: "", Failing: failing, Severity: def.Severity, Summary: summary, Attributes: attrs}}, nil
}

// DockerSource is the subset of *docker.Manager the docker_container
// evaluator needs.
type DockerSource interface {
	Containers(ctx context.Context) ([]docker.ContainerSummary, error)
	Container(ctx context.Context, id string) (docker.ContainerDetail, error)
}

// crashLoopWindow is how far back DockerEvaluator looks for restart-count
// increases when deciding a container is crash-looping.
const crashLoopWindow = 5 * time.Minute

// crashLoopRestarts is the number of restarts inside crashLoopWindow that
// marks a container as crash-looping.
const crashLoopRestarts = 3

// restartTrack tracks one container's restart history for crash-loop
// detection: lastCount is the most recently observed RestartCount, and
// increases holds one timestamp per observed increment, pruned to
// crashLoopWindow on every evaluation.
type restartTrack struct {
	lastCount int
	increases []time.Time
}

// DockerEvaluator evaluates docker_container for every container Docker
// reports (the wildcard "*" default monitor covers every non-ignored
// container; a relay-synced monitor can disable one by name).
type DockerEvaluator struct {
	Docker DockerSource
	Defs   DefinitionResolver
	Now    func() time.Time

	restarts map[string]*restartTrack
}

func (e *DockerEvaluator) Kind() Kind { return KindDockerContainer }

func (e *DockerEvaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *DockerEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	summaries, err := e.Docker.Containers(ctx)
	if err != nil {
		return nil, err
	}
	if e.restarts == nil {
		e.restarts = map[string]*restartTrack{}
	}
	now := e.now()
	seen := make(map[string]bool, len(summaries))
	var out []Observation
	for _, s := range summaries {
		target := s.Name
		def, enabled := e.Defs.Resolve(KindDockerContainer, target)
		if !enabled {
			continue
		}
		seen[s.ID] = true
		restartCount := 0
		if detail, derr := e.Docker.Container(ctx, s.ID); derr == nil {
			restartCount = detail.RestartCount
		}
		crashLoop := e.trackCrashLoop(s.ID, restartCount, now)
		stopped := !strings.EqualFold(s.State, "running")
		unhealthy := strings.EqualFold(s.Health, "unhealthy")
		failing := stopped || unhealthy || crashLoop
		summary := fmt.Sprintf("%s is %s", target, s.State)
		switch {
		case crashLoop:
			summary = fmt.Sprintf("%s is crash-looping (%d restarts/%s)", target, crashLoopRestarts, crashLoopWindow)
		case unhealthy:
			summary = fmt.Sprintf("%s is unhealthy", target)
		}
		out = append(out, Observation{
			Target:   target,
			Failing:  failing,
			Severity: def.Severity,
			Summary:  summary,
			Attributes: map[string]string{
				"state":         s.State,
				"health":        s.Health,
				"restart_count": strconv.Itoa(restartCount),
			},
		})
	}
	for id := range e.restarts {
		if !seen[id] {
			delete(e.restarts, id)
		}
	}
	return out, nil
}

// trackCrashLoop records an increase in restartCount (one timestamp per
// increment, since Docker can report more than one restart between polls)
// and reports whether crashLoopRestarts increments have landed inside the
// trailing crashLoopWindow.
func (e *DockerEvaluator) trackCrashLoop(containerID string, restartCount int, now time.Time) bool {
	tr := e.restarts[containerID]
	if tr == nil {
		tr = &restartTrack{lastCount: restartCount}
		e.restarts[containerID] = tr
	}
	if delta := restartCount - tr.lastCount; delta > 0 {
		for range delta {
			tr.increases = append(tr.increases, now)
		}
		tr.lastCount = restartCount
	}
	cutoff := now.Add(-crashLoopWindow)
	kept := tr.increases[:0]
	for _, t := range tr.increases {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	tr.increases = kept
	return len(tr.increases) >= crashLoopRestarts
}

// SystemdSource is the subset of *systemd.Manager the systemd_unit evaluator
// needs.
type SystemdSource interface {
	Status(ctx context.Context) systemd.Status
	List(ctx context.Context) ([]systemd.Unit, error)
}

// SystemdEvaluator evaluates systemd_unit for every unit systemd reports
// (the wildcard "*" default monitor covers every unit; a relay-synced
// monitor can disable one by name).
type SystemdEvaluator struct {
	Systemd SystemdSource
	Defs    DefinitionResolver
}

func (e *SystemdEvaluator) Kind() Kind { return KindSystemdUnit }

func (e *SystemdEvaluator) Evaluate(ctx context.Context) ([]Observation, error) {
	status := e.Systemd.Status(ctx)
	if !status.Available {
		return nil, nil
	}
	units, err := e.Systemd.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []Observation
	for _, u := range units {
		def, enabled := e.Defs.Resolve(KindSystemdUnit, u.Name)
		if !enabled {
			continue
		}
		failing := strings.EqualFold(u.ActiveState, "failed")
		out = append(out, Observation{
			Target:     u.Name,
			Failing:    failing,
			Severity:   def.Severity,
			Summary:    fmt.Sprintf("%s is %s", u.Name, u.ActiveState),
			Attributes: map[string]string{"active_state": u.ActiveState},
		})
	}
	return out, nil
}
