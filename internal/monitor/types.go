// Package monitor is the agent's Phase 2 local monitor engine (issue #78):
// it evaluates infra/docker/systemd collectors against a small set of
// canonical monitor kinds, drives a per-(kind,target) failure/recovery state
// machine with hysteresis and consecutive-hit debouncing, persists that
// state so an in-progress episode survives a restart, and emits signed
// monitor-event envelopes to the Watchtower relay on firing/resolved
// transitions only -- a single transient failure never pages.
package monitor

import (
	"context"
	"errors"
)

// State is one node in the per-(kind,target) monitor state machine. The
// full enum mirrors the relay/mobile-visible state set (issue #78 §7); the
// agent engine itself only ever transitions through unknown, healthy,
// pending, firing, recovering, resolved, and muted -- acknowledged is a
// mobile/relay-side annotation the agent never assigns.
type State string

const (
	StateUnknown      State = "unknown"
	StateHealthy      State = "healthy"
	StatePending      State = "pending"
	StateFiring       State = "firing"
	StateAcknowledged State = "acknowledged"
	StateRecovering   State = "recovering"
	StateResolved     State = "resolved"
	StateMuted        State = "muted"
)

// inEpisode reports whether s represents an in-progress failing episode
// (started but not yet fully recovered), used to pick the hysteresis
// boundary a threshold-based evaluator compares against: firingThreshold
// before an episode starts, recoveryValue once one is under way.
func (s State) inEpisode() bool {
	switch s {
	case StatePending, StateFiring, StateRecovering, StateAcknowledged:
		return true
	default:
		return false
	}
}

// Kind is one of the five canonical monitor kinds (identical strings across
// agent, relay, and mobile).
type Kind string

const (
	KindDiskCapacity    Kind = "disk_capacity"
	KindInodeCapacity   Kind = "inode_capacity"
	KindMemoryPressure  Kind = "memory_pressure"
	KindDockerContainer Kind = "docker_container"
	KindSystemdUnit     Kind = "systemd_unit"

	KindCPUPressure        Kind = "cpu_pressure"
	KindLoadPerCore        Kind = "load_per_core"
	KindDiskFillRate       Kind = "disk_fill_rate"
	KindCertExpiry         Kind = "cert_expiry"
	KindSystemdTimerFailed Kind = "systemd_timer_failed"
	KindJobFreshness       Kind = "job_freshness"
	KindPortListening      Kind = "port_listening"
	KindProcessRunning     Kind = "process_running"
	KindRebootDetected     Kind = "reboot_detected"
	KindLogErrorSpike      Kind = "log_error_spike"
)

// wildcardTarget marks a built-in default that applies to every instance of
// a dynamically-enumerated kind (every non-ignored container/unit) rather
// than one fixed target.
const wildcardTarget = "*"

// Definition mirrors the agent-facing monitor DTO: a built-in default or a
// relay-synced override for one (Kind, Target) pair.
type Definition struct {
	ID                 string
	ServerID           string
	Kind               Kind
	Target             string
	Enabled            bool
	Severity           string // "warning" | "critical"
	EvaluationLocation string
	FailureThreshold   int
	RecoveryThreshold  int
	CooldownSeconds    int
	FiringThreshold    float64
	RecoveryValue      float64
	Params             map[string]string
}

// failureThreshold returns d.FailureThreshold, defaulting to 3 when unset.
func (d Definition) failureThreshold() int {
	if d.FailureThreshold > 0 {
		return d.FailureThreshold
	}
	return 3
}

// recoveryThreshold returns d.RecoveryThreshold, defaulting to 3 when unset.
func (d Definition) recoveryThreshold() int {
	if d.RecoveryThreshold > 0 {
		return d.RecoveryThreshold
	}
	return 3
}

// cooldownSeconds returns d.CooldownSeconds, defaulting to 300 when unset.
func (d Definition) cooldownSeconds() int {
	if d.CooldownSeconds > 0 {
		return d.CooldownSeconds
	}
	return 300
}

// DefaultDefinitions returns the shipped built-in monitors (issue #78),
// overlaid at runtime by whatever the relay sync returns for the same
// (kind, target).
func DefaultDefinitions() []Definition {
	return []Definition{
		{
			Kind: KindDiskCapacity, Target: "/", Enabled: true, Severity: "critical", EvaluationLocation: "agent",
			FailureThreshold: 3, RecoveryThreshold: 3, CooldownSeconds: 300, FiringThreshold: 90, RecoveryValue: 85,
		},
		// Every other mounted filesystem uses the same thresholds as "/".
		{
			Kind: KindDiskCapacity, Target: wildcardTarget, Enabled: true, Severity: "critical", EvaluationLocation: "agent",
			FailureThreshold: 3, RecoveryThreshold: 3, CooldownSeconds: 300, FiringThreshold: 90, RecoveryValue: 85,
		},
		{
			Kind: KindInodeCapacity, Target: "/", Enabled: true, Severity: "warning", EvaluationLocation: "agent",
			FailureThreshold: 3, RecoveryThreshold: 3, CooldownSeconds: 300, FiringThreshold: 90, RecoveryValue: 85,
		},
		{
			Kind: KindMemoryPressure, Target: "", Enabled: true, Severity: "critical", EvaluationLocation: "agent",
			FailureThreshold: 3, RecoveryThreshold: 3, CooldownSeconds: 300, FiringThreshold: 90, RecoveryValue: 80,
		},
		{
			Kind: KindDockerContainer, Target: wildcardTarget, Enabled: true, Severity: "critical", EvaluationLocation: "agent",
			FailureThreshold: 2, RecoveryThreshold: 3, CooldownSeconds: 300,
		},
		{
			Kind: KindSystemdUnit, Target: wildcardTarget, Enabled: true, Severity: "critical", EvaluationLocation: "agent",
			FailureThreshold: 2, RecoveryThreshold: 3, CooldownSeconds: 300,
		},
		// Sustained-condition monitors. Thresholds count 30s ticks: 10 ticks
		// is ~5 minutes of continuous breach before anything pages.
		{
			Kind: KindCPUPressure, Target: "", Enabled: true, Severity: "warning", EvaluationLocation: "agent",
			FailureThreshold: 10, RecoveryThreshold: 6, CooldownSeconds: 600, FiringThreshold: 95, RecoveryValue: 80,
		},
		{
			Kind: KindLoadPerCore, Target: "", Enabled: true, Severity: "warning", EvaluationLocation: "agent",
			FailureThreshold: 10, RecoveryThreshold: 6, CooldownSeconds: 600, FiringThreshold: 2, RecoveryValue: 1.5,
		},
		// FiringThreshold/RecoveryValue are hours until the disk is full.
		{
			Kind: KindDiskFillRate, Target: "/", Enabled: true, Severity: "warning", EvaluationLocation: "agent",
			FailureThreshold: 3, RecoveryThreshold: 3, CooldownSeconds: 1800, FiringThreshold: 24, RecoveryValue: 36,
		},
		{
			Kind: KindSystemdTimerFailed, Target: wildcardTarget, Enabled: true, Severity: "warning", EvaluationLocation: "agent",
			FailureThreshold: 2, RecoveryThreshold: 2, CooldownSeconds: 300,
		},
		// One event per reboot: fires on the first tick after the boot ID
		// changes and resolves on the next.
		{
			Kind: KindRebootDetected, Target: "", Enabled: true, Severity: "warning", EvaluationLocation: "agent",
			FailureThreshold: 1, RecoveryThreshold: 1, CooldownSeconds: 300,
		},
	}
}

// Observation is one evaluator's read of one (kind,target) instance for the
// current tick.
type Observation struct {
	Target     string
	Failing    bool
	Severity   string
	Summary    string
	Attributes map[string]string

	// Hold marks a target the evaluator still knows about but could not
	// read this tick (collector unavailable, still warming up, transient
	// dial or inspect failure). Its state is left exactly as it was.
	//
	// Every in-episode target of the evaluator's kind that is neither
	// observed nor held after a successful Evaluate is treated as gone (a
	// removed container, a deleted unit, a target the evaluator no longer
	// monitors) and is walked to resolved -- see Manager.retireAbsent. An
	// evaluator must therefore report Hold, never silence, for a target it
	// merely failed to read.
	Hold bool
}

// Evaluator produces observations for one monitor kind from live collector
// state.
type Evaluator interface {
	Kind() Kind
	Evaluate(ctx context.Context) ([]Observation, error)
}

// ErrSourceUnavailable is returned by an evaluator whose whole collector is
// unavailable this tick (e.g. systemd not running). The tick is skipped
// without logging and without retiring absent targets, so every existing
// episode holds.
var ErrSourceUnavailable = errors.New("monitor: collector unavailable")

// AttrReason / ReasonTargetGone mark the resolved event emitted when a
// failing target stops being reported at all, so the relay can close the
// incident without sending a "recovered" push for something that was
// removed.
const (
	AttrReason       = "reason"
	ReasonTargetGone = "target_gone"
)

// key returns the store.MonitorState primary key for one (kind,target).
func key(kind Kind, target string) string {
	return string(kind) + ":" + target
}
