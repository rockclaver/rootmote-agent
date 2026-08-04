// Package monitor is the agent's Phase 2 local monitor engine (issue #78):
// it evaluates infra/docker/systemd collectors against a small set of
// canonical monitor kinds, drives a per-(kind,target) failure/recovery state
// machine with hysteresis and consecutive-hit debouncing, persists that
// state so an in-progress episode survives a restart, and emits signed
// monitor-event envelopes to the Watchtower relay on firing/resolved
// transitions only -- a single transient failure never pages.
package monitor

import "context"

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
}

// Evaluator produces observations for one monitor kind from live collector
// state.
type Evaluator interface {
	Kind() Kind
	Evaluate(ctx context.Context) ([]Observation, error)
}

// key returns the store.MonitorState primary key for one (kind,target).
func key(kind Kind, target string) string {
	return string(kind) + ":" + target
}
