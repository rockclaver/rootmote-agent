package monitor

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/watchtower"
)

// StateStore is the subset of *store.Store the engine needs to persist
// per-(kind,target) runtime state across restarts.
type StateStore interface {
	PutMonitorState(store.MonitorState) error
	ListMonitorStates() ([]store.MonitorState, error)
}

// EventSender is the subset of *watchtower.Client the engine needs to emit
// firing/resolved transitions. Enqueue-then-flush (rather than a bare send)
// keeps a transition durable across a mid-send crash and across the relay
// being briefly unreachable.
type EventSender interface {
	EnqueueMonitorEvent(watchtower.MonitorEvent) error
	FlushQueue(ctx context.Context) error
}

// DefaultCadence is the tick interval Config.Cadence defaults to.
const DefaultCadence = 30 * time.Second

// Config configures a Manager.
type Config struct {
	Infra     InfraSampler
	Docker    DockerSource  // optional: nil disables the docker_container evaluator
	Systemd   SystemdSource // optional: nil disables the systemd_unit and systemd_timer_failed evaluators
	Host      Host          // optional: defaults to the real machine (OSHost)
	Sockets   SocketSource  // optional: defaults to ss/netstat
	Processes ProcessSource // optional: defaults to the agent process manager
	Cores     func() int    // optional: logical CPU count for load_per_core; defaults to runtime.NumCPU
	Store     StateStore
	Client    EventSender
	Now       func() time.Time
	Cadence   time.Duration
	Logf      func(format string, args ...any)
}

// Manager is the Phase 2 local monitor engine: it ticks on Cadence,
// evaluates every enabled monitor, drives the per-(kind,target) state
// machine, persists runtime state, and emits events on firing/resolved
// transitions.
type Manager struct {
	store   StateStore
	client  EventSender
	now     func() time.Time
	cadence time.Duration
	logf    func(format string, args ...any)

	defs       *DefinitionSet
	evaluators []Evaluator

	mu     sync.Mutex
	states map[string]store.MonitorState
}

// New constructs a Manager, loading any persisted runtime state from
// cfg.Store so an in-progress episode's FirstFailureAt survives a restart.
func New(cfg Config) (*Manager, error) {
	if cfg.Infra == nil {
		return nil, errors.New("monitor: infra sampler is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("monitor: store is required")
	}
	if cfg.Client == nil {
		return nil, errors.New("monitor: watchtower client is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Cadence <= 0 {
		cfg.Cadence = DefaultCadence
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}

	m := &Manager{
		store:   cfg.Store,
		client:  cfg.Client,
		now:     cfg.Now,
		cadence: cfg.Cadence,
		logf:    cfg.Logf,
		defs:    NewDefinitionSet(DefaultDefinitions()),
		states:  map[string]store.MonitorState{},
	}

	if persisted, err := cfg.Store.ListMonitorStates(); err == nil {
		for _, s := range persisted {
			m.states[s.Key] = s
		}
	} else {
		m.logf("monitor: load persisted state: %v", err)
	}

	m.evaluators = []Evaluator{
		&DiskEvaluator{MonitorKind: KindDiskCapacity, Infra: cfg.Infra, Defs: m.defs, Held: m},
		&DiskEvaluator{MonitorKind: KindInodeCapacity, Infra: cfg.Infra, Defs: m.defs, Held: m},
		&MemoryEvaluator{Infra: cfg.Infra, Defs: m.defs, Held: m, Now: m.now},
	}
	if cfg.Docker != nil {
		m.evaluators = append(m.evaluators, &DockerEvaluator{Docker: cfg.Docker, Defs: m.defs, Now: m.now})
	}
	if cfg.Host == nil {
		cfg.Host = OSHost{}
	}
	if cfg.Sockets == nil {
		cfg.Sockets = defaultSocketSource()
	}
	if cfg.Processes == nil {
		cfg.Processes = defaultProcessSource()
	}
	if cfg.Systemd != nil {
		m.evaluators = append(m.evaluators, &SystemdEvaluator{Systemd: cfg.Systemd, Defs: m.defs})
		m.evaluators = append(m.evaluators, &TimerEvaluator{Systemd: cfg.Systemd, Host: cfg.Host, Defs: m.defs})
	}

	m.evaluators = append(m.evaluators,
		&CPUEvaluator{Infra: cfg.Infra, Defs: m.defs, Held: m},
		&LoadEvaluator{Infra: cfg.Infra, Defs: m.defs, Held: m, Cores: cfg.Cores},
		&DiskFillEvaluator{Infra: cfg.Infra, Defs: m.defs, Held: m, Now: m.now},
		&CertEvaluator{Host: cfg.Host, Defs: m.defs, Held: m, Now: m.now},
		&JobFreshnessEvaluator{Host: cfg.Host, Defs: m.defs, Now: m.now},
		&PortEvaluator{Sockets: cfg.Sockets, Defs: m.defs},
		&LogSpikeEvaluator{Host: cfg.Host, Defs: m.defs, Held: m, Now: m.now},
	)
	if cfg.Processes != nil {
		m.evaluators = append(m.evaluators, &ProcessEvaluator{Procs: cfg.Processes, Defs: m.defs})
	}
	// Without a persistent boot-ID store a reboot cannot be told apart from
	// an agent restart, so the evaluator is only registered with one.
	if boot, ok := cfg.Store.(BootStore); ok {
		m.evaluators = append(m.evaluators, &RebootEvaluator{Host: cfg.Host, Defs: m.defs, Boot: boot})
	}

	return m, nil
}

// SetSyncedDefinitions overlays the relay's monitor definitions and records
// disabled runtime nodes as muted immediately. Evaluators intentionally
// produce no observations for disabled definitions, so waiting for the next
// tick would otherwise leave their persisted state stuck at firing.
func (m *Manager) SetSyncedDefinitions(defs []Definition) {
	m.defs.SetSynced(defs)
	now := m.now()
	var updates []store.MonitorState

	m.mu.Lock()
	for _, def := range defs {
		if def.Enabled {
			continue
		}
		prefix := string(def.Kind) + ":"
		if def.Target != wildcardTarget {
			k := key(def.Kind, def.Target)
			rt := store.MonitorState{Key: k, State: string(StateMuted), LastTransitionAt: now, UpdatedAt: now}
			m.states[k] = rt
			updates = append(updates, rt)
			continue
		}
		for k := range m.states {
			if !strings.HasPrefix(k, prefix) {
				continue
			}
			rt := store.MonitorState{Key: k, State: string(StateMuted), LastTransitionAt: now, UpdatedAt: now}
			m.states[k] = rt
			updates = append(updates, rt)
		}
	}
	m.mu.Unlock()

	for _, rt := range updates {
		if err := m.store.PutMonitorState(rt); err != nil {
			m.logf("monitor: persist muted state %s: %v", rt.Key, err)
		}
	}
}

// DefinitionsFromSync translates the relay's agent-facing monitor DTOs
// (returned by watchtower.Client.SyncMonitors) into engine Definitions.
func DefinitionsFromSync(defs []watchtower.MonitorDef) []Definition {
	out := make([]Definition, 0, len(defs))
	for _, d := range defs {
		if d.EvaluationLocation != "" && d.EvaluationLocation != "agent" {
			continue
		}
		out = append(out, Definition{
			ID:                 d.ID,
			Kind:               Kind(d.Kind),
			Target:             d.Target,
			Enabled:            d.Enabled,
			Severity:           d.Severity,
			EvaluationLocation: d.EvaluationLocation,
			FailureThreshold:   d.FailureThreshold,
			RecoveryThreshold:  d.RecoveryThreshold,
			CooldownSeconds:    d.CooldownSeconds,
			FiringThreshold:    d.FiringThreshold,
			RecoveryValue:      d.RecoveryValue,
			Params:             d.Params,
		})
	}
	return out
}

// WasFailing implements WasFailingResolver by consulting the in-memory
// runtime-state cache (kept in lockstep with the persisted store).
func (m *Manager) WasFailing(kind Kind, target string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.states[key(kind, target)]
	if !ok {
		return false
	}
	return State(rt.State).inEpisode()
}

// Start runs the tick loop in a background goroutine until ctx is done,
// evaluating once immediately and then every Cadence.
func (m *Manager) Start(ctx context.Context) {
	go func() {
		m.Evaluate(ctx)
		ticker := time.NewTicker(m.cadence)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.Evaluate(ctx)
			}
		}
	}()
}

// Evaluate runs every evaluator once and processes their observations
// through the state machine. Exported so tests can drive ticks
// synchronously with a fake clock instead of racing a real ticker.
func (m *Manager) Evaluate(ctx context.Context) {
	for _, ev := range m.evaluators {
		obs, err := ev.Evaluate(ctx)
		if err != nil {
			m.logf("monitor: evaluate %s: %v", ev.Kind(), err)
			continue
		}
		for _, o := range obs {
			m.process(ctx, ev.Kind(), o)
		}
	}
}

func (m *Manager) process(ctx context.Context, kind Kind, obs Observation) {
	now := m.now()
	k := key(kind, obs.Target)
	def, enabled := m.defs.Resolve(kind, obs.Target)

	m.mu.Lock()
	rt, ok := m.states[k]
	if !ok {
		rt = store.MonitorState{Key: k, State: string(StateHealthy), LastTransitionAt: now}
	}

	if !enabled {
		if State(rt.State) != StateMuted {
			rt = store.MonitorState{Key: k, State: string(StateMuted), LastTransitionAt: now, UpdatedAt: now}
			m.states[k] = rt
			m.mu.Unlock()
			if err := m.store.PutMonitorState(rt); err != nil {
				m.logf("monitor: persist muted state %s: %v", k, err)
			}
			return
		}
		m.mu.Unlock()
		return
	}
	if State(rt.State) == StateMuted {
		// Re-enabled: start clean rather than replaying whatever counters
		// were frozen at mute time.
		rt = store.MonitorState{Key: k, State: string(StateHealthy), LastTransitionAt: now}
	}

	newRt, tr := stepState(rt, obs.Failing, now, def)
	newRt.UpdatedAt = now
	m.mu.Unlock()

	if tr != nil {
		eventID, err := watchtower.NewMonitorEventID()
		if err != nil {
			m.logf("monitor: mint event id %s: %v", k, err)
			return
		}
		event := watchtower.MonitorEvent{
			EventID:        eventID,
			MonitorKind:    string(kind),
			Target:         obs.Target,
			FromState:      string(tr.from),
			ToState:        string(tr.to),
			Severity:       firstNonEmptyStr(obs.Severity, def.Severity),
			FirstFailureAt: newRt.FirstFailureAt,
			OccurredAt:     now,
			Summary:        obs.Summary,
			Attributes:     obs.Attributes,
		}
		// Queue first. If the process dies after this point, the transition
		// can be replayed; persisting firing first could lose the only page.
		if err := m.client.EnqueueMonitorEvent(event); err != nil {
			m.logf("monitor: enqueue event %s: %v", k, err)
			return
		}
	}

	m.mu.Lock()
	m.states[k] = newRt
	m.mu.Unlock()
	if err := m.store.PutMonitorState(newRt); err != nil {
		m.logf("monitor: persist state %s: %v", k, err)
	}
	if tr == nil {
		return
	}
	if err := m.client.FlushQueue(ctx); err != nil {
		m.logf("monitor: flush queue after %s: %v", k, err)
	}
}
