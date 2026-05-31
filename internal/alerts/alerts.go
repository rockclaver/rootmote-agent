// Package alerts evaluates live infra state against persisted alert rules.
package alerts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rockclaver/claver/agent/internal/infra"
	"github.com/rockclaver/claver/agent/internal/notifications"
	"github.com/rockclaver/claver/agent/internal/store"
	"github.com/rockclaver/claver/agent/internal/systemd"
)

const (
	ServerLocal = "local"

	RuleDiskUsage     = "disk_usage"
	RuleLoadSustained = "load_sustained"
	RuleUnitFailed    = "unit_failed"
)

type MetricsSampler interface {
	Sample(context.Context) infra.HostMetrics
}

type UnitLister interface {
	Status(context.Context) systemd.Status
	List(context.Context) ([]systemd.Unit, error)
}

type Config struct {
	Store               *store.Store
	Metrics             MetricsSampler
	Systemd             UnitLister
	Sink                notifications.Sink
	Now                 func() time.Time
	Cadence             time.Duration
	DiskHysteresis      float64
	LoadHysteresis      float64
	LoadConsecutiveHits int
}

type Manager struct {
	store *store.Store
	m     MetricsSampler
	sd    UnitLister
	sink  notifications.Sink
	now   func() time.Time

	cadence             time.Duration
	diskHysteresis      float64
	loadHysteresis      float64
	loadConsecutiveHits int

	mu     sync.Mutex
	active map[string]alertState
}

type alertState struct {
	active   bool
	hits     int
	firedAt  time.Time
	ruleKind string
	target   string
	body     string
	severity string
}

// ActiveAlert is a snapshot of one currently-fired alert, suitable for
// surfacing in the unified inbox.
type ActiveAlert struct {
	Key      string
	RuleKind string
	Target   string
	Body     string
	Severity string
	FiredAt  time.Time
}

// ActiveAlerts returns a snapshot of all alerts currently in the fired state.
func (m *Manager) ActiveAlerts() []ActiveAlert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ActiveAlert, 0, len(m.active))
	for key, st := range m.active {
		if !st.active {
			continue
		}
		out = append(out, ActiveAlert{
			Key: key, RuleKind: st.ruleKind, Target: st.target,
			Body: st.body, Severity: st.severity, FiredAt: st.firedAt,
		})
	}
	return out
}

func New(cfg Config) (*Manager, error) {
	if cfg.Store == nil {
		return nil, errors.New("alerts: store is required")
	}
	if cfg.Metrics == nil {
		return nil, errors.New("alerts: metrics sampler is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Cadence <= 0 {
		cfg.Cadence = 30 * time.Second
	}
	if cfg.DiskHysteresis <= 0 {
		cfg.DiskHysteresis = 5
	}
	if cfg.LoadHysteresis <= 0 {
		cfg.LoadHysteresis = 0.5
	}
	if cfg.LoadConsecutiveHits <= 0 {
		cfg.LoadConsecutiveHits = 2
	}
	return &Manager{
		store:               cfg.Store,
		m:                   cfg.Metrics,
		sd:                  cfg.Systemd,
		sink:                cfg.Sink,
		now:                 cfg.Now,
		cadence:             cfg.Cadence,
		diskHysteresis:      cfg.DiskHysteresis,
		loadHysteresis:      cfg.LoadHysteresis,
		loadConsecutiveHits: cfg.LoadConsecutiveHits,
		active:              make(map[string]alertState),
	}, nil
}

func (m *Manager) Config(ctx context.Context, serverID string) ([]store.InfraAlertRule, error) {
	return m.store.ListInfraAlertRules(normServer(serverID))
}

func (m *Manager) SetConfig(ctx context.Context, rule store.InfraAlertRule) (store.InfraAlertRule, error) {
	_ = ctx
	rule.ServerID = normServer(rule.ServerID)
	if rule.Kind == "" {
		return store.InfraAlertRule{}, errors.New("alerts: rule kind required")
	}
	if !knownRule(rule.Kind) {
		return store.InfraAlertRule{}, fmt.Errorf("alerts: unknown rule %q", rule.Kind)
	}
	def := store.DefaultInfraAlertRule(rule.ServerID, rule.Kind)
	if rule.Threshold == 0 {
		rule.Threshold = def.Threshold
	}
	if rule.UpdatedAt.IsZero() {
		rule.UpdatedAt = m.now()
	}
	if err := m.store.PutInfraAlertRule(rule); err != nil {
		return store.InfraAlertRule{}, err
	}
	return rule, nil
}

func (m *Manager) Start(ctx context.Context) {
	ticker := time.NewTicker(m.cadence)
	go func() {
		defer ticker.Stop()
		m.Evaluate(ctx)
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

func (m *Manager) Evaluate(ctx context.Context) {
	rules, err := m.Config(ctx, ServerLocal)
	if err != nil {
		return
	}
	byKind := map[string]store.InfraAlertRule{}
	for _, r := range rules {
		byKind[r.Kind] = r
	}
	sample := m.m.Sample(ctx)
	m.evalDisk(ctx, byKind[RuleDiskUsage], sample)
	m.evalLoad(ctx, byKind[RuleLoadSustained], sample)
	m.evalUnits(ctx, byKind[RuleUnitFailed])
}

func (m *Manager) evalDisk(ctx context.Context, rule store.InfraAlertRule, sample infra.HostMetrics) {
	if !rule.Enabled {
		m.clearStatePrefix(RuleDiskUsage + ":")
		return
	}
	for _, d := range sample.Disks {
		if !d.Available {
			continue
		}
		key := RuleDiskUsage + ":" + d.Mountpoint
		if d.Percent >= rule.Threshold {
			m.enter(ctx, key, rule, d.Mountpoint, floatPtr(d.Percent), fmt.Sprintf("Disk %s usage %.1f%%", d.Mountpoint, d.Percent))
			continue
		}
		if d.Percent <= rule.Threshold-m.diskHysteresis {
			m.clear(ctx, key, rule, d.Mountpoint, floatPtr(d.Percent), fmt.Sprintf("Disk %s recovered to %.1f%%", d.Mountpoint, d.Percent))
		}
	}
}

func (m *Manager) evalLoad(ctx context.Context, rule store.InfraAlertRule, sample infra.HostMetrics) {
	key := RuleLoadSustained + ":host"
	if !rule.Enabled || !sample.Load.Available {
		m.clearStatePrefix(key)
		return
	}
	st := m.state(key)
	if sample.Load.One >= rule.Threshold {
		st.hits++
		m.setState(key, st)
		if st.hits >= m.loadConsecutiveHits {
			m.enter(ctx, key, rule, "host", floatPtr(sample.Load.One), fmt.Sprintf("Sustained load %.2f", sample.Load.One))
		}
		return
	}
	if st.active && sample.Load.One <= rule.Threshold-m.loadHysteresis {
		m.clear(ctx, key, rule, "host", floatPtr(sample.Load.One), fmt.Sprintf("Load recovered to %.2f", sample.Load.One))
		m.setState(key, alertState{})
		return
	}
	if !st.active && st.hits != 0 {
		st.hits = 0
		m.setState(key, st)
	}
}

func (m *Manager) evalUnits(ctx context.Context, rule store.InfraAlertRule) {
	if m.sd == nil {
		return
	}
	if !rule.Enabled {
		m.clearStatePrefix(RuleUnitFailed + ":")
		return
	}
	st := m.sd.Status(ctx)
	if !st.Available {
		return
	}
	units, err := m.sd.List(ctx)
	if err != nil {
		return
	}
	failed := map[string]bool{}
	for _, u := range units {
		if strings.EqualFold(u.ActiveState, "failed") || strings.EqualFold(u.SubState, "failed") {
			failed[u.Name] = true
			m.enter(ctx, RuleUnitFailed+":"+u.Name, rule, u.Name, nil, fmt.Sprintf("%s entered failed state", u.Name))
		}
	}
	m.mu.Lock()
	keys := make([]string, 0)
	for key, st := range m.active {
		if st.active && strings.HasPrefix(key, RuleUnitFailed+":") && !failed[strings.TrimPrefix(key, RuleUnitFailed+":")] {
			keys = append(keys, key)
		}
	}
	m.mu.Unlock()
	for _, key := range keys {
		unit := strings.TrimPrefix(key, RuleUnitFailed+":")
		m.clear(ctx, key, rule, unit, nil, fmt.Sprintf("%s recovered", unit))
	}
}

func (m *Manager) enter(ctx context.Context, key string, rule store.InfraAlertRule, target string, value *float64, body string) {
	st := m.state(key)
	if st.active {
		return
	}
	st.active = true
	st.firedAt = m.now()
	st.ruleKind = rule.Kind
	st.target = target
	st.body = body
	st.severity = "warning"
	m.setState(key, st)
	m.publish(ctx, rule, target, value, false, body)
}

func (m *Manager) clear(ctx context.Context, key string, rule store.InfraAlertRule, target string, value *float64, body string) {
	st := m.state(key)
	if !st.active {
		return
	}
	st.active = false
	st.hits = 0
	m.setState(key, st)
	m.publish(ctx, rule, target, value, true, body)
}

func (m *Manager) publish(ctx context.Context, rule store.InfraAlertRule, target string, value *float64, clear bool, body string) {
	if m.sink == nil {
		return
	}
	severity := "warning"
	title := "Infrastructure alert"
	if clear {
		severity = "resolved"
		title = "Infrastructure alert cleared"
	}
	data := map[string]any{
		"server_id":  rule.ServerID,
		"rule":       rule.Kind,
		"target":     target,
		"threshold":  rule.Threshold,
		"clear":      clear,
		"updated_at": rule.UpdatedAt.Unix(),
	}
	if value != nil {
		data["value"] = *value
	}
	_ = m.sink.Publish(ctx, notifications.Notification{
		ID:        fmt.Sprintf("infra-alert-%d", m.now().UnixNano()),
		Type:      "infra.alert",
		Title:     title,
		Body:      body,
		Severity:  severity,
		CreatedAt: m.now(),
		Data:      data,
	})
}

func floatPtr(v float64) *float64 {
	return &v
}

func (m *Manager) state(key string) alertState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[key]
}

func (m *Manager) setState(key string, st alertState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[key] = st
}

func (m *Manager) clearStatePrefix(prefix string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.active {
		if strings.HasPrefix(key, prefix) {
			delete(m.active, key)
		}
	}
}

func normServer(serverID string) string {
	if strings.TrimSpace(serverID) == "" {
		return ServerLocal
	}
	return serverID
}

func knownRule(kind string) bool {
	switch kind {
	case RuleDiskUsage, RuleLoadSustained, RuleUnitFailed:
		return true
	default:
		return false
	}
}
