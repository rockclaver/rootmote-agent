// Package alerts evaluates live infra state against persisted alert rules.
package alerts

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/notifications"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

const (
	ServerLocal = "local"

	RuleDiskUsage     = "disk_usage"
	RuleLoadSustained = "load_sustained"
	RuleUnitFailed    = "unit_failed"

	// loadRecoveryRatio places the load_sustained clear level at 75% of its
	// per-core threshold, so load hovering around the threshold stays inside
	// one episode instead of alternating fire/clear.
	loadRecoveryRatio = 0.75
)

type MetricsSampler interface {
	Sample(context.Context) infra.HostMetrics
}

type UnitLister interface {
	Status(context.Context) systemd.Status
	List(context.Context) ([]systemd.Unit, error)
}

type Config struct {
	Store          *store.Store
	Metrics        MetricsSampler
	Systemd        UnitLister
	Sink           notifications.Sink
	Now            func() time.Time
	Cadence        time.Duration
	DiskHysteresis float64
	// CPUCount normalizes load_sustained to load per core. Defaults to
	// runtime.NumCPU().
	CPUCount int
	// LoadFiringFor is how long the 5-minute load per core must stay at or
	// above the rule threshold before load_sustained fires. Default 5m.
	LoadFiringFor time.Duration
	// LoadRecoveryFor is how long it must then stay at or below
	// loadRecoveryRatio of the threshold before the alert clears. Default
	// 10m: a busy box dipping briefly under the threshold keeps one episode.
	LoadRecoveryFor time.Duration
	// UnitConsecutiveHits is the number of consecutive evaluation cycles a
	// systemd unit must be observed failed (or observed healthy again)
	// before its unit_failed alert fires or clears. Without this a unit
	// that flaps faster than Cadence (e.g. a crash-looping service caught
	// mid-restart on alternating polls) pages on every single cycle.
	UnitConsecutiveHits int
	// RenotifyAfter is the quiet window after an alert clears. If the same
	// alert fires again inside it, the previous episode reopens without a
	// new notification. Default 1h.
	RenotifyAfter time.Duration
	// MonitorOwns reports whether the Watchtower monitor engine already
	// pages for a rule's condition (see ownership.go). Nil means the legacy
	// manager owns every rule.
	MonitorOwns func(rule string) bool
}

type Manager struct {
	store *store.Store
	m     MetricsSampler
	sd    UnitLister
	sink  notifications.Sink
	now   func() time.Time

	cadence             time.Duration
	diskHysteresis      float64
	cpuCount            int
	loadFiringHits      int
	loadRecoveryHits    int
	unitConsecutiveHits int
	renotifyAfter       time.Duration
	monitorOwned        func(rule string) bool

	mu     sync.Mutex
	active map[string]alertState
}

type alertState struct {
	active bool
	// hits counts consecutive samples pointing at the opposite state
	// (failing while clear, healthy while firing).
	hits     int
	firedAt  time.Time
	ruleKind string
	target   string
	body     string
	severity string
	// clearedAt is when the last episode cleared; zero if it never has.
	clearedAt time.Time
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

// ActiveAlerts returns a snapshot of all alerts currently in the fired state,
// excluding any that are silenced or whose current firing episode has been
// acknowledged. The inbox feed is built from this, so ack/silence both stop an
// alert from counting toward the unread badge.
func (m *Manager) ActiveAlerts() []ActiveAlert {
	now := m.now()
	silenced, _ := m.store.AlertSilencesActive(now)
	acks, _ := m.store.AlertAcks()

	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ActiveAlert, 0, len(m.active))
	for key, st := range m.active {
		if !st.active {
			continue
		}
		if _, ok := silenced[key]; ok {
			continue
		}
		if firedAt, ok := acks[key]; ok && firedAt.Unix() == st.firedAt.Unix() {
			continue // this firing episode was acknowledged
		}
		out = append(out, ActiveAlert{
			Key: key, RuleKind: st.ruleKind, Target: st.target,
			Body: st.body, Severity: st.severity, FiredAt: st.firedAt,
		})
	}
	return out
}

// Silence suppresses notifications and inbox surfacing for rule+target until
// now+d. A non-positive duration is treated as a no-op clear (use Unsilence).
// Returns the absolute expiry time.
func (m *Manager) Silence(rule, target string, d time.Duration) (time.Time, error) {
	if d <= 0 {
		return time.Time{}, m.Unsilence(rule, target)
	}
	until := m.now().Add(d)
	key := rule + ":" + target
	if err := m.store.PutAlertSilence(key, rule, target, until); err != nil {
		return time.Time{}, err
	}
	return until, nil
}

// Unsilence removes any active silence for rule+target.
func (m *Manager) Unsilence(rule, target string) error {
	return m.store.DeleteAlertSilence(rule + ":" + target)
}

// Ack acknowledges the current firing episode of an alert key. The alert stays
// active (it can re-fire after recovery) but is hidden from the feed until the
// next distinct firing. firedAt must match the episode the operator saw; pass
// the FiredAt from the inbox item.
func (m *Manager) Ack(key string, firedAt time.Time) error {
	return m.store.PutAlertAck(key, firedAt)
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
	if cfg.CPUCount <= 0 {
		cfg.CPUCount = runtime.NumCPU()
	}
	if cfg.LoadFiringFor <= 0 {
		cfg.LoadFiringFor = 5 * time.Minute
	}
	if cfg.LoadRecoveryFor <= 0 {
		cfg.LoadRecoveryFor = 10 * time.Minute
	}
	if cfg.UnitConsecutiveHits <= 0 {
		cfg.UnitConsecutiveHits = 2
	}
	if cfg.RenotifyAfter <= 0 {
		cfg.RenotifyAfter = time.Hour
	}
	return &Manager{
		store:               cfg.Store,
		m:                   cfg.Metrics,
		sd:                  cfg.Systemd,
		sink:                cfg.Sink,
		now:                 cfg.Now,
		cadence:             cfg.Cadence,
		diskHysteresis:      cfg.DiskHysteresis,
		cpuCount:            max(cfg.CPUCount, 1),
		loadFiringHits:      samplesFor(cfg.LoadFiringFor, cfg.Cadence),
		loadRecoveryHits:    samplesFor(cfg.LoadRecoveryFor, cfg.Cadence),
		unitConsecutiveHits: cfg.UnitConsecutiveHits,
		renotifyAfter:       cfg.RenotifyAfter,
		monitorOwned:        cfg.MonitorOwns,
		active:              make(map[string]alertState),
	}, nil
}

// samplesFor converts a hold duration into consecutive evaluation cycles.
func samplesFor(d, cadence time.Duration) int {
	return max(int((d+cadence-1)/cadence), 1)
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
		m.track(ctx, RuleDiskUsage+":"+d.Mountpoint, rule, d.Mountpoint, floatPtr(d.Percent),
			d.Percent >= rule.Threshold, d.Percent <= rule.Threshold-m.diskHysteresis, 1, 1,
			fmt.Sprintf("Disk %s usage %.1f%%", d.Mountpoint, d.Percent),
			fmt.Sprintf("Disk %s recovered to %.1f%%", d.Mountpoint, d.Percent))
	}
}

// evalLoad alerts on the 5-minute load average per CPU core. The 1-minute
// figure jumps on every cron job, deploy, or backup, and an absolute
// threshold means something different on a 1-core VPS and a 32-core host.
// rule.Threshold is therefore load per core.
func (m *Manager) evalLoad(ctx context.Context, rule store.InfraAlertRule, sample infra.HostMetrics) {
	key := RuleLoadSustained + ":host"
	if !rule.Enabled {
		m.clearStatePrefix(key)
		return
	}
	if !sample.Load.Available {
		// A missed sample says nothing about recovery: hold the current
		// state rather than dropping a firing episode and re-paging later.
		return
	}
	perCore := sample.Load.Five / float64(m.cpuCount)
	m.track(ctx, key, rule, "host", floatPtr(perCore),
		perCore >= rule.Threshold, perCore <= rule.Threshold*loadRecoveryRatio,
		m.loadFiringHits, m.loadRecoveryHits,
		fmt.Sprintf("Sustained load %.2f on %d CPUs (%.2f per core)", sample.Load.Five, m.cpuCount, perCore),
		fmt.Sprintf("Load recovered to %.2f on %d CPUs (%.2f per core)", sample.Load.Five, m.cpuCount, perCore))
}

func (m *Manager) evalUnits(ctx context.Context, rule store.InfraAlertRule) {
	if m.sd == nil {
		return
	}
	if !rule.Enabled {
		m.clearStatePrefix(RuleUnitFailed + ":")
		return
	}
	sdStatus := m.sd.Status(ctx)
	if !sdStatus.Available {
		return
	}
	units, err := m.sd.List(ctx)
	if err != nil {
		return
	}
	failed := map[string]bool{}
	for _, u := range units {
		if systemd.IgnoredForFailureAlerts(u) {
			continue
		}
		if strings.EqualFold(u.ActiveState, "failed") || strings.EqualFold(u.SubState, "failed") {
			failed[u.Name] = true
		}
	}
	for name := range failed {
		m.trackUnit(ctx, rule, RuleUnitFailed+":"+name, name, true)
	}

	// Sweep every unit_failed key with state to carry (either already firing,
	// or mid-debounce toward firing) that this poll no longer reports failed,
	// so a recovered/never-confirmed unit's counter moves toward clear.
	m.mu.Lock()
	tracked := make([]string, 0, len(m.active))
	for key, st := range m.active {
		if strings.HasPrefix(key, RuleUnitFailed+":") && (st.active || st.hits > 0) {
			tracked = append(tracked, key)
		}
	}
	m.mu.Unlock()
	for _, key := range tracked {
		unit := strings.TrimPrefix(key, RuleUnitFailed+":")
		if failed[unit] {
			continue
		}
		m.trackUnit(ctx, rule, key, unit, false)
	}
}

// trackUnit debounces a unit's failed/recovered transition: isFailed must
// hold for unitConsecutiveHits consecutive polls before the alert fires or
// clears. A unit that flaps faster than the poll cadence (e.g. a
// crash-looping service caught mid-restart on alternating polls) resets the
// counter instead of paging on every single cycle.
func (m *Manager) trackUnit(ctx context.Context, rule store.InfraAlertRule, key, unit string, isFailed bool) {
	m.track(ctx, key, rule, unit, nil, isFailed, !isFailed, m.unitConsecutiveHits, m.unitConsecutiveHits,
		fmt.Sprintf("%s entered failed state", unit), fmt.Sprintf("%s recovered", unit))
}

// track debounces one alert key. failing and healthy are never both true;
// when neither holds (the value sits inside the hysteresis band) any
// pending transition is cancelled and the current state stands. The alert
// fires after fireHits consecutive failing samples and clears after
// clearHits consecutive healthy ones.
func (m *Manager) track(ctx context.Context, key string, rule store.InfraAlertRule, target string, value *float64, failing, healthy bool, fireHits, clearHits int, enterBody, clearBody string) {
	st := m.state(key)
	toward, need := failing, fireHits
	if st.active {
		toward, need = healthy, clearHits
	}
	if !toward {
		if st.hits != 0 {
			st.hits = 0
			m.setState(key, st)
		}
		return
	}
	st.hits++
	m.setState(key, st)
	if st.hits < need {
		return
	}
	if st.active {
		m.clear(ctx, key, rule, target, value, clearBody)
	} else {
		m.enter(ctx, key, rule, target, value, enterBody)
	}
}

// enter starts a firing episode. If the same alert cleared less than
// renotifyAfter ago, it reopens that episode instead: it is back in the
// inbox under its original firedAt (so an earlier ack still applies), but
// no notification is sent for the repeat.
func (m *Manager) enter(ctx context.Context, key string, rule store.InfraAlertRule, target string, value *float64, body string) {
	st := m.state(key)
	if st.active {
		return
	}
	now := m.now()
	reopen := !st.clearedAt.IsZero() && now.Sub(st.clearedAt) < m.renotifyAfter
	st.active = true
	st.hits = 0
	if !reopen {
		st.firedAt = now
	}
	st.ruleKind = rule.Kind
	st.target = target
	st.body = body
	st.severity = "warning"
	m.setState(key, st)
	if reopen {
		return
	}
	m.publish(ctx, rule, target, value, false, body, st.firedAt)
}

func (m *Manager) clear(ctx context.Context, key string, rule store.InfraAlertRule, target string, value *float64, body string) {
	st := m.state(key)
	if !st.active {
		return
	}
	st.active = false
	st.hits = 0
	st.clearedAt = m.now()
	m.setState(key, st)
	m.publish(ctx, rule, target, value, true, body, st.firedAt)
}

func (m *Manager) publish(ctx context.Context, rule store.InfraAlertRule, target string, value *float64, clear bool, body string, firedAt time.Time) {
	if m.monitorOwns(rule.Kind) {
		return
	}
	if m.sink == nil {
		return
	}
	// While silenced, suppress both the firing push and its clear so a
	// silenced alert never reaches the device. The inbox feed already hides
	// silenced keys via ActiveAlerts.
	if silenced, _ := m.store.AlertSilencesActive(m.now()); silenced != nil {
		if _, ok := silenced[rule.Kind+":"+target]; ok {
			return
		}
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
		// fired_at is the firing episode's timestamp, echoed back by the
		// client on infra.alerts.ack (Manager.Ack requires an exact match --
		// see its doc comment) so an "Acknowledge" tap staged from the OS
		// notification action button acks the right episode.
		"fired_at": firedAt.Unix(),
		// category drives the OS notification action buttons the app renders
		// (acknowledge / silence / open); deep_link routes a tap into the
		// matching inbox item. Recovery ("clear") notifications carry neither
		// since there is nothing to act on.
		"category":  "alert",
		"key":       rule.Kind + ":" + target,
		"deep_link": "alert/" + rule.Kind + ":" + target,
	}
	if clear {
		delete(data, "category")
		delete(data, "deep_link")
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
