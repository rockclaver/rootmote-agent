// Package systemd implements the Service Manager deep module. It enumerates
// and inspects systemd units through a narrow Client interface and performs
// guarded lifecycle actions (start/stop/restart/enable/disable).
//
// Every mutating action must go through the existing auth.confirm flow on the
// server side; this package owns the *protected-unit* blocklist that refuses
// stop/disable on units the agent must never shoot in the foot
// (sshd/claver-agent/caddy/init), returning a typed error before any client
// call is made.
package systemd

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Unavailable reason codes returned in Status.UnavailableReason.
const (
	ReasonNotSystemd       = "not_systemd"
	ReasonPermissionDenied = "permission_denied"
	ReasonUnknown          = "unknown"
)

// Typed errors.
var (
	// ErrNotSystemd indicates the host does not run systemd.
	ErrNotSystemd = errors.New("systemd: host is not running systemd")
	// ErrProtectedUnit indicates a stop/disable was rejected by the
	// protected-unit guard. The guard fires before any Client call.
	ErrProtectedUnit = errors.New("systemd: action refused on protected unit")
	// ErrUnsupportedAction indicates an unknown lifecycle verb.
	ErrUnsupportedAction = errors.New("systemd: unsupported action")
)

// ProtectedUnitError carries the unit name and reason for a protected
// rejection so the UI can show a precise explanation.
type ProtectedUnitError struct {
	Unit   string
	Action Action
	Reason string
}

func (e *ProtectedUnitError) Error() string {
	return fmt.Sprintf("systemd: %s refused on protected unit %q: %s", e.Action, e.Unit, e.Reason)
}

func (e *ProtectedUnitError) Unwrap() error { return ErrProtectedUnit }

// Action is a typed lifecycle verb.
type Action string

const (
	ActionStart   Action = "start"
	ActionStop    Action = "stop"
	ActionRestart Action = "restart"
	ActionEnable  Action = "enable"
	ActionDisable Action = "disable"
)

var allowedActions = map[Action]struct{}{
	ActionStart: {}, ActionStop: {}, ActionRestart: {},
	ActionEnable: {}, ActionDisable: {},
}

// Unit is a compact summary returned by List.
type Unit struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	LoadState   string `json:"load_state,omitempty"`
	ActiveState string `json:"active_state,omitempty"`
	SubState    string `json:"sub_state,omitempty"`
	// EnabledOnBoot reflects systemd's UnitFileState: "enabled",
	// "disabled", "static", "masked", or "" when unknown.
	EnabledOnBoot string `json:"enabled_on_boot,omitempty"`
	Protected     bool   `json:"protected"`
	ProtectReason string `json:"protect_reason,omitempty"`
}

// UnitDetail is the inspect subset returned by Get.
type UnitDetail struct {
	Unit
	FragmentPath string `json:"fragment_path,omitempty"`
	Following    string `json:"following,omitempty"`
}

// Status is a typed availability snapshot.
type Status struct {
	Available          bool   `json:"available"`
	UnavailableReason  string `json:"unavailable_reason,omitempty"`
	UnavailableMessage string `json:"unavailable_message,omitempty"`
}

// Client is the agent's narrow view of systemd. Real callers get a
// dbus-backed client; tests pass a fake.
type Client interface {
	// Available returns nil when systemd is reachable on this host.
	Available(ctx context.Context) error
	List(ctx context.Context) ([]Unit, error)
	Get(ctx context.Context, name string) (UnitDetail, error)
	Action(ctx context.Context, name string, action Action) error
	// Reboot triggers an immediate reboot of the whole host.
	Reboot(ctx context.Context) error
}

// Config configures the Manager.
type Config struct {
	Client Client
	// ExtraProtected lets the host extend the blocklist (e.g. additional
	// supervisord-style units). The base set is always enforced.
	ExtraProtected []string
}

// Manager is the Service Manager deep module.
type Manager struct {
	client    Client
	protected map[string]string // unit name -> reason
}

// New constructs a Manager. client must be non-nil.
func New(cfg Config) (*Manager, error) {
	if cfg.Client == nil {
		return nil, errors.New("systemd: Client is required")
	}
	protected := map[string]string{
		"sshd.service":         "SSH daemon is the transport into the agent",
		"ssh.service":          "SSH daemon is the transport into the agent",
		"claver-agent.service": "Claver agent supervises itself; refuse self-shutdown",
		"caddy.service":        "Caddy terminates TLS for preview tunnels",
		"init.scope":           "pid-1/init must never be stopped",
	}
	for _, name := range cfg.ExtraProtected {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		protected[name] = "protected by host configuration"
	}
	return &Manager{client: cfg.Client, protected: protected}, nil
}

// Status probes the systemd host.
func (m *Manager) Status(ctx context.Context) Status {
	if err := m.client.Available(ctx); err != nil {
		return Status{
			Available:          false,
			UnavailableReason:  classify(err),
			UnavailableMessage: err.Error(),
		}
	}
	return Status{Available: true}
}

// List returns every unit the client surfaces, decorated with the
// protected-unit flag and reason.
func (m *Manager) List(ctx context.Context) ([]Unit, error) {
	units, err := m.client.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range units {
		units[i] = m.decorate(units[i])
	}
	return units, nil
}

// Get returns a single unit's detail, decorated with the protected-unit flag.
func (m *Manager) Get(ctx context.Context, name string) (UnitDetail, error) {
	if name == "" {
		return UnitDetail{}, errors.New("systemd: unit name required")
	}
	d, err := m.client.Get(ctx, name)
	if err != nil {
		return UnitDetail{}, err
	}
	d.Unit = m.decorate(d.Unit)
	return d, nil
}

// Action performs a lifecycle verb. The protected-unit guard rejects
// stop/disable on protected units before any client call.
func (m *Manager) Action(ctx context.Context, name string, action Action) error {
	if name == "" {
		return errors.New("systemd: unit name required")
	}
	if _, ok := allowedActions[action]; !ok {
		return ErrUnsupportedAction
	}
	if reason, ok := m.protectedReason(name); ok {
		switch action {
		case ActionStop, ActionDisable:
			return &ProtectedUnitError{Unit: name, Action: action, Reason: reason}
		}
	}
	return m.client.Action(ctx, name, action)
}

// Reboot triggers an immediate reboot of the whole host. There is no
// protected-unit check: a full reboot is a host-wide action gated solely by the
// caller's confirmation token, not by the per-unit blocklist.
func (m *Manager) Reboot(ctx context.Context) error {
	return m.client.Reboot(ctx)
}

// IsProtected reports whether name is in the protected-unit blocklist.
func (m *Manager) IsProtected(name string) bool {
	_, ok := m.protectedReason(name)
	return ok
}

// ProtectedUnits returns the protected-unit blocklist (defensive copy).
func (m *Manager) ProtectedUnits() map[string]string {
	out := make(map[string]string, len(m.protected))
	for k, v := range m.protected {
		out[k] = v
	}
	return out
}

func (m *Manager) decorate(u Unit) Unit {
	if reason, ok := m.protectedReason(u.Name); ok {
		u.Protected = true
		u.ProtectReason = reason
	}
	return u
}

func (m *Manager) protectedReason(name string) (string, bool) {
	if reason, ok := m.protected[name]; ok {
		return reason, true
	}
	// Allow lookup without the .service suffix.
	if !strings.Contains(name, ".") {
		if reason, ok := m.protected[name+".service"]; ok {
			return reason, true
		}
	}
	return "", false
}

func classify(err error) string {
	switch {
	case errors.Is(err, ErrNotSystemd):
		return ReasonNotSystemd
	default:
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "permission denied") {
			return ReasonPermissionDenied
		}
		return ReasonUnknown
	}
}
