// Package firewall implements the Firewall Manager module. It detects the
// active backend (ufw or firewalld), reads listening sockets and current
// rules, and performs guarded add/remove of rules behind a Backend
// interface. It owns the anti-lockout guard that hard-refuses any edit that
// would deny or remove the active SSH port — resolved from the live
// connection, not user input.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// BackendKind identifies the detected firewall backend.
type BackendKind string

const (
	BackendUFW       BackendKind = "ufw"
	BackendFirewalld BackendKind = "firewalld"
	BackendNone      BackendKind = "none"
)

// Action is the rule action: allow or deny.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// Protocol is the rule transport protocol.
type Protocol string

const (
	ProtoTCP Protocol = "tcp"
	ProtoUDP Protocol = "udp"
	ProtoAny Protocol = "any"
)

// Typed errors.
var (
	// ErrAntiLockout is returned when an edit would deny or remove the
	// active SSH port. The guard fires before any backend call.
	ErrAntiLockout = errors.New("firewall: edit refused by anti-lockout guard")
	// ErrReadOnly is returned when an edit is attempted on a host without
	// a supported backend.
	ErrReadOnly = errors.New("firewall: host has no managed backend; read-only")
	// ErrUnsupportedAction is returned for unknown action verbs.
	ErrUnsupportedAction = errors.New("firewall: unsupported action")
	// ErrRuleNotFound is returned when a remove targets a rule the
	// backend does not surface.
	ErrRuleNotFound = errors.New("firewall: rule not found")
)

// AntiLockoutError carries the offending rule and the resolved SSH port(s)
// so the UI can show a precise explanation.
type AntiLockoutError struct {
	Rule     Rule
	SSHPorts []int
	Reason   string
}

func (e *AntiLockoutError) Error() string {
	return fmt.Sprintf("firewall: anti-lockout refused %s/%s %d → ssh ports %v: %s",
		e.Rule.Action, e.Rule.Protocol, e.Rule.Port, e.SSHPorts, e.Reason)
}

func (e *AntiLockoutError) Unwrap() error { return ErrAntiLockout }

// Rule is a single firewall rule. Source is "" for any source.
type Rule struct {
	Action   Action   `json:"action"`
	Protocol Protocol `json:"protocol"`
	Port     int      `json:"port"`
	Source   string   `json:"source,omitempty"`
	Comment  string   `json:"comment,omitempty"`
}

// Socket is a listening socket as reported by `ss` (or the SocketReader fake).
type Socket struct {
	Protocol Protocol `json:"protocol"`
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	Process  string   `json:"process,omitempty"`
	PID      int      `json:"pid,omitempty"`
}

// Status is the snapshot returned by `infra.firewall.status`.
type Status struct {
	Backend            BackendKind `json:"backend"`
	Available          bool        `json:"available"`
	UnavailableReason  string      `json:"unavailable_reason,omitempty"`
	UnavailableMessage string      `json:"unavailable_message,omitempty"`
	Rules              []Rule      `json:"rules"`
	Sockets            []Socket    `json:"sockets"`
	SSHPorts           []int       `json:"ssh_ports"`
}

// Backend is the agent's narrow view of a firewall backend. Real callers
// get a ufw- or firewalld-backed implementation; tests pass a fake.
type Backend interface {
	Kind() BackendKind
	// Available returns nil when this backend is reachable on the host.
	Available(ctx context.Context) error
	Rules(ctx context.Context) ([]Rule, error)
	Add(ctx context.Context, rule Rule) error
	Remove(ctx context.Context, rule Rule) error
}

// SocketReader returns the host's listening sockets. Real callers shell
// out to `ss -tulnp`; tests pass a fake.
type SocketReader interface {
	Listening(ctx context.Context) ([]Socket, error)
}

// SSHResolver resolves the active SSH port(s) from the live transport.
// The resolution must NOT come from user input — production callers
// inspect listening sockets owned by sshd; tests inject a fixed list.
type SSHResolver interface {
	SSHPorts(ctx context.Context) []int
}

// Config configures the Manager.
type Config struct {
	// Backends, in detection priority order. The first one whose
	// Available() returns nil is selected.
	Backends []Backend
	Sockets  SocketReader
	SSH      SSHResolver
}

// Manager is the Firewall Manager deep module.
type Manager struct {
	backends []Backend
	sockets  SocketReader
	ssh      SSHResolver
}

// New constructs a Manager. Backends is the detection list; the first
// backend whose Available() returns nil at call time is used. Empty or
// all-unavailable falls back to a read-only listening-sockets view.
func New(cfg Config) (*Manager, error) {
	if cfg.Sockets == nil {
		return nil, errors.New("firewall: SocketReader is required")
	}
	if cfg.SSH == nil {
		return nil, errors.New("firewall: SSHResolver is required")
	}
	return &Manager{
		backends: append([]Backend(nil), cfg.Backends...),
		sockets:  cfg.Sockets,
		ssh:      cfg.SSH,
	}, nil
}

// detect picks the first available backend, or nil for read-only.
func (m *Manager) detect(ctx context.Context) (Backend, string) {
	var lastErr error
	for _, b := range m.backends {
		if err := b.Available(ctx); err == nil {
			return b, ""
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, lastErr.Error()
	}
	return nil, "no ufw or firewalld backend present"
}

// Status returns the current snapshot: detected backend, listening
// sockets, current rules (empty for read-only), and the resolved SSH port
// set used by the anti-lockout guard.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	sockets, sockErr := m.sockets.Listening(ctx)
	if sockErr != nil {
		sockets = nil
	}
	sshPorts := m.ssh.SSHPorts(ctx)
	sort.Ints(sshPorts)

	backend, reason := m.detect(ctx)
	if backend == nil {
		st := Status{
			Backend:            BackendNone,
			Available:          false,
			UnavailableReason:  "no_backend",
			UnavailableMessage: reason,
			Rules:              []Rule{},
			Sockets:            sockets,
			SSHPorts:           sshPorts,
		}
		if sockErr != nil {
			st.UnavailableMessage = strings.TrimSpace(reason + "; sockets: " + sockErr.Error())
		}
		return st, nil
	}

	rules, err := backend.Rules(ctx)
	if err != nil {
		return Status{}, err
	}
	return Status{
		Backend:   backend.Kind(),
		Available: true,
		Rules:     rules,
		Sockets:   sockets,
		SSHPorts:  sshPorts,
	}, nil
}

// RuleAdd adds a rule. The anti-lockout guard refuses any deny rule
// covering an active SSH port before any backend call.
func (m *Manager) RuleAdd(ctx context.Context, rule Rule) error {
	if err := validate(rule); err != nil {
		return err
	}
	backend, reason := m.detect(ctx)
	if backend == nil {
		return fmt.Errorf("%w: %s", ErrReadOnly, reason)
	}
	sshPorts := m.ssh.SSHPorts(ctx)
	if rule.Action == ActionDeny && portIn(rule.Port, sshPorts) {
		return &AntiLockoutError{
			Rule:     rule,
			SSHPorts: append([]int(nil), sshPorts...),
			Reason:   "would deny the active SSH port",
		}
	}
	return backend.Add(ctx, rule)
}

// RuleRemove removes a rule. The anti-lockout guard refuses removing any
// allow rule that covers an active SSH port before any backend call.
func (m *Manager) RuleRemove(ctx context.Context, rule Rule) error {
	if err := validate(rule); err != nil {
		return err
	}
	backend, reason := m.detect(ctx)
	if backend == nil {
		return fmt.Errorf("%w: %s", ErrReadOnly, reason)
	}
	sshPorts := m.ssh.SSHPorts(ctx)
	if rule.Action == ActionAllow && portIn(rule.Port, sshPorts) {
		return &AntiLockoutError{
			Rule:     rule,
			SSHPorts: append([]int(nil), sshPorts...),
			Reason:   "would remove the rule allowing the active SSH port",
		}
	}
	return backend.Remove(ctx, rule)
}

// IsSSHRule reports whether the rule's port matches an active SSH port.
// Used by the UI to render the SSH rule pinned/locked.
func (m *Manager) IsSSHRule(ctx context.Context, rule Rule) bool {
	return portIn(rule.Port, m.ssh.SSHPorts(ctx))
}

func validate(r Rule) error {
	switch r.Action {
	case ActionAllow, ActionDeny:
	default:
		return ErrUnsupportedAction
	}
	switch r.Protocol {
	case ProtoTCP, ProtoUDP, ProtoAny:
	default:
		return fmt.Errorf("firewall: unsupported protocol %q", r.Protocol)
	}
	if r.Port <= 0 || r.Port > 65535 {
		return fmt.Errorf("firewall: port %d out of range", r.Port)
	}
	return nil
}

func portIn(port int, ports []int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}
