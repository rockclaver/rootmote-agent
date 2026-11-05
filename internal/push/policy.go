package push

import "github.com/rockclaver/rootmote-agent/internal/notifications"

// Kind is the pref key used to classify a notification for push routing.
// Usually equal to notifications.Notification.Type, except infra.alert,
// which splits into two kinds -- "fired" and "cleared" have opposite
// defaults and an operator may want to override only one of them.
type Kind string

const (
	KindAlertFired   Kind = "infra.alert.fired"
	KindAlertCleared Kind = "infra.alert.cleared"
	KindRunbook      Kind = "infra.runbook"
)

// KindInfo describes one push-eligible notification kind for the settings
// UI: a stable key, an operator-facing label, and the built-in default.
type KindInfo struct {
	Key         string
	Label       string
	DefaultPush bool
}

// KnownKinds lists only active incident-operation producers. Persisted rows for
// retired kinds are intentionally left in SQLite but are not surfaced again.
func KnownKinds() []KindInfo {
	return []KindInfo{
		{Key: string(KindAlertFired), Label: "Infrastructure alert fired", DefaultPush: true},
		{Key: string(KindAlertCleared), Label: "Infrastructure alert recovered", DefaultPush: false},
		{Key: string(KindRunbook), Label: "AI runbook proposed", DefaultPush: false},
	}
}

// defaultPush is KnownKinds() flattened for a fast lookup. Unknown and retired
// types default closed, including any persisted preference row without an
// active producer.
var defaultPush = map[Kind]bool{
	KindAlertFired:   true,
	KindAlertCleared: false,
	KindRunbook:      false,
}

// classify maps a notification to its pref key.
func classify(n notifications.Notification) Kind {
	if n.Type == "infra.alert" {
		if clear, _ := n.Data["clear"].(bool); clear {
			return KindAlertCleared
		}
		return KindAlertFired
	}
	return Kind(n.Type)
}

// pushEligible decides whether n should be pushed, given a set of persisted
// per-kind overrides (Kind -> push_enabled). An override always wins; absent
// a row, unknown kinds default closed (never push) rather than open, so a
// future notification producer doesn't wake every phone in the fleet by
// oversight.
func pushEligible(n notifications.Notification, overrides map[Kind]bool) bool {
	kind := classify(n)
	if _, known := defaultPush[kind]; !known {
		return false
	}
	if enabled, ok := overrides[kind]; ok {
		return enabled
	}
	return defaultPush[kind]
}
