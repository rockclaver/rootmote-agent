package monitor

// alertRuleOwners maps a legacy agent alert rule (internal/alerts) to the
// monitor kind that evaluates the same condition.
//
// Ownership rule: the legacy alerts manager and this engine both watch the
// host, so once the host is enrolled with a Watchtower relay a single
// condition would otherwise page twice (one infra.alert push from the agent,
// one incident push from the relay). When enrolled, the monitor engine owns
// every rule listed here and the legacy manager keeps its state (inbox feed,
// ack, silence, infra.alerts.* endpoints) but does not publish a
// notification for it. Rules not listed stay legacy-owned until a monitor
// kind covers them; adding that kind here makes the legacy rule yield
// automatically.
var alertRuleOwners = map[string]Kind{
	"disk_usage":     KindDiskCapacity,
	"unit_failed":    KindSystemdUnit,
	"load_sustained": KindLoadPerCore,
}

// OwnsAlertRule reports whether the monitor engine owns the legacy alert
// rule's condition (see alertRuleOwners).
func OwnsAlertRule(rule string) bool {
	_, ok := alertRuleOwners[rule]
	return ok
}
