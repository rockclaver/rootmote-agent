package push

import "github.com/rockclaver/rootmote-agent/internal/notifications"

// Kind is the pref key used to classify a notification for push routing.
// Usually equal to notifications.Notification.Type, except infra.alert,
// which splits into two kinds -- "fired" and "cleared" have opposite
// defaults and an operator may want to override only one of them.
type Kind string

const (
	KindAlertFired    Kind = "infra.alert.fired"
	KindAlertCleared  Kind = "infra.alert.cleared"
	KindRunbook       Kind = "infra.runbook"
	KindActionDone    Kind = "action.completed"
	KindCIFailed      Kind = "ci_failed"
	KindAIProposal    Kind = "ai_proposal"
	KindPRReview      Kind = "pr_review"
	KindSessionFinish Kind = "session_finished"
)

// KindInfo describes one push-eligible notification kind for the settings
// UI: a stable key, an operator-facing label, and the built-in default.
type KindInfo struct {
	Key         string
	Label       string
	DefaultPush bool
}

// KnownKinds lists every kind the settings screen can present a toggle for.
// A kind only belongs here once its producer actually reaches
// notifications.Hub -- ai_proposal, pr_review, and session_finished are
// deliberately absent: those sources are inbox.Manager-only pull sources
// with no change-detection into the hub yet, so a toggle for them would be
// decorative. See Hub.Forward's doc comment for the wiring each kind needs.
func KnownKinds() []KindInfo {
	return []KindInfo{
		{Key: string(KindAlertFired), Label: "Infrastructure alert fired", DefaultPush: true},
		{Key: string(KindAlertCleared), Label: "Infrastructure alert recovered", DefaultPush: false},
		{Key: string(KindRunbook), Label: "AI runbook proposed", DefaultPush: true},
		{Key: string(KindActionDone), Label: "Action job completed", DefaultPush: true},
		{Key: string(KindCIFailed), Label: "PR's CI failed", DefaultPush: true},
	}
}

// defaultPush is KnownKinds() flattened for a fast lookup, plus the kinds
// that exist but are always inbox/digest-only today (ai_proposal, pr_review,
// session_finished) so an unrecognised type never accidentally pushes.
var defaultPush = map[Kind]bool{
	KindAlertFired:    true,
	KindAlertCleared:  false,
	KindRunbook:       true,
	KindActionDone:    true,
	KindCIFailed:      true,
	KindAIProposal:    false,
	KindPRReview:      false,
	KindSessionFinish: false,
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
	if enabled, ok := overrides[kind]; ok {
		return enabled
	}
	return defaultPush[kind]
}
