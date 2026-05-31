package inbox

import (
	"context"
	"fmt"
	"time"

	"github.com/rockclaver/claver/agent/internal/aiproposal"
	"github.com/rockclaver/claver/agent/internal/alerts"
	"github.com/rockclaver/claver/agent/internal/notifications"
	"github.com/rockclaver/claver/agent/internal/store"
)

// ProposalSource yields one inbox item per pending AI proposal.
type ProposalSource struct{ Mgr *aiproposal.Manager }

func (s *ProposalSource) Items(_ context.Context) ([]Item, error) {
	if s == nil || s.Mgr == nil {
		return nil, nil
	}
	props := s.Mgr.List()
	out := make([]Item, 0, len(props))
	for _, p := range props {
		if p.Status != aiproposal.StatusPending {
			continue
		}
		out = append(out, Item{
			ID:         "ai_proposal:" + p.ID,
			Type:       TypeAIProposal,
			Title:      "AI proposal: " + string(p.Kind),
			Body:       p.Rationale,
			Severity:   "info",
			CreatedAt:  p.CreatedAt,
			Actionable: true,
			ActionKind: "infra.proposal.approve",
			Data: map[string]any{
				"proposal_id": p.ID,
				"kind":        string(p.Kind),
				"session_id":  p.SessionID,
			},
		})
	}
	return out, nil
}

// AlertSource yields one inbox item per currently-fired infra alert.
type AlertSource struct{ Mgr *alerts.Manager }

func (s *AlertSource) Items(_ context.Context) ([]Item, error) {
	if s == nil || s.Mgr == nil {
		return nil, nil
	}
	active := s.Mgr.ActiveAlerts()
	out := make([]Item, 0, len(active))
	for _, a := range active {
		out = append(out, alertToItem(a))
	}
	return out, nil
}

func alertToItem(a alerts.ActiveAlert) Item {
	body := a.Body
	if body == "" {
		body = fmt.Sprintf("%s on %s", a.RuleKind, a.Target)
	}
	sev := a.Severity
	if sev == "" {
		sev = "warning"
	}
	return Item{
		ID:        "alert:" + a.Key,
		Type:      TypeAlertFired,
		Title:     "Alert: " + a.RuleKind,
		Body:      body,
		Severity:  sev,
		CreatedAt: a.FiredAt,
		Data: map[string]any{
			"rule":   a.RuleKind,
			"target": a.Target,
			"key":    a.Key,
		},
	}
}

// SessionSource yields recently-finished sessions across all projects.
// Sessions are pulled from the store directly so this remains a cheap query.
type SessionSource struct {
	Store *store.Store
	// Window bounds how far back to include finished sessions. Defaults to 24h.
	Window time.Duration
	// Now returns "now"; defaults to time.Now.
	Now func() time.Time
}

func (s *SessionSource) Items(_ context.Context) ([]Item, error) {
	if s == nil || s.Store == nil {
		return nil, nil
	}
	window := s.Window
	if window <= 0 {
		window = 24 * time.Hour
	}
	now := s.Now
	if now == nil {
		now = time.Now
	}
	cutoff := now().Add(-window)
	// ListSessions("") returns all sessions newest-first.
	sessions, err := s.Store.ListSessions("")
	if err != nil {
		return nil, err
	}
	out := make([]Item, 0, len(sessions))
	for _, sess := range sessions {
		if sess.EndedAt == nil {
			continue
		}
		if sess.EndedAt.Before(cutoff) {
			continue
		}
		title := "Session finished"
		if sess.Agent != "" {
			title = sess.Agent + " session finished"
		}
		out = append(out, Item{
			ID:        "session_finished:" + sess.ID,
			Type:      TypeSessionFinished,
			Title:     title,
			Body:      fmt.Sprintf("Project %s — %d in / %d out tokens", sess.ProjectID, sess.InputTokens, sess.OutputTokens),
			Severity:  "info",
			CreatedAt: *sess.EndedAt,
			Data: map[string]any{
				"session_id": sess.ID,
				"project_id": sess.ProjectID,
				"agent":      sess.Agent,
			},
		})
	}
	return out, nil
}

// BridgeAlertNotifications subscribes to the notification hub and republishes
// every infra.alert (non-cleared) notification as an inbox item. This is what
// gives the unified inbox its "fired alert appears within one streaming tick"
// behaviour: alerts.Manager already publishes synchronously to the hub.
//
// The returned cleanup unsubscribes from the hub.
func BridgeAlertNotifications(hub *notifications.Hub, mgr *Manager) func() {
	if hub == nil || mgr == nil {
		return func() {}
	}
	return hub.Subscribe(func(n notifications.Notification) {
		if n.Type != "infra.alert" {
			return
		}
		// alerts.publish sets Data["clear"]=true on a recovery notification.
		// We only surface the firing edge in the inbox; recovery is implicit
		// (the next inbox.list refresh will drop the item).
		if clr, ok := n.Data["clear"].(bool); ok && clr {
			return
		}
		key, _ := n.Data["target"].(string)
		rule, _ := n.Data["rule"].(string)
		if key == "" {
			key = n.ID
		}
		stableKey := rule + ":" + key
		mgr.Publish(Item{
			ID:        "alert:" + stableKey,
			Type:      TypeAlertFired,
			Title:     n.Title,
			Body:      n.Body,
			Severity:  n.Severity,
			CreatedAt: n.CreatedAt,
			Data: map[string]any{
				"rule":   rule,
				"target": key,
				"key":    stableKey,
			},
		})
	})
}
