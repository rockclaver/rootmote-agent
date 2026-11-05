package watchtower

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/store"
)

// RemediationEvent is the redacted remediation lifecycle event posted to
// the relay, field-for-field matching the relay's remediationEventWire
// (watchtower/internal/server/remediation.go) -- deliberately no field for
// a command, output, credential, or the raw confirmation token; only the
// token's audit id (TokenID) is ever projected. json tags must match the
// relay's exactly since the relay decodes this same shape out of the
// signed envelope's payload.event.
type RemediationEvent struct {
	EventID          string   `json:"eventId"`
	Kind             string   `json:"kind"`
	Actor            string   `json:"actor,omitempty"`
	Detail           string   `json:"detail,omitempty"`
	OccurredAt       string   `json:"occurredAt,omitempty"`
	RunbookID        string   `json:"runbookId,omitempty"`
	ExecutionID      string   `json:"executionId,omitempty"`
	ContentHash      string   `json:"contentHash,omitempty"`
	Risk             string   `json:"risk,omitempty"`
	DiagnosisID      string   `json:"diagnosisId,omitempty"`
	ProviderVersion  string   `json:"providerVersion,omitempty"`
	TokenID          string   `json:"tokenId,omitempty"`
	ResultSummary    string   `json:"resultSummary,omitempty"`
	MonitorIDs       []string `json:"monitorIds,omitempty"`
	StabilitySeconds int      `json:"stabilitySeconds,omitempty"`
}

// remediationEventPayload is the signed envelope's inner payload for one
// lifecycle projection, mirroring the relay's remediationEventPayload.
type remediationEventPayload struct {
	Kind       string           `json:"kind"`
	IncidentID string           `json:"incidentId"`
	Event      RemediationEvent `json:"event"`
}

// SendRemediationEvent posts one redacted remediation lifecycle event to
// relayURL/v1/incidents/{incidentId}/remediation-events. It reuses the
// same signed-envelope construction as Heartbeat (SigningString,
// PayloadHash, Sign, newNonce, saveCreds/envelope) -- the
// payload kind is "remediation_event". As with those, the sequence number
// is incremented and persisted to the credential file BEFORE the request
// is sent, so a crash mid-request never reuses a sequence number the relay
// may already have processed. Returns ErrNotEnrolled if Enroll has not
// succeeded yet.
func (c *Client) SendRemediationEvent(ctx context.Context, incidentID string, ev RemediationEvent) error {
	c.mu.Lock()
	if c.creds == nil {
		c.mu.Unlock()
		return ErrNotEnrolled
	}
	next := *c.creds
	next.Seq++
	if err := saveCreds(c.DataDir, &next); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("watchtower: persist sequence: %w", err)
	}
	c.creds = &next
	creds := next
	c.mu.Unlock()

	payload := remediationEventPayload{Kind: "remediation_event", IncidentID: incidentID, Event: ev}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	timestamp := c.now().UTC().Format(time.RFC3339)
	payloadHash := PayloadHash(payloadBytes)
	signingString := SigningString(creds.AgentID, creds.ServerID, creds.Seq, timestamp, nonce, payloadHash)
	sig, err := Sign(creds.Secret, signingString)
	if err != nil {
		return err
	}
	env := envelope{
		AgentID:        creds.AgentID,
		ServerID:       creds.ServerID,
		SequenceNumber: creds.Seq,
		Timestamp:      timestamp,
		Nonce:          nonce,
		PayloadHash:    payloadHash,
		Payload:        json.RawMessage(payloadBytes),
		Signature:      sig,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	url := creds.RelayURL + "/v1/incidents/" + incidentID + "/remediation-events"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("watchtower: remediation-event: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("watchtower: remediation-event: relay returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// Relay-accepted remediation event kinds this package produces. These are a
// subset of the relay's full store.RemediationEventTimelineType vocabulary
// (watchtower/internal/store/store.go): the rollback_* kinds have no agent
// producer yet because remediation.Manager derives a rollback as a NEW
// execution (with its own propose/approve/execute lifecycle) rather than
// emitting rollback events on the original one.
//
// "step_result" is deliberately absent: it carries raw exit codes and
// command output, which is exactly what the relay's
// remediationForbiddenKeys rejects by design.
const (
	relayKindRunbookProposed          = "runbook_proposed"
	relayKindRunbookBlocked           = "runbook_blocked"
	relayKindRunbookApproved          = "runbook_approved"
	relayKindRunbookDeclined          = "runbook_declined"
	relayKindExecutionStarted         = "execution_started"
	relayKindExecutionFailed          = "execution_failed"
	relayKindVerificationStarted      = "verification_started"
	relayKindInternalVerificationPass = "internal_verification_passed"
	relayKindInternalVerificationFail = "internal_verification_failed"
)

// remediationEventData is the subset of fields this package's own
// remediation.Manager actually writes into store.RemediationEvent.Data's
// JSON (see appendEvent's call sites in internal/remediation/remediation.go)
// for the event types translateRemediationEvent understands. Fields it
// does not recognise (in particular step_result's "output"/"exit_code",
// which are exactly what the relay's remediationForbiddenKeys blocks) are
// simply never read.
type remediationEventData struct {
	Passed     *bool  `json:"passed"`
	Detail     string `json:"detail"`
	Error      string `json:"error"`
	FailedStep *int   `json:"failed_step"`
	Reason     string `json:"reason"`
	// Lifecycle-milestone fields. The relay consumes these to build its
	// redacted runbook/execution projections: without risk + content hash
	// on runbook_proposed it cannot record what was approved, and without
	// the monitor ids + stability window on verification_started it never
	// opens an external verification request.
	Risk             string   `json:"risk"`
	DiagnosisID      string   `json:"diagnosis_id"`
	ProviderVersion  string   `json:"provider_version"`
	ContentHash      string   `json:"content_hash"`
	TokenID          string   `json:"token_id"`
	Steps            *int     `json:"steps"`
	MonitorIDs       []string `json:"monitor_ids"`
	StabilitySeconds *int     `json:"stability_seconds"`
}

// translateRemediationEvent maps one agent-local store.RemediationEvent.Type
// to the relay's accepted kind vocabulary, filling only the fields derived
// from the event's own Data. ok is false for any type with no relay-accepted
// counterpart (notably "step_result", which carries raw step output/exit
// codes and must never reach the relay) -- the caller must skip projecting
// rather than error.
//
// The returned RemediationEvent is partial: the caller owns the identity
// fields it resolves from the execution row (event id, runbook id, execution
// id, content hash, occurred-at, actor).
func translateRemediationEvent(ev store.RemediationEvent) (RemediationEvent, bool) {
	var d remediationEventData
	// Best-effort decode: malformed Data (should never happen -- Manager
	// always marshals it itself) still yields a bare, kind-only projection
	// rather than dropping the event.
	_ = json.Unmarshal([]byte(ev.Data), &d)

	switch ev.Type {
	case "runbook_proposed":
		return RemediationEvent{
			Kind:            relayKindRunbookProposed,
			Detail:          proposedDetail(d),
			Risk:            d.Risk,
			DiagnosisID:     d.DiagnosisID,
			ProviderVersion: d.ProviderVersion,
		}, true
	case "runbook_blocked":
		detail := d.Reason
		if detail == "" {
			detail = "destructive runbook blocked by default"
		}
		return RemediationEvent{Kind: relayKindRunbookBlocked, Detail: detail, Risk: d.Risk}, true
	case "runbook_approved":
		// TokenID is the confirmation token's AUDIT id, never the token.
		return RemediationEvent{Kind: relayKindRunbookApproved, TokenID: d.TokenID}, true
	case "runbook_declined":
		return RemediationEvent{Kind: relayKindRunbookDeclined, Detail: d.Reason}, true
	case "execution_started":
		detail := ""
		if d.Steps != nil {
			detail = fmt.Sprintf("%d step(s)", *d.Steps)
		}
		return RemediationEvent{Kind: relayKindExecutionStarted, Detail: detail, TokenID: d.TokenID}, true
	case "verification_started":
		out := RemediationEvent{Kind: relayKindVerificationStarted, MonitorIDs: d.MonitorIDs}
		if d.StabilitySeconds != nil {
			out.StabilitySeconds = *d.StabilitySeconds
		}
		return out, true
	case "remediation_failed":
		var detail string
		switch {
		case d.Reason != "":
			detail = d.Reason
		case d.FailedStep != nil:
			detail = fmt.Sprintf("step %d failed", *d.FailedStep)
		default:
			detail = "remediation failed"
		}
		return RemediationEvent{Kind: relayKindExecutionFailed, Detail: detail}, true
	case "internal_verification":
		kind := relayKindInternalVerificationFail
		if d.Passed != nil && *d.Passed {
			kind = relayKindInternalVerificationPass
		}
		detail := d.Detail
		if d.Error != "" {
			if detail != "" {
				detail += ": " + d.Error
			} else {
				detail = d.Error
			}
		}
		return RemediationEvent{Kind: kind, Detail: detail, ResultSummary: d.Detail}, true
	default:
		return RemediationEvent{}, false
	}
}

// proposedDetail summarizes a proposal for the incident timeline without
// naming a single command.
func proposedDetail(d remediationEventData) string {
	switch {
	case d.Steps != nil && d.Risk != "":
		return fmt.Sprintf("%s runbook, %d step(s)", d.Risk, *d.Steps)
	case d.Risk != "":
		return d.Risk + " runbook"
	case d.Steps != nil:
		return fmt.Sprintf("%d step(s)", *d.Steps)
	default:
		return "runbook proposed"
	}
}

// RemediationExecutionStore is the narrow, read-only lookup
// RemediationProjector needs to resolve one execution's IncidentID,
// RunbookID, and ContentHash -- store.RemediationEvent itself carries only
// ExecutionID/Seq/Type/Data/CreatedAt (see internal/store's doc comment on
// RemediationEvent), not the incident the relay's
// POST /v1/incidents/{id}/remediation-events path requires. *store.Store
// satisfies this; main.go wires the very same instance it already hands to
// remediation.Config.Store.
type RemediationExecutionStore interface {
	GetExecution(id string) (store.RemediationExecution, error)
}

// RemediationProjector adapts remediation.Manager's local
// store.RemediationEvent lifecycle events to SendRemediationEvent's relay
// wire shape, so internal/remediation stays a pure local-execution engine
// with no relay transport dependency of its own (it only knows the
// Projector interface). It lives in internal/watchtower rather than
// internal/remediation because internal/store has no dependency on
// internal/watchtower, so importing store here -- the only way to type
// RemediationExecutionStore and share store.RemediationEvent -- introduces
// no import cycle, whereas the reverse (watchtower living inside
// remediation) would.
//
// Projection is always best-effort, matching remediation.Manager's own
// invariant that a Projector failure never loses the local record: a nil
// Client, an unenrolled Client, an event kind the relay does not accept,
// or a failed execution lookup all return nil rather than propagating an
// error that could be mistaken for something Manager should react to.
type RemediationProjector struct {
	// Client posts the translated event. A nil Client makes Project a
	// permanent no-op, so it is safe to wire this projector even when
	// watchtower is disabled (main.go's wtClient may be nil).
	Client *Client
	// Store resolves ev.ExecutionID to its owning incident/runbook. A nil
	// Store makes Project a no-op (logged) rather than panicking.
	Store RemediationExecutionStore
	// Logf receives debug notices for skipped events (unmapped kind,
	// missing store, failed lookup). Defaults to no-op when nil -- unlike
	// Client.Logf, silence is the safe default here: an unmapped kind
	// (e.g. every step_result) is expected, routine traffic, not a fault.
	Logf func(format string, args ...any)
}

func (p RemediationProjector) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf("rootmote-agent: watchtower: "+format, args...)
	}
}

// Project implements remediation.Projector.
func (p RemediationProjector) Project(ctx context.Context, ev store.RemediationEvent) error {
	if p.Client == nil || p.Client.Creds() == nil {
		return nil
	}
	wire, ok := translateRemediationEvent(ev)
	if !ok {
		p.logf("remediation event kind %q has no relay projection, skipping", ev.Type)
		return nil
	}
	if p.Store == nil {
		p.logf("no execution store wired, cannot resolve incident for remediation event %q, skipping", ev.Type)
		return nil
	}
	exec, err := p.Store.GetExecution(ev.ExecutionID)
	if err != nil {
		p.logf("resolve execution %s for remediation projection: %v", ev.ExecutionID, err)
		return nil
	}
	// Identity fields come from the execution row, never from the event's
	// own Data, so a malformed Data blob can never misattribute an event.
	wire.EventID = fmt.Sprintf("%s#%d", ev.ExecutionID, ev.Seq)
	wire.Actor = "agent"
	wire.OccurredAt = ev.CreatedAt.UTC().Format(time.RFC3339)
	wire.RunbookID = exec.RunbookID
	wire.ExecutionID = ev.ExecutionID
	if wire.ContentHash == "" {
		wire.ContentHash = exec.RunbookHash
	}
	return p.Client.SendRemediationEvent(ctx, exec.IncidentID, wire)
}
