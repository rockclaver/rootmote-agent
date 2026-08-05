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
)

// DiagnosticHypothesis mirrors diagnose.Hypothesis field-for-field.
type DiagnosticHypothesis struct {
	Cause       string   `json:"cause"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidenceIds"`
}

// DiagnosticAction mirrors diagnose.RecommendedAction field-for-field.
type DiagnosticAction struct {
	ActionID         string `json:"actionId"`
	Risk             string `json:"risk"`
	Reason           string `json:"reason"`
	RequiresApproval bool   `json:"requiresApproval"`
}

// DiagnosticSummary mirrors diagnose.Summary field-for-field. It is
// duplicated here -- rather than importing internal/diagnose -- so this
// package stays a pure outbound HTTP client with no dependency on the
// diagnosis pipeline; only the wire shape (json tags) needs to match.
type DiagnosticSummary struct {
	Summary            string                 `json:"summary"`
	Impact             string                 `json:"impact,omitempty"`
	ProbableCause      string                 `json:"probableCause,omitempty"`
	Confidence         float64                `json:"confidence"`
	Uncertain          bool                   `json:"uncertain"`
	AIAvailable        bool                   `json:"aiAvailable"`
	AIProvider         string                 `json:"aiProvider,omitempty"`
	RedactionApplied   bool                   `json:"redactionApplied"`
	Hypotheses         []DiagnosticHypothesis `json:"hypotheses"`
	RecommendedActions []DiagnosticAction     `json:"recommendedActions"`
	MissingEvidence    []string               `json:"missingEvidence"`
	CapturedAt         time.Time              `json:"capturedAt"`
}

type diagnosticSummaryPayload struct {
	Kind       string            `json:"kind"`
	IncidentID string            `json:"incidentId"`
	Summary    DiagnosticSummary `json:"summary"`
}

// SendDiagnosticSummary posts the REDACTED summary for one incident to
// relayURL/v1/incidents/{incidentId}/diagnostic-summary. It reuses the same
// signed-envelope construction as Heartbeat and SendMonitorEvents
// (SigningString, PayloadHash, Sign, newNonce, saveCreds/envelope) -- the
// payload kind is "diagnostic_summary". As with those, the sequence number
// is incremented and persisted to the credential file BEFORE the request is
// sent, so a crash mid-request never reuses a sequence number the relay may
// already have processed. Returns ErrNotEnrolled if Enroll has not
// succeeded yet.
func (c *Client) SendDiagnosticSummary(ctx context.Context, incidentID string, s DiagnosticSummary) error {
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

	payload := diagnosticSummaryPayload{Kind: "diagnostic_summary", IncidentID: incidentID, Summary: s}
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
	url := creds.RelayURL + "/v1/incidents/" + incidentID + "/diagnostic-summary"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("watchtower: diagnostic-summary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("watchtower: diagnostic-summary: relay returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}
