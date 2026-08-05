package watchtower

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendDiagnosticSummary_PostsSignedEnvelopeToIncidentPath(t *testing.T) {
	var gotPath string
	var gotBody []byte
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b := make([]byte, 0)
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				break
			}
		}
		gotBody = b
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer relay.Close()

	dir := t.TempDir()
	fixedNow := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	c := &Client{DataDir: dir, AgentVersion: "1.0.0", HTTP: relay.Client(), Now: func() time.Time { return fixedNow }}
	if err := saveCreds(dir, &Creds{RelayURL: relay.URL, AgentID: "agt_diag", ServerID: "srv_diag", Secret: "abcdef00", Seq: 3}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)

	summary := DiagnosticSummary{
		Summary:          "The API container is being killed because the host has exhausted available memory.",
		ProbableCause:    "Container exceeded available host memory",
		Confidence:       0.93,
		Uncertain:        false,
		AIAvailable:      true,
		AIProvider:       "claude",
		RedactionApplied: true,
		Hypotheses: []DiagnosticHypothesis{
			{Cause: "Container exceeded available host memory", Confidence: 0.93, EvidenceIDs: []string{"sig_oom_kill"}},
		},
		RecommendedActions: []DiagnosticAction{
			{ActionID: "restart_api_after_memory_reclaim", Risk: "medium", Reason: "Reclaim memory and restart.", RequiresApproval: true},
		},
		MissingEvidence: []string{"container memory limit"},
		CapturedAt:      fixedNow,
	}

	if err := c.SendDiagnosticSummary(context.Background(), "inc_01", summary); err != nil {
		t.Fatalf("SendDiagnosticSummary: %v", err)
	}

	if gotPath != "/v1/incidents/inc_01/diagnostic-summary" {
		t.Fatalf("path = %q, want /v1/incidents/inc_01/diagnostic-summary", gotPath)
	}
	if got := c.Creds().Seq; got != 4 {
		t.Fatalf("seq after send = %d, want 4 (incremented once)", got)
	}

	var env envelope
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.AgentID != "agt_diag" || env.ServerID != "srv_diag" || env.SequenceNumber != 4 {
		t.Fatalf("envelope identity = %+v, want agt_diag/srv_diag/4", env)
	}

	var payload diagnosticSummaryPayload
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Kind != "diagnostic_summary" {
		t.Fatalf("payload.Kind = %q, want diagnostic_summary", payload.Kind)
	}
	if payload.IncidentID != "inc_01" {
		t.Fatalf("payload.IncidentID = %q, want inc_01", payload.IncidentID)
	}
	if payload.Summary.ProbableCause != summary.ProbableCause || payload.Summary.Confidence != summary.Confidence {
		t.Fatalf("payload.Summary = %+v, want it to mirror the posted summary", payload.Summary)
	}
	if len(payload.Summary.Hypotheses) != 1 || payload.Summary.Hypotheses[0].Cause != "Container exceeded available host memory" {
		t.Fatalf("payload.Summary.Hypotheses = %+v", payload.Summary.Hypotheses)
	}

	// Verify the signature the exact way the relay's verifier would.
	seen := map[string]bool{}
	if err := referenceVerify("abcdef00", "agt_diag", "srv_diag", gotBody, fixedNow, 5*time.Minute, seen); err != nil {
		t.Fatalf("valid envelope rejected by reference verifier: %v", err)
	}
}

func TestSendDiagnosticSummary_RequiresEnrollment(t *testing.T) {
	dir := t.TempDir()
	c := &Client{DataDir: dir, AgentVersion: "1.0.0", HTTP: &captureDoer{}}
	err := c.SendDiagnosticSummary(context.Background(), "inc_01", DiagnosticSummary{Summary: "x"})
	if err != ErrNotEnrolled {
		t.Fatalf("SendDiagnosticSummary before enrollment = %v, want ErrNotEnrolled", err)
	}
}
