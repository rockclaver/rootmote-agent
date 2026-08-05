package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
	"github.com/rockclaver/rootmote-agent/internal/docker"
)

// TestIncidentDiagnose_ReturnsAssessmentAndEvidence is a WS round trip
// against a test server wired with a fake docker.Manager: incident.diagnose
// runs the real Collector/Match pipeline (deterministic-only, no
// DiagnoseProposer configured, proving AC6's "AI unavailable" path still
// serves a full diagnosis) and incident.evidence returns the exact bundle
// that diagnosis was built from -- proved by a strictly-increasing fake
// clock: a re-collection would observe a later capturedAt.
func TestIncidentDiagnose_ReturnsAssessmentAndEvidence(t *testing.T) {
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{
		containers: []docker.ContainerSummary{
			{ID: "c1", Name: "api", State: "running", Status: "Up 2 minutes"},
		},
		detail: docker.ContainerDetail{ID: "c1", Name: "api", State: "running", RestartCount: 5},
		logs:   []docker.LogEntry{{ContainerID: "c1", Stream: "stdout", Line: "listening on :8080"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	redactor, err := redact.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	var nowCalls int
	cfg := Config{
		Addr:             "127.0.0.1:0",
		Docker:           mgr,
		DiagnoseRedactor: redactor,
		Now: func() time.Time {
			nowCalls++
			return base.Add(time.Duration(nowCalls) * time.Hour)
		},
	}
	wsURL, stop := startTestServerWith(t, cfg)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	send := func(id, kind string, payload []byte) Frame {
		t.Helper()
		req, _ := json.Marshal(Frame{ID: id, Kind: kind, Payload: payload})
		if err := c.Write(ctx, websocket.MessageText, req); err != nil {
			t.Fatal(err)
		}
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var resp Frame
		if err := json.Unmarshal(data, &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	diagPayload, _ := json.Marshal(map[string]string{
		"incidentId": "inc_1", "monitorKind": "docker_container", "target": "api",
	})
	diagResp := send("d1", "incident.diagnose", diagPayload)
	if diagResp.Kind != "incident.diagnose" {
		t.Fatalf("kind = %q, payload = %s", diagResp.Kind, diagResp.Payload)
	}
	var assessment diagnose.Assessment
	if err := json.Unmarshal(diagResp.Payload, &assessment); err != nil {
		t.Fatalf("decode assessment: %v", err)
	}
	if assessment.IncidentID != "inc_1" {
		t.Fatalf("assessment.IncidentID = %q, want inc_1", assessment.IncidentID)
	}
	if assessment.AIAvailable {
		t.Fatalf("assessment.AIAvailable = true, want false (no DiagnoseProposer configured)")
	}
	if assessment.SummaryText == "" || assessment.Confidence <= 0 {
		t.Fatalf("assessment not populated: %+v", assessment)
	}
	if len(assessment.Hypotheses) == 0 {
		t.Fatalf("assessment has no hypotheses: %+v", assessment)
	}
	foundRestartLoop := false
	for _, sig := range assessment.Signatures {
		if sig.Type == "container_restart_loop" {
			foundRestartLoop = true
		}
	}
	if !foundRestartLoop {
		t.Fatalf("assessment.Signatures = %+v, want a container_restart_loop signature from RestartCount=5", assessment.Signatures)
	}

	// incident.evidence after incident.diagnose must return the SAME
	// bundle the assessment was built from, not a freshly re-collected one:
	// the fake clock strictly increases per Collect() call, so a
	// re-collection would carry a strictly later capturedAt.
	evPayload, _ := json.Marshal(map[string]string{
		"incidentId": "inc_1", "monitorKind": "docker_container", "target": "api",
	})
	evResp := send("e1", "incident.evidence", evPayload)
	if evResp.Kind != "incident.evidence" {
		t.Fatalf("kind = %q, payload = %s", evResp.Kind, evResp.Payload)
	}
	var bundle diagnose.Bundle
	if err := json.Unmarshal(evResp.Payload, &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if !bundle.CapturedAt.Equal(assessment.CapturedAt) {
		t.Fatalf("incident.evidence capturedAt = %v, want the cached bundle's %v (re-collected instead of cached)", bundle.CapturedAt, assessment.CapturedAt)
	}
	if bundle.IncidentID != "inc_1" {
		t.Fatalf("bundle.IncidentID = %q, want inc_1", bundle.IncidentID)
	}
	foundEvidenceSignal := false
	for _, sig := range bundle.Signals {
		if sig.Type == "container_restart_loop" {
			foundEvidenceSignal = true
		}
	}
	if !foundEvidenceSignal {
		t.Fatalf("bundle.Signals = %+v, want the container_restart_loop signal", bundle.Signals)
	}

	// incident.evidence for an incident that was never diagnosed collects a
	// fresh bundle rather than erroring.
	freshPayload, _ := json.Marshal(map[string]string{
		"incidentId": "inc_2", "monitorKind": "docker_container", "target": "api",
	})
	freshResp := send("e2", "incident.evidence", freshPayload)
	var freshBundle diagnose.Bundle
	if err := json.Unmarshal(freshResp.Payload, &freshBundle); err != nil {
		t.Fatalf("decode fresh bundle: %v", err)
	}
	if freshBundle.IncidentID != "inc_2" {
		t.Fatalf("freshBundle.IncidentID = %q, want inc_2", freshBundle.IncidentID)
	}
	if freshBundle.CapturedAt.Equal(bundle.CapturedAt) || freshBundle.CapturedAt.Before(bundle.CapturedAt) {
		t.Fatalf("freshBundle.CapturedAt = %v, want strictly after the first bundle's %v (proves a real collection ran)", freshBundle.CapturedAt, bundle.CapturedAt)
	}
}

func TestIncidentDiagnose_UnconfiguredReturnsUnavailable(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"incidentId": "inc_1"})
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0"}, "incident.diagnose", payload)
	if resp.Kind != "error.unavailable" {
		t.Fatalf("kind = %q, want error.unavailable", resp.Kind)
	}
}

func TestIncidentDiagnose_BadPayloadRejected(t *testing.T) {
	redactor, err := redact.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"monitorKind": "docker_container"})
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", DiagnoseRedactor: redactor}, "incident.diagnose", payload)
	if resp.Kind != "error.bad_payload" {
		t.Fatalf("kind = %q, want error.bad_payload", resp.Kind)
	}
}
