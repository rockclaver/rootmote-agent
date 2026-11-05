package watchtower

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func enrolledClient(t *testing.T, relay *httptest.Server) *Client {
	t.Helper()
	dir := t.TempDir()
	fixed := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	c := &Client{DataDir: dir, AgentVersion: "1.0.0", HTTP: relay.Client(), PlaybookHTTP: relay.Client(), Now: func() time.Time { return fixed }}
	if err := saveCreds(dir, &Creds{RelayURL: relay.URL, AgentID: "agt_1", ServerID: "srv_1", Secret: "abcdef00", Seq: 7}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)
	return c
}

func TestRequestPlaybook_PostsSignedEnvelopeAndDecodesAnswer(t *testing.T) {
	var gotPath string
	var env envelope
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&env)
		_ = json.NewEncoder(w).Encode(PlaybookResponse{Status: PlaybookOK, Playbook: &PlaybookDraft{
			Title: "Restart nginx", Steps: []PlaybookStep{{Step: "service.restart", Params: map[string]any{"unit": "nginx.service"}}},
		}})
	}))
	defer relay.Close()
	c := enrolledClient(t, relay)

	resp, err := c.RequestPlaybook(context.Background(), PlaybookRequest{IncidentID: "inc-1", Kind: "systemd_unit", Severity: "critical", CatalogVersion: 1, UserRequested: true})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/agents/playbooks" {
		t.Fatalf("path = %q", gotPath)
	}
	if resp.Status != PlaybookOK || resp.Playbook == nil || resp.Playbook.Steps[0].Step != "service.restart" {
		t.Fatalf("response = %+v", resp)
	}
	if env.AgentID != "agt_1" || env.ServerID != "srv_1" || env.SequenceNumber != 8 || env.Signature == "" {
		t.Fatalf("envelope = %+v, want agent identity, next sequence number and a signature", env)
	}
	if env.PayloadHash != PayloadHash(env.Payload) {
		t.Fatal("payload hash does not match the payload")
	}
	want, _ := Sign("abcdef00", SigningString("agt_1", "srv_1", 8, env.Timestamp, env.Nonce, env.PayloadHash))
	if env.Signature != want {
		t.Fatal("signature does not verify with the enrolled secret")
	}
	var payload PlaybookRequest
	if err := json.Unmarshal(env.Payload, &payload); err != nil || payload.IncidentID != "inc-1" || !payload.UserRequested {
		t.Fatalf("payload = %+v err = %v", payload, err)
	}
	if c.Creds().Seq != 8 {
		t.Fatalf("sequence = %d, want it persisted as 8", c.Creds().Seq)
	}
}

func TestRequestPlaybook_NonOKAndNotEnrolled(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
	}))
	defer relay.Close()
	c := enrolledClient(t, relay)
	if _, err := c.RequestPlaybook(context.Background(), PlaybookRequest{}); err == nil {
		t.Fatal("a 401 must be an error")
	}
	blank := &Client{DataDir: t.TempDir()}
	if _, err := blank.RequestPlaybook(context.Background(), PlaybookRequest{}); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
}

func TestSendMonitorEvents_ReportsIncidentsTheRelayOpened(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"incidents":[{"eventId":"mevt_a","incidentId":"inc-1"},{"eventId":"mevt_unknown","incidentId":"inc-9"}]}`))
	}))
	defer relay.Close()
	c := enrolledClient(t, relay)
	type pair struct{ event, incident string }
	var got []pair
	c.IncidentOpened = func(ev MonitorEvent, incidentID string) { got = append(got, pair{ev.EventID, incidentID}) }

	events := []MonitorEvent{
		{EventID: "mevt_a", MonitorKind: "systemd_unit", Target: "nginx.service", ToState: "firing"},
		{EventID: "mevt_b", MonitorKind: "systemd_unit", Target: "other.service", ToState: "resolved"},
	}
	if err := c.SendMonitorEvents(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (pair{"mevt_a", "inc-1"}) {
		t.Fatalf("callbacks = %+v, want only the event the batch contained", got)
	}
}

func TestSendMonitorEvents_OlderRelayAnswerIsFine(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer relay.Close()
	c := enrolledClient(t, relay)
	c.IncidentOpened = func(MonitorEvent, string) { t.Fatal("no incident was reported") }
	if err := c.SendMonitorEvents(context.Background(), []MonitorEvent{{EventID: "mevt_a", MonitorKind: "systemd_unit", ToState: "firing"}}); err != nil {
		t.Fatal(err)
	}
}
