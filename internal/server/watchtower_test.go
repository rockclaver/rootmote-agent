package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rockclaver/rootmote-agent/internal/watchtower"
)

func TestWatchtowerEnable_EnrollsAndStartsLoop(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/register" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agentId": "agt_ws", "serverId": "srv_ws", "secret": "abcdef",
		})
	}))
	defer relay.Close()

	dir := t.TempDir()
	wt, err := watchtower.NewClient(dir, "1.0.0", relay.Client())
	if err != nil {
		t.Fatal(err)
	}
	started := 0

	payload, _ := json.Marshal(map[string]string{
		"relayUrl": relay.URL, "enrollmentCode": "code-1",
	})
	resp := dockerRoundTripConfig(t, Config{
		Addr: "127.0.0.1:0", Watchtower: wt,
		OnWatchtowerEnabled: func() { started++ },
	}, "watchtower.enable", payload)
	if resp.Kind != "watchtower.enable" {
		t.Fatalf("kind = %q, payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		ServerID string `json:"serverId"`
		AgentID  string `json:"agentId"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if out.ServerID != "srv_ws" || out.AgentID != "agt_ws" || out.Status != "protected" {
		t.Fatalf("unexpected watchtower.enable payload: %+v", out)
	}

	if got := wt.Creds(); got == nil || got.AgentID != "agt_ws" {
		t.Fatalf("client not enrolled after watchtower.enable: %+v", got)
	}
	if started != 1 {
		t.Fatalf("OnWatchtowerEnabled calls = %d, want 1", started)
	}
}

func TestWatchtowerEnable_BadPayloadRejected(t *testing.T) {
	dir := t.TempDir()
	wt, err := watchtower.NewClient(dir, "1.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"relayUrl": "http://example.invalid"})
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Watchtower: wt}, "watchtower.enable", payload)
	if resp.Kind != "error.bad_payload" {
		t.Fatalf("kind = %q, want error.bad_payload", resp.Kind)
	}
}

func TestWatchtowerEnable_RelayFailureSurfacesError(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"reused enrollment code"}`))
	}))
	defer relay.Close()

	dir := t.TempDir()
	wt, err := watchtower.NewClient(dir, "1.0.0", relay.Client())
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{
		"relayUrl": relay.URL, "enrollmentCode": "bad-code",
	})
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Watchtower: wt}, "watchtower.enable", payload)
	if resp.Kind != "error.watchtower_error" {
		t.Fatalf("kind = %q, want error.watchtower_error, payload = %s", resp.Kind, resp.Payload)
	}
	if wt.Creds() != nil {
		t.Fatal("client should remain unenrolled after a relay register failure")
	}
}

func TestWatchtowerStatus_UnenrolledAndEnrolled(t *testing.T) {
	dir := t.TempDir()
	wt, err := watchtower.NewClient(dir, "1.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Watchtower: wt}, "watchtower.status", nil)
	if resp.Kind != "watchtower.status" {
		t.Fatalf("kind = %q, payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Enrolled bool `json:"enrolled"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if out.Enrolled {
		t.Fatal("expected enrolled=false before Enroll")
	}
}

func TestWatchtowerKinds_UnconfiguredReturnsUnavailable(t *testing.T) {
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0"}, "watchtower.status", nil)
	if resp.Kind != "error.unavailable" {
		t.Fatalf("kind = %q, want error.unavailable", resp.Kind)
	}
}
