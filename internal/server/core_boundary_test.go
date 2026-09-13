package server

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/store"
)

func startCoreServer(t *testing.T, cfg Config) (string, func()) {
	t.Helper()
	srv := New(cfg)
	ln, err := srv.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	return "ws://" + ln.Addr().String() + "/ws", func() { cancel(); <-done }
}

func coreRoundTrip(t *testing.T, url, key string, f Frame) Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	b, _ := json.Marshal(f)
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got Frame
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRetiredRoutesAreUnknownAndCoreReviewRemainsAvailable(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	url, stop := startCoreServer(t, Config{Addr: "127.0.0.1:0", RequirePairing: true, ControlPlaneKey: "core-key", Review: review.New(st)})
	defer stop()

	for _, kind := range []string{
		"project.create", "session.start", "skills.list", "github.repo_list", "action.submit", "preview.start",
		"docker.container.list", "infra.metrics.subscribe", "infra.service.action", "infra.webserver.list",
		"infra.process.kill", "infra.firewall.rule_add", "storage.delete", "security.ai_fix", "infra.snapshot",
		"infra.proposal.create", "infra.proposal.list", "infra.proposal.get",
	} {
		retired := coreRoundTrip(t, url, "core-key", Frame{ID: kind, Kind: kind})
		if retired.Kind != "error.unknown_kind" {
			t.Fatalf("retired %s response = %q", kind, retired.Kind)
		}
	}

	payload, _ := json.Marshal(map[string]any{"action": "incident.runbook.execute", "project_id": "incident-1", "files": []string{"restart:api"}})
	confirmed := coreRoundTrip(t, url, "core-key", Frame{ID: "confirm", Kind: "auth.confirm", Payload: payload})
	if confirmed.Kind != "auth.confirm" {
		t.Fatalf("confirm response = %q", confirmed.Kind)
	}
	audit := coreRoundTrip(t, url, "core-key", Frame{ID: "audit", Kind: "audit.list"})
	if audit.Kind != "audit.list" {
		t.Fatalf("audit response = %q", audit.Kind)
	}
}

func TestPairingRejectsUnauthenticatedWebSocket(t *testing.T) {
	url, stop := startCoreServer(t, Config{Addr: "127.0.0.1:0", RequirePairing: true, ControlPlaneKey: "secret"})
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, err := websocket.Dial(ctx, url, nil); err == nil {
		t.Fatal("unauthenticated pairing succeeded")
	}
}

func TestListenRejectsNonLoopbackAddresses(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.168.1.1:0", "example.com:0"} {
		if _, err := New(Config{Addr: addr}).Listen(); err == nil {
			t.Fatalf("Listen(%q) succeeded", addr)
		}
	}
}

func TestHealthAndReplayDedupeRemainAvailable(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	url, stop := startCoreServer(t, Config{Addr: "127.0.0.1:0", RequirePairing: true, ControlPlaneKey: "dedupe-key", Review: review.New(st)})
	defer stop()
	health := coreRoundTrip(t, url, "dedupe-key", Frame{ID: "health", Kind: "server.health"})
	if health.Kind != "server.health" {
		t.Fatalf("health kind = %q", health.Kind)
	}
	payload, _ := json.Marshal(map[string]any{"action": "incident.runbook.execute", "project_id": "incident-1"})
	first := coreRoundTrip(t, url, "dedupe-key", Frame{ID: "repeat", Kind: "auth.confirm", Payload: payload})
	second := coreRoundTrip(t, url, "dedupe-key", Frame{ID: "repeat", Kind: "auth.confirm", Payload: payload})
	if first.Kind != "auth.confirm" || second.Kind != "auth.confirm" || string(second.Payload) != `{"replay":true}` {
		t.Fatalf("replay was not deduped: %s / %s", first.Payload, second.Payload)
	}
}
