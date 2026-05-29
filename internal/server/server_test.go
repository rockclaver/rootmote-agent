package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/store"
	"github.com/rockclaver/claver/agent/internal/version"
)

// startTestServer brings up a server on a real loopback port and returns the
// ws URL plus a cancel function.
func startTestServer(t *testing.T) (wsURL string, stop func()) {
	t.Helper()
	return startTestServerWith(t, Config{Addr: "127.0.0.1:0"})
}

func startTestServerWith(t *testing.T, cfg Config) (wsURL string, stop func()) {
	t.Helper()
	srv := New(cfg)
	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx, ln)
		close(done)
	}()
	stop = func() {
		cancel()
		<-done
	}
	return "ws://" + ln.Addr().String() + "/ws", stop
}

// AC: "Agent binds only to 127.0.0.1; non-loopback bind is refused."
func TestListen_RefusesNonLoopback(t *testing.T) {
	cases := []string{
		"0.0.0.0:0",
		"192.168.1.1:8080",
		"example.com:8080", // hostnames must be rejected too
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			srv := New(Config{Addr: addr})
			_, err := srv.Listen()
			if !errors.Is(err, ErrNonLoopbackBind) {
				t.Fatalf("expected ErrNonLoopbackBind for %q, got %v", addr, err)
			}
		})
	}
}

// AC: "server.health returns agent version + uptime."
func TestServerHealth_ReturnsVersionAndUptime(t *testing.T) {
	wsURL, stop := startTestServer(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	req, _ := json.Marshal(Frame{ID: "1", Kind: "server.health"})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp Frame
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	if resp.ID != "1" {
		t.Errorf("id: got %q want %q", resp.ID, "1")
	}
	if resp.Kind != "server.health" {
		t.Errorf("kind: got %q want server.health", resp.Kind)
	}
	var hp HealthPayload
	if err := json.Unmarshal(resp.Payload, &hp); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if hp.Version != version.Version {
		t.Errorf("version: got %q want %q", hp.Version, version.Version)
	}
	if hp.UptimeS < 0 {
		t.Errorf("uptime_s should be >= 0, got %d", hp.UptimeS)
	}
}

// AC: end-to-end wiring for project.create / project.list over WebSocket.
func TestProject_CreateAndListOverWS(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	mgr, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}

	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Projects: mgr})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	// Create.
	payload, _ := json.Marshal(map[string]string{"name": "demo"})
	req, _ := json.Marshal(Frame{ID: "1", Kind: "project.create", Payload: payload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "project.create" {
		t.Fatalf("unexpected kind: %s", resp.Kind)
	}
	var p ProjectDTO
	_ = json.Unmarshal(resp.Payload, &p)
	if p.ID == "" || p.Name != "demo" {
		t.Fatalf("bad dto: %+v", p)
	}

	// List should see it.
	req, _ = json.Marshal(Frame{ID: "2", Kind: "project.list"})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, _ = c.Read(ctx)
	_ = json.Unmarshal(data, &resp)
	var list struct {
		Projects []ProjectDTO `json:"projects"`
	}
	_ = json.Unmarshal(resp.Payload, &list)
	if len(list.Projects) != 1 || list.Projects[0].ID != p.ID {
		t.Fatalf("list mismatch: %+v", list)
	}
}

// AC: project.* surface is unavailable without the projects manager wired in.
func TestProject_Unavailable_WhenNotWired(t *testing.T) {
	wsURL, stop := startTestServer(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	req, _ := json.Marshal(Frame{ID: "1", Kind: "project.list"})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "error.unavailable" {
		t.Errorf("got %q want error.unavailable", resp.Kind)
	}
}

// AC support: protocol robustness — unknown kinds produce an error frame.
func TestServer_UnknownKindReturnsError(t *testing.T) {
	wsURL, stop := startTestServer(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	req, _ := json.Marshal(Frame{ID: "x", Kind: "nope.does_not_exist"})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if !strings.HasPrefix(resp.Kind, "error.") {
		t.Errorf("expected error.* kind, got %q", resp.Kind)
	}
}
