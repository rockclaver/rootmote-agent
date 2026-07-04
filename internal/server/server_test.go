package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/alerts"
	"github.com/rockclaver/rootmote-agent/internal/cliauth"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/firewall"
	gh "github.com/rockclaver/rootmote-agent/internal/github"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	agentprocess "github.com/rockclaver/rootmote-agent/internal/process"
	"github.com/rockclaver/rootmote-agent/internal/projects"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/sessions"
	"github.com/rockclaver/rootmote-agent/internal/storage"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/version"
	"github.com/rockclaver/rootmote-agent/internal/webserver"
)

type fakeSessionRuntime struct{}

func (fakeSessionRuntime) Start(_ context.Context, spec sessions.RuntimeSpec) error {
	_, _ = spec.Output.Write([]byte("ready\n"))
	return nil
}

func TestIssue41InfraMetricsSampleOverWS(t *testing.T) {
	mgr, err := infra.New(infra.Config{})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Infra: mgr})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	req, _ := json.Marshal(Frame{ID: "infra-sample", Kind: "infra.metrics.sample"})
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
	if resp.Kind != "infra.metrics.sample" {
		t.Fatalf("kind = %s payload=%s", resp.Kind, string(resp.Payload))
	}
	var out struct {
		Sample infra.HostMetrics `json:"sample"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if err := out.Sample.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestIssue41InfraMetricsSubscribeUnsubscribeOverWS(t *testing.T) {
	mgr, err := infra.New(infra.Config{Cadence: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Infra: mgr})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	payload, _ := json.Marshal(map[string]string{"subscription_id": "sub-1"})
	req, _ := json.Marshal(Frame{ID: "infra-sub", Kind: "infra.metrics.subscribe", Payload: payload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ack Frame
	if err := json.Unmarshal(data, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Kind != "infra.metrics.subscribe" {
		t.Fatalf("ack kind = %s payload=%s", ack.Kind, string(ack.Payload))
	}
	_, data, err = c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var event Frame
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatal(err)
	}
	if event.Kind != "infra.metrics.event" {
		t.Fatalf("event kind = %s payload=%s", event.Kind, string(event.Payload))
	}

	unsubPayload, _ := json.Marshal(map[string]string{"subscription_id": "sub-1"})
	unsub, _ := json.Marshal(Frame{ID: "infra-unsub", Kind: "infra.metrics.unsubscribe", Payload: unsubPayload})
	if err := c.Write(ctx, websocket.MessageText, unsub); err != nil {
		t.Fatal(err)
	}
	for {
		_, data, err = c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var resp Frame
		if err := json.Unmarshal(data, &resp); err != nil {
			t.Fatal(err)
		}
		if resp.ID != "infra-unsub" {
			continue
		}
		if resp.Kind != "infra.metrics.unsubscribe" {
			t.Fatalf("unsubscribe kind = %s payload=%s", resp.Kind, string(resp.Payload))
		}
		var body struct {
			Cancelled bool `json:"cancelled"`
		}
		if err := json.Unmarshal(resp.Payload, &body); err != nil {
			t.Fatal(err)
		}
		if !body.Cancelled {
			t.Fatal("subscription was not cancelled")
		}
		break
	}
}
func (fakeSessionRuntime) Attach(context.Context, sessions.RuntimeSpec) error { return nil }
func (fakeSessionRuntime) SendPrompt(context.Context, string, string) error   { return nil }
func (fakeSessionRuntime) SendInput(context.Context, string, string) error    { return nil }
func (fakeSessionRuntime) Interrupt(context.Context, string) error            { return nil }
func (fakeSessionRuntime) Resize(context.Context, string, int, int) error     { return nil }
func (fakeSessionRuntime) Stop(context.Context, string) error                 { return nil }
func (fakeSessionRuntime) Capture(context.Context, string) (string, error)    { return "", nil }
func (fakeSessionRuntime) Alive(context.Context, string) bool                 { return true }
func (fakeSessionRuntime) SendApproval(context.Context, string, string, string, string) error {
	return nil
}
func (fakeSessionRuntime) SetMode(context.Context, string, string) error { return nil }

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

func TestAuthStatus_AcceptsGitHubKind(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ghBin := filepath.Join(binDir, "gh")
	if err := os.WriteFile(ghBin, []byte(`#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "gh version 2.0.0"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "token" ]; then
  echo "gho_test"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  echo "Logged in to github.com account octo (/tmp/hosts.yml)"
  exit 0
fi
exit 1
`), 0o755); err != nil {
		t.Fatal(err)
	}
	auth, err := cliauth.New(cliauth.Config{
		BinDir:  binDir,
		HomeDir: dir,
		Vault:   gh.NewTokenVault(filepath.Join(dir, "github.key"), filepath.Join(dir, "tokens")),
		Store:   st,
	})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Auth: auth})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	payload, _ := json.Marshal(map[string]string{"kind": "github"})
	req, _ := json.Marshal(Frame{ID: "github-status", Kind: "auth.status", Payload: payload})
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
	if resp.Kind != "auth.status" {
		t.Fatalf("kind = %s payload=%s", resp.Kind, string(resp.Payload))
	}
	var stResp struct {
		Kind     string `json:"kind"`
		LoggedIn bool   `json:"logged_in"`
		Account  string `json:"account"`
	}
	if err := json.Unmarshal(resp.Payload, &stResp); err != nil {
		t.Fatal(err)
	}
	if stResp.Kind != "github" || !stResp.LoggedIn || stResp.Account != "octo" {
		t.Fatalf("status = %+v", stResp)
	}
}

// Phase 9 AC1: a replayed request id arriving on the SAME connection is not
// re-executed; the second arrival is answered with a replay marker.
func TestServer_DedupesReplayedFrameID_SameConnection(t *testing.T) {
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
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	payload, _ := json.Marshal(map[string]string{"name": "demo"})
	req, _ := json.Marshal(Frame{ID: "dup-1", Kind: "project.create", Payload: payload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, _ := c.Read(ctx)
	var first Frame
	_ = json.Unmarshal(data, &first)
	if first.Kind != "project.create" {
		t.Fatalf("first call: %s", first.Kind)
	}

	// Replay with the same id; should be answered without creating a second project.
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, _ = c.Read(ctx)
	var second Frame
	_ = json.Unmarshal(data, &second)
	var pl struct {
		Replay bool `json:"replay"`
	}
	_ = json.Unmarshal(second.Payload, &pl)
	if !pl.Replay {
		t.Fatalf("expected replay marker, got %s/%s", second.Kind, string(second.Payload))
	}

	listReq, _ := json.Marshal(Frame{ID: "list-1", Kind: "project.list"})
	_ = c.Write(ctx, websocket.MessageText, listReq)
	_, data, _ = c.Read(ctx)
	var listFrame Frame
	_ = json.Unmarshal(data, &listFrame)
	var list struct {
		Projects []ProjectDTO `json:"projects"`
	}
	_ = json.Unmarshal(listFrame.Payload, &list)
	if len(list.Projects) != 1 {
		t.Fatalf("replayed call double-created projects: %+v", list.Projects)
	}
}

// Phase 9 AC1 (review #3324241271): a replayed request id arriving on a NEW
// WebSocket — the realistic post-tunnel-drop case — must also dedupe, so the
// dedupe cache has to live on Server, not per-connection.
func TestServer_DedupesReplayedFrameID_AcrossReconnect(t *testing.T) {
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

	// First WebSocket: send project.create, then drop the connection.
	c1, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"name": "demo"})
	req, _ := json.Marshal(Frame{ID: "reconnect-1", Kind: "project.create", Payload: payload})
	if err := c1.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, _ := c1.Read(ctx)
	var first Frame
	_ = json.Unmarshal(data, &first)
	if first.Kind != "project.create" {
		t.Fatalf("first call: %s", first.Kind)
	}
	_ = c1.Close(websocket.StatusNormalClosure, "")

	// Second WebSocket: same id, simulating client-side replay after a drop.
	c2, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close(websocket.StatusNormalClosure, "")
	if err := c2.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, _ = c2.Read(ctx)
	var second Frame
	_ = json.Unmarshal(data, &second)
	var pl struct {
		Replay bool `json:"replay"`
	}
	_ = json.Unmarshal(second.Payload, &pl)
	if !pl.Replay {
		t.Fatalf("cross-connection replay was re-executed, got %s/%s", second.Kind, string(second.Payload))
	}

	listReq, _ := json.Marshal(Frame{ID: "list-rc", Kind: "project.list"})
	_ = c2.Write(ctx, websocket.MessageText, listReq)
	_, data, _ = c2.Read(ctx)
	var listFrame Frame
	_ = json.Unmarshal(data, &listFrame)
	var list struct {
		Projects []ProjectDTO `json:"projects"`
	}
	_ = json.Unmarshal(listFrame.Payload, &list)
	if len(list.Projects) != 1 {
		t.Fatalf("cross-connection replay double-created projects: %+v", list.Projects)
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

// AC: "Disconnecting and reopening the app reattaches to the live session and
// continues streaming from the correct sequence number."
func TestSession_SubscribeReplaysFromSequenceOverWS(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pm, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "p1" }
	if _, err := pm.CreateEmpty("demo"); err != nil {
		t.Fatal(err)
	}
	sm := sessions.New(st, pm, fakeSessionRuntime{})
	sm.IDGen = func() string { return "s1" }
	if _, err := sm.Start(context.Background(), "p1", "codex", "manual", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := sm.Publish(store.SessionEvent{SessionID: "s1", Type: "stdout", Data: "after\n"}); err != nil {
		t.Fatal(err)
	}

	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Projects: pm, Sessions: sm})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	payload, _ := json.Marshal(map[string]any{"session_id": "s1", "after_seq": 2})
	req, _ := json.Marshal(Frame{ID: "sub", Kind: "session.subscribe", Payload: payload})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "session.subscribe" {
		t.Fatalf("subscribe ack kind %q", resp.Kind)
	}
	_, data, err = c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "session.event" {
		t.Fatalf("event kind %q", resp.Kind)
	}
	var ev SessionEventDTO
	_ = json.Unmarshal(resp.Payload, &ev)
	if ev.Seq != 3 || ev.Data != "after\n" {
		t.Fatalf("replay mismatch: %+v", ev)
	}
}

// AC: "No code path exposes an arbitrary shell command to the mobile UI."
func TestSessionStartRejectsArbitraryAgentOverWS(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pm, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "p1" }
	if _, err := pm.CreateEmpty("demo"); err != nil {
		t.Fatal(err)
	}
	sm := sessions.New(st, pm, fakeSessionRuntime{})
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Projects: pm, Sessions: sm})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	payload, _ := json.Marshal(map[string]string{"project_id": "p1", "agent": "bash"})
	req, _ := json.Marshal(Frame{ID: "x", Kind: "session.start", Payload: payload})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "error.bad_agent" {
		t.Fatalf("got %q want error.bad_agent", resp.Kind)
	}
}

// AC: end-to-end approval flow. confirm + review.approve + audit.list over WS.
func TestReview_ApproveFlow_OverWS(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pm, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "p1" }
	if _, err := pm.CreateEmpty("demo"); err != nil {
		t.Fatal(err)
	}
	rm := review.New(pm, st, review.HeuristicSummarizer{})
	sm := sessions.New(st, pm, fakeSessionRuntime{})
	sm.IDGen = func() string { return "s1" }
	if _, err := sm.Start(context.Background(), "p1", "codex", "manual", ""); err != nil {
		t.Fatal(err)
	}

	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Projects: pm, Sessions: sm, Review: rm})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	// 1. Approve without a token must fail with token_invalid.
	payload, _ := json.Marshal(map[string]any{
		"project_id": "p1", "session_id": "s1",
		"files": []string{"x.txt"}, "comment": "",
	})
	req, _ := json.Marshal(Frame{ID: "1", Kind: "review.approve", Payload: payload})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, _ := c.Read(ctx)
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("missing token: kind = %q want error.token_invalid", resp.Kind)
	}

	// 2. Mint a token via auth.confirm.
	payload, _ = json.Marshal(map[string]any{
		"action": "review.approve", "project_id": "p1",
		"files": []string{"x.txt"}, "comment": "",
	})
	req, _ = json.Marshal(Frame{ID: "2", Kind: "auth.confirm", Payload: payload})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, _ = c.Read(ctx)
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "auth.confirm" {
		t.Fatalf("auth.confirm kind = %q", resp.Kind)
	}
	var mint struct {
		Token string `json:"confirmation_token"`
	}
	_ = json.Unmarshal(resp.Payload, &mint)
	if mint.Token == "" {
		t.Fatal("empty token")
	}

	// 3. Approve with token: succeeds.
	payload, _ = json.Marshal(map[string]any{
		"project_id": "p1", "session_id": "s1",
		"files": []string{"x.txt"}, "comment": "",
		"confirmation_token": mint.Token,
	})
	req, _ = json.Marshal(Frame{ID: "3", Kind: "review.approve", Payload: payload})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, _ = c.Read(ctx)
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "review.approve" {
		t.Fatalf("approve kind = %q payload %s", resp.Kind, resp.Payload)
	}

	// 4. Replay rejected as token_used.
	req, _ = json.Marshal(Frame{ID: "4", Kind: "review.approve", Payload: payload})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, _ = c.Read(ctx)
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "error.token_used" {
		t.Fatalf("replay kind = %q want error.token_used", resp.Kind)
	}

	// 5. audit.list must contain the approval.
	payload, _ = json.Marshal(map[string]any{"type": "review.approve"})
	req, _ = json.Marshal(Frame{ID: "5", Kind: "audit.list", Payload: payload})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, _ = c.Read(ctx)
	_ = json.Unmarshal(data, &resp)
	var list struct {
		Entries []AuditDTO `json:"entries"`
	}
	_ = json.Unmarshal(resp.Payload, &list)
	if len(list.Entries) == 0 || list.Entries[0].Type != "review.approve" {
		t.Fatalf("audit list missing approval: %+v", list)
	}
}

// AC: diff.status / diff.file / diff.summarize wire through over WS.
func TestDiff_StatusFileSummarize_OverWS(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pm, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "p1" }
	if _, err := pm.CreateEmpty("demo"); err != nil {
		t.Fatal(err)
	}
	ws := pm.WorkspaceDir("p1")
	mustWriteFile(t, ws+"/added.txt", "fresh\n")
	rm := review.New(pm, st, review.HeuristicSummarizer{})
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Projects: pm, Review: rm})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	payload, _ := json.Marshal(map[string]any{"project_id": "p1"})
	req, _ := json.Marshal(Frame{ID: "1", Kind: "diff.status", Payload: payload})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, _ := c.Read(ctx)
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "diff.status" {
		t.Fatalf("status kind = %q", resp.Kind)
	}
	var list struct {
		Files []ChangedFileDTO `json:"files"`
	}
	_ = json.Unmarshal(resp.Payload, &list)
	if len(list.Files) == 0 || list.Files[0].Path != "added.txt" {
		t.Fatalf("diff.status missing added.txt: %+v", list)
	}

	payload, _ = json.Marshal(map[string]any{"project_id": "p1", "path": "added.txt"})
	req, _ = json.Marshal(Frame{ID: "2", Kind: "diff.summarize", Payload: payload})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, _ = c.Read(ctx)
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "diff.summarize" {
		t.Fatalf("summarize kind = %q payload %s", resp.Kind, resp.Payload)
	}
}

// AC: docker.status surfaces the typed daemon status (availability + version
// or machine-readable unavailable reason) over the WebSocket.
func TestDockerStatus_Reachable(t *testing.T) {
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{v: docker.VersionInfo{Version: "26.0.0", APIVersion: "1.45"}}})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Docker: mgr})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	req, _ := json.Marshal(Frame{ID: "1", Kind: "docker.status"})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "docker.status" {
		t.Fatalf("kind = %q (payload %s)", resp.Kind, resp.Payload)
	}
	var dto DockerStatusDTO
	if err := json.Unmarshal(resp.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	if !dto.Available || dto.Version != "26.0.0" || dto.APIVersion != "1.45" {
		t.Errorf("unexpected dto: %+v", dto)
	}
}

func TestDockerStatus_PermissionDenied(t *testing.T) {
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{err: fakeErr{cause: docker.ErrPermissionDenied}}})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Docker: mgr})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	req, _ := json.Marshal(Frame{ID: "1", Kind: "docker.status"})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	var dto DockerStatusDTO
	_ = json.Unmarshal(resp.Payload, &dto)
	if dto.Available {
		t.Fatalf("expected unavailable, got %+v", dto)
	}
	if dto.UnavailableReason != docker.ReasonPermissionDenied {
		t.Errorf("reason = %q", dto.UnavailableReason)
	}
}

func TestDockerStatus_Unconfigured(t *testing.T) {
	wsURL, stop := startTestServer(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	req, _ := json.Marshal(Frame{ID: "1", Kind: "docker.status"})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if !strings.HasPrefix(resp.Kind, "error.") {
		t.Errorf("expected error frame, got %q", resp.Kind)
	}
}

// AC: docker.container.list is exposed over the WebSocket with all returned
// containers, including Compose metadata and unmanaged markers.
func TestDockerContainerList(t *testing.T) {
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{containers: []docker.ContainerSummary{
		{ID: "1", Name: "api", Image: "api:latest", State: "running", Labels: map[string]string{
			"com.docker.compose.project": "nest",
			"com.docker.compose.service": "api",
		}},
		{ID: "2", Name: "redis", Image: "redis:7", State: "exited"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Docker: mgr})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	req, _ := json.Marshal(Frame{ID: "1", Kind: "docker.container.list"})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "docker.container.list" {
		t.Fatalf("kind = %q payload %s", resp.Kind, resp.Payload)
	}
	var dto struct {
		Containers []docker.ContainerSummary `json:"containers"`
	}
	if err := json.Unmarshal(resp.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	if len(dto.Containers) != 2 || dto.Containers[0].ComposeProject != "nest" || dto.Containers[1].Managed {
		t.Fatalf("containers payload = %+v", dto.Containers)
	}
}

// AC: docker.container.get is exposed over the WebSocket and returns the
// detail inspect subset with environment redaction preserved.
func TestDockerContainerGet(t *testing.T) {
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{detail: docker.ContainerDetail{
		ID:            "1",
		Name:          "api",
		Image:         "api:latest",
		Command:       "npm start",
		RestartPolicy: "unless-stopped",
		EnvironmentVars: []docker.EnvSummary{{
			Key: "API_TOKEN", Value: "REDACTED", Redacted: true,
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Docker: mgr})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	payload, _ := json.Marshal(map[string]string{"id": "1"})
	req, _ := json.Marshal(Frame{ID: "1", Kind: "docker.container.get", Payload: payload})
	_ = c.Write(ctx, websocket.MessageText, req)
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	if resp.Kind != "docker.container.get" {
		t.Fatalf("kind = %q payload %s", resp.Kind, resp.Payload)
	}
	var dto struct {
		Container docker.ContainerDetail `json:"container"`
	}
	if err := json.Unmarshal(resp.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	if dto.Container.Command != "npm start" || len(dto.Container.EnvironmentVars) != 1 || !dto.Container.EnvironmentVars[0].Redacted {
		t.Fatalf("detail payload = %+v", dto.Container)
	}
}

func TestDockerContainerAction_RequiresBoundConfirmationTokenAndAudits(t *testing.T) {
	// AC issue #25: lifecycle requests require a valid single-use token bound
	// to the exact action and container, and failed attempts are audited
	// without mutating Docker.
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	calls := []string{}
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{actionCalls: &calls}})
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]any{"id": "abc", "action": "start"})
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Docker: mgr, Review: rm}, "docker.container.action", payload)
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("missing token response kind = %q", resp.Kind)
	}
	if len(calls) != 0 {
		t.Fatalf("missing token mutated Docker: %+v", calls)
	}

	wrongAction, projectID, files := dockerLifecycleTokenBinding("abc", docker.ActionStop)
	wrong, err := rm.MintConfirmationToken(wrongAction, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"id": "abc", "action": "start", "confirmation_token": wrong.Token})
	resp = dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Docker: mgr, Review: rm}, "docker.container.action", payload)
	if resp.Kind != "error.token_mismatch" {
		t.Fatalf("mismatched token response kind = %q", resp.Kind)
	}
	if len(calls) != 0 {
		t.Fatalf("mismatched token mutated Docker: %+v", calls)
	}

	action, projectID, files := dockerLifecycleTokenBinding("abc", docker.ActionStart)
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"id": "abc", "action": "start", "confirmation_token": tok.Token})
	resp = dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Docker: mgr, Review: rm}, "docker.container.action", payload)
	if resp.Kind != "docker.container.action" {
		t.Fatalf("valid token response kind = %q", resp.Kind)
	}
	if len(calls) != 1 || calls[0] != "abc:start" {
		t.Fatalf("valid token did not mutate once: %+v", calls)
	}

	entries, err := rm.ListAudit("docker.container.action", "docker", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("audit entries = %d want 3: %+v", len(entries), entries)
	}
	if !strings.Contains(entries[0].Summary, "succeeded") ||
		!strings.Contains(entries[1].Summary, "does not match") ||
		!strings.Contains(entries[2].Summary, "invalid") {
		t.Fatalf("audit entries missing outcome metadata: %+v", entries)
	}

	resp = dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Docker: mgr, Review: rm}, "docker.container.action", payload)
	if resp.Kind != "error.token_used" {
		t.Fatalf("reused token response kind = %q", resp.Kind)
	}
	if len(calls) != 1 {
		t.Fatalf("reused token mutated Docker: %+v", calls)
	}
}

func TestDockerContainerAction_RejectsUnsupportedActionAndAuditsDockerFailure(t *testing.T) {
	// AC issue #25: unsupported actions are rejected, Docker failures surface
	// clearly, and each failed lifecycle attempt is audited.
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	calls := []string{}
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{
		actionCalls: &calls,
		actionErr:   errors.New("daemon refused stop"),
	}})
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]any{"id": "abc", "action": "delete", "confirmation_token": "tok"})
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Docker: mgr, Review: rm}, "docker.container.action", payload)
	if resp.Kind != "error.bad_payload" {
		t.Fatalf("unsupported action response kind = %q", resp.Kind)
	}
	if len(calls) != 0 {
		t.Fatalf("unsupported action mutated Docker: %+v", calls)
	}

	action, projectID, files := dockerLifecycleTokenBinding("abc", docker.ActionStop)
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"id": "abc", "action": "stop", "confirmation_token": tok.Token})
	resp = dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Docker: mgr, Review: rm}, "docker.container.action", payload)
	if resp.Kind != "error.docker_error" {
		t.Fatalf("docker failure response kind = %q", resp.Kind)
	}
	if len(calls) != 1 || calls[0] != "abc:stop" {
		t.Fatalf("docker failure should attempt exactly once: %+v", calls)
	}
	entries, err := rm.ListAudit("docker.container.action", "docker", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 ||
		!strings.Contains(entries[0].Summary, "daemon refused stop") ||
		!strings.Contains(entries[1].Summary, "unsupported action") {
		t.Fatalf("failure audits missing metadata: %+v", entries)
	}
}

// AC: docker.image.list is exposed over the WebSocket with safe metadata.
func TestDockerImageList(t *testing.T) {
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{images: []docker.ImageSummary{
		{ID: "sha256:abc", Tags: []string{"nginx:latest"}, Size: 1024, Containers: 1},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	resp := dockerRoundTrip(t, mgr, "docker.image.list", nil)
	if resp.Kind != "docker.image.list" {
		t.Fatalf("kind = %q payload %s", resp.Kind, resp.Payload)
	}
	var dto struct {
		Images []docker.ImageSummary `json:"images"`
	}
	if err := json.Unmarshal(resp.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	if len(dto.Images) != 1 || dto.Images[0].ID != "sha256:abc" || dto.Images[0].Tags[0] != "nginx:latest" {
		t.Fatalf("images payload = %+v", dto.Images)
	}
}

// AC: docker.image.get returns inspect-level safe metadata.
func TestDockerImageGet(t *testing.T) {
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{imageDetail: docker.ImageDetail{
		ImageSummary: docker.ImageSummary{ID: "sha256:abc", Tags: []string{"app:v1"}},
		Architecture: "arm64", OS: "linux",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"id": "sha256:abc"})
	resp := dockerRoundTrip(t, mgr, "docker.image.get", payload)
	if resp.Kind != "docker.image.get" {
		t.Fatalf("kind = %q payload %s", resp.Kind, resp.Payload)
	}
	var dto struct {
		Image docker.ImageDetail `json:"image"`
	}
	if err := json.Unmarshal(resp.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	if dto.Image.Architecture != "arm64" || dto.Image.OS != "linux" {
		t.Fatalf("image detail payload = %+v", dto.Image)
	}
}

// AC: docker.volume.list exposes name, driver, mountpoint, labels, in-use hint.
func TestDockerVolumeList(t *testing.T) {
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{volumes: []docker.VolumeSummary{
		{Name: "data", Driver: "local", Mountpoint: "/var/lib/docker/volumes/data/_data",
			Labels: map[string]string{"app": "api"}, InUseCount: 2},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	resp := dockerRoundTrip(t, mgr, "docker.volume.list", nil)
	if resp.Kind != "docker.volume.list" {
		t.Fatalf("kind = %q payload %s", resp.Kind, resp.Payload)
	}
	var dto struct {
		Volumes []docker.VolumeSummary `json:"volumes"`
	}
	if err := json.Unmarshal(resp.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	if len(dto.Volumes) != 1 || dto.Volumes[0].Driver != "local" || dto.Volumes[0].InUseCount != 2 {
		t.Fatalf("volumes payload = %+v", dto.Volumes)
	}
}

// AC: docker.network.list exposes name, driver, scope, attached count.
func TestDockerNetworkList(t *testing.T) {
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{networks: []docker.NetworkSummary{
		{ID: "n1", Name: "bridge", Driver: "bridge", Scope: "local", AttachedCount: 4},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	resp := dockerRoundTrip(t, mgr, "docker.network.list", nil)
	if resp.Kind != "docker.network.list" {
		t.Fatalf("kind = %q payload %s", resp.Kind, resp.Payload)
	}
	var dto struct {
		Networks []docker.NetworkSummary `json:"networks"`
	}
	if err := json.Unmarshal(resp.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	if len(dto.Networks) != 1 || dto.Networks[0].Driver != "bridge" || dto.Networks[0].AttachedCount != 4 {
		t.Fatalf("networks payload = %+v", dto.Networks)
	}
}

// AC: docker.info exposes daemon-level inventory totals.
func TestDockerInfo(t *testing.T) {
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{daemon: docker.DaemonInfo{
		Containers: 5, ContainersRunning: 3, Images: 9, ServerVersion: "26.0.0",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	resp := dockerRoundTrip(t, mgr, "docker.info", nil)
	if resp.Kind != "docker.info" {
		t.Fatalf("kind = %q payload %s", resp.Kind, resp.Payload)
	}
	var dto struct {
		Info docker.DaemonInfo `json:"info"`
	}
	if err := json.Unmarshal(resp.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	if dto.Info.Containers != 5 || dto.Info.ContainersRunning != 3 || dto.Info.Images != 9 {
		t.Fatalf("info payload = %+v", dto.Info)
	}
}

func TestDockerContainerLogs(t *testing.T) {
	// AC issue #30: docker.container.logs exposes a bounded recent log tail.
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{logs: []docker.LogEntry{{
		ContainerID: "abc",
		Stream:      "stdout",
		Timestamp:   "2026-05-29T10:00:00Z",
		Line:        "ready",
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"id": "abc", "tail": 50})
	resp := dockerRoundTrip(t, mgr, "docker.container.logs", payload)
	if resp.Kind != "docker.container.logs" {
		t.Fatalf("kind = %q", resp.Kind)
	}
	var dto struct {
		Logs []docker.LogEntry `json:"logs"`
	}
	if err := json.Unmarshal(resp.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	if len(dto.Logs) != 1 || dto.Logs[0].Stream != "stdout" || dto.Logs[0].Line != "ready" {
		t.Fatalf("logs payload = %+v", dto.Logs)
	}
}

func TestDockerContainerLogsSubscribeTerminalState(t *testing.T) {
	// AC issue #30: docker.container.logs_subscribe streams events then emits a
	// visible terminal state when the Docker stream ends.
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{streamLogs: []docker.LogEntry{{
		ContainerID: "abc",
		Stream:      "stderr",
		Line:        "warn",
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Docker: mgr})
	t.Cleanup(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	payload, _ := json.Marshal(map[string]any{"id": "abc", "subscription_id": "sub-1"})
	req, _ := json.Marshal(Frame{ID: "sub", Kind: "docker.container.logs_subscribe", Payload: payload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	var seen []Frame
	for len(seen) < 3 {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var f Frame
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		seen = append(seen, f)
	}
	if seen[0].Kind != "docker.container.logs_subscribe" ||
		seen[1].Kind != "docker.container.log_event" ||
		seen[2].Kind != "docker.container.log_done" {
		t.Fatalf("stream frames = %+v", seen)
	}
	var done struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(seen[2].Payload, &done); err != nil {
		t.Fatal(err)
	}
	if !done.OK {
		t.Fatalf("done payload = %s", string(seen[2].Payload))
	}
}

func TestDockerContainerLogsUnsubscribeCancelsStream(t *testing.T) {
	// Review #3327184090: cancelling a log stream must stop the agent-side
	// Docker follow goroutine without waiting for the WebSocket to close.
	started := make(chan struct{})
	cancelled := make(chan struct{})
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{
		blockStream:     true,
		streamStarted:   started,
		streamCancelled: cancelled,
	}})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Docker: mgr})
	t.Cleanup(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	subPayload, _ := json.Marshal(map[string]any{"id": "abc", "subscription_id": "sub-1"})
	req, _ := json.Marshal(Frame{ID: "sub", Kind: "docker.container.logs_subscribe", Payload: subPayload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ack Frame
	if err := json.Unmarshal(data, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Kind != "docker.container.logs_subscribe" {
		t.Fatalf("ack kind = %q", ack.Kind)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("stream did not start")
	}
	unsubPayload, _ := json.Marshal(map[string]any{"subscription_id": "sub-1"})
	unsub, _ := json.Marshal(Frame{ID: "unsub", Kind: "docker.container.logs_unsubscribe", Payload: unsubPayload})
	if err := c.Write(ctx, websocket.MessageText, unsub); err != nil {
		t.Fatal(err)
	}
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var f Frame
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		if f.ID == "unsub" {
			if f.Kind != "docker.container.logs_unsubscribe" {
				t.Fatalf("unsubscribe kind = %q", f.Kind)
			}
			break
		}
	}
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("stream was not cancelled")
	}
}

func TestDockerContainerStats(t *testing.T) {
	// AC issue #28: docker.container.stats returns a computed live sample.
	sample := docker.StatsSample{
		Read:   "2026-05-29T10:00:00Z",
		CPU:    docker.StatsCPU{OnlineCPUs: 1},
		Memory: docker.StatsMemory{Usage: 200, Limit: 1000},
		Networks: map[string]docker.StatsNetwork{
			"eth0": {RxBytes: 10, TxBytes: 20},
		},
	}
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{statsSample: sample}})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"id": "abc"})
	resp := dockerRoundTrip(t, mgr, "docker.container.stats", payload)
	if resp.Kind != "docker.container.stats" {
		t.Fatalf("kind = %q", resp.Kind)
	}
	var dto struct {
		Sample docker.StatsSnapshot `json:"sample"`
	}
	if err := json.Unmarshal(resp.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	if !dto.Sample.Available || dto.Sample.MemLimitBytes != 1000 || dto.Sample.NetRxBytes != 10 {
		t.Fatalf("sample = %+v", dto.Sample)
	}
}

func TestDockerContainerStatsSubscribeTerminalState(t *testing.T) {
	// AC issue #28: stats_subscribe streams events then emits a done frame.
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{statsStream: []docker.StatsSample{{
		CPU:    docker.StatsCPU{OnlineCPUs: 1},
		Memory: docker.StatsMemory{Usage: 1, Limit: 100},
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Docker: mgr})
	t.Cleanup(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	payload, _ := json.Marshal(map[string]any{"id": "abc", "subscription_id": "stat-1"})
	req, _ := json.Marshal(Frame{ID: "sub", Kind: "docker.container.stats_subscribe", Payload: payload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	var seen []Frame
	for len(seen) < 3 {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var f Frame
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		seen = append(seen, f)
	}
	if seen[0].Kind != "docker.container.stats_subscribe" ||
		seen[1].Kind != "docker.container.stats_event" ||
		seen[2].Kind != "docker.container.stats_done" {
		t.Fatalf("stream frames = %+v", seen)
	}
}

func TestDockerContainerStatsUnsubscribeCancelsStream(t *testing.T) {
	// AC issue #28: cancelling a stats stream must stop the agent-side Docker
	// follow goroutine. Mirrors the logs unsubscribe contract so the UI can
	// stop sampling when the detail screen disappears.
	started := make(chan struct{})
	cancelled := make(chan struct{})
	mgr, err := docker.New(docker.Config{Client: fakeDockerClient{
		statsBlockStream: true,
		statsStarted:     started,
		statsCancelled:   cancelled,
	}})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Docker: mgr})
	t.Cleanup(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	subPayload, _ := json.Marshal(map[string]any{"id": "abc", "subscription_id": "stat-1"})
	req, _ := json.Marshal(Frame{ID: "sub", Kind: "docker.container.stats_subscribe", Payload: subPayload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ack Frame
	if err := json.Unmarshal(data, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Kind != "docker.container.stats_subscribe" {
		t.Fatalf("ack kind = %q", ack.Kind)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("stream did not start")
	}
	unsubPayload, _ := json.Marshal(map[string]any{"subscription_id": "stat-1"})
	unsub, _ := json.Marshal(Frame{ID: "unsub", Kind: "docker.container.stats_unsubscribe", Payload: unsubPayload})
	if err := c.Write(ctx, websocket.MessageText, unsub); err != nil {
		t.Fatal(err)
	}
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var f Frame
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		if f.ID == "unsub" {
			if f.Kind != "docker.container.stats_unsubscribe" {
				t.Fatalf("unsubscribe kind = %q", f.Kind)
			}
			break
		}
	}
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("stream was not cancelled")
	}
}

func dockerRoundTrip(t *testing.T, mgr *docker.Manager, kind string, payload []byte) Frame {
	t.Helper()
	return dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Docker: mgr}, kind, payload)
}

func dockerRoundTripConfig(t *testing.T, cfg Config, kind string, payload []byte) Frame {
	t.Helper()
	wsURL, stop := startTestServerWith(t, cfg)
	t.Cleanup(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	req, _ := json.Marshal(Frame{ID: "1", Kind: kind, Payload: payload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	return resp
}

type fakeDockerClient struct {
	v               docker.VersionInfo
	err             error
	containers      []docker.ContainerSummary
	detail          docker.ContainerDetail
	images          []docker.ImageSummary
	imageDetail     docker.ImageDetail
	volumes         []docker.VolumeSummary
	networks        []docker.NetworkSummary
	daemon          docker.DaemonInfo
	logs            []docker.LogEntry
	streamLogs      []docker.LogEntry
	streamErr       error
	blockStream     bool
	streamStarted   chan struct{}
	streamCancelled chan struct{}

	statsSample      docker.StatsSample
	statsErr         error
	statsStream      []docker.StatsSample
	statsStreamErr   error
	statsBlockStream bool
	statsStarted     chan struct{}
	statsCancelled   chan struct{}

	actionCalls *[]string
	actionErr   error

	diskUsage    docker.DiskUsage
	diskUsageErr error
	pruneResult  docker.PruneResult
	pruneErr     error
}

func (f fakeDockerClient) Version(context.Context) (docker.VersionInfo, error) {
	return f.v, f.err
}

func (f fakeDockerClient) Containers(context.Context) ([]docker.ContainerSummary, error) {
	return f.containers, f.err
}

func (f fakeDockerClient) Container(context.Context, string) (docker.ContainerDetail, error) {
	return f.detail, f.err
}

func (f fakeDockerClient) Images(context.Context) ([]docker.ImageSummary, error) {
	return f.images, f.err
}

func (f fakeDockerClient) Image(context.Context, string) (docker.ImageDetail, error) {
	return f.imageDetail, f.err
}

func (f fakeDockerClient) Volumes(context.Context) ([]docker.VolumeSummary, error) {
	return f.volumes, f.err
}

func (f fakeDockerClient) Networks(context.Context) ([]docker.NetworkSummary, error) {
	return f.networks, f.err
}

func (f fakeDockerClient) Info(context.Context) (docker.DaemonInfo, error) {
	return f.daemon, f.err
}

func (f fakeDockerClient) ContainerLogs(context.Context, string, int) ([]docker.LogEntry, error) {
	return f.logs, f.err
}

func (f fakeDockerClient) ContainerLogStream(ctx context.Context, id string, since time.Time, emit func(docker.LogEntry)) error {
	if f.blockStream {
		if f.streamStarted != nil {
			close(f.streamStarted)
		}
		<-ctx.Done()
		if f.streamCancelled != nil {
			close(f.streamCancelled)
		}
		return ctx.Err()
	}
	for _, entry := range f.streamLogs {
		emit(entry)
	}
	return f.streamErr
}

func (f fakeDockerClient) ContainerStats(context.Context, string) (docker.StatsSample, error) {
	return f.statsSample, f.statsErr
}

func (f fakeDockerClient) ContainerStatsStream(ctx context.Context, id string, emit func(docker.StatsSample)) error {
	if f.statsBlockStream {
		if f.statsStarted != nil {
			close(f.statsStarted)
		}
		<-ctx.Done()
		if f.statsCancelled != nil {
			close(f.statsCancelled)
		}
		return ctx.Err()
	}
	for _, s := range f.statsStream {
		emit(s)
	}
	return f.statsStreamErr
}

func (f fakeDockerClient) ContainerAction(_ context.Context, id string, action docker.ContainerAction) error {
	if f.actionCalls != nil {
		*f.actionCalls = append(*f.actionCalls, id+":"+string(action))
	}
	if f.actionErr != nil {
		return f.actionErr
	}
	return f.err
}

func (f fakeDockerClient) DiskUsage(context.Context) (docker.DiskUsage, error) {
	return f.diskUsage, f.diskUsageErr
}

func (f fakeDockerClient) PruneContainers(context.Context) (docker.PruneResult, error) {
	return f.pruneResult, f.pruneErr
}

func (f fakeDockerClient) PruneImages(context.Context) (docker.PruneResult, error) {
	return f.pruneResult, f.pruneErr
}

func (f fakeDockerClient) PruneBuildCache(context.Context) (docker.PruneResult, error) {
	return f.pruneResult, f.pruneErr
}

func (f fakeDockerClient) PruneVolumes(context.Context) (docker.PruneResult, error) {
	return f.pruneResult, f.pruneErr
}

type fakeErr struct{ cause error }

func (e fakeErr) Error() string { return "fake: " + e.cause.Error() }
func (e fakeErr) Unwrap() error { return e.cause }

type fakeSystemdClient struct {
	units     []systemd.Unit
	details   map[string]systemd.UnitDetail
	available error
	actions   []string
	actionErr error
	reboots   int
	rebootErr error
}

func (f *fakeSystemdClient) Available(_ context.Context) error { return f.available }
func (f *fakeSystemdClient) Status(_ context.Context) systemd.Status {
	if f.available != nil {
		return systemd.Status{
			Available:          false,
			UnavailableReason:  "test_unavailable",
			UnavailableMessage: f.available.Error(),
		}
	}
	return systemd.Status{Available: true}
}
func (f *fakeSystemdClient) List(_ context.Context) ([]systemd.Unit, error) {
	return append([]systemd.Unit(nil), f.units...), nil
}
func (f *fakeSystemdClient) Get(_ context.Context, name string) (systemd.UnitDetail, error) {
	if d, ok := f.details[name]; ok {
		return d, nil
	}
	return systemd.UnitDetail{}, errors.New("not found")
}
func (f *fakeSystemdClient) Action(_ context.Context, name string, action systemd.Action) error {
	f.actions = append(f.actions, name+":"+string(action))
	return f.actionErr
}
func (f *fakeSystemdClient) Reboot(_ context.Context) error {
	f.reboots++
	return f.rebootErr
}

func systemdRoundTrip(t *testing.T, cfg Config, kind string, payload []byte) Frame {
	t.Helper()
	return dockerRoundTripConfig(t, cfg, kind, payload)
}

func TestAlertsConfigRPCUsesSnakeCaseRules(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	infraMgr, err := infra.New(infra.Config{})
	if err != nil {
		t.Fatal(err)
	}
	alertMgr, err := alerts.New(alerts.Config{Store: st, Metrics: infraMgr})
	if err != nil {
		t.Fatal(err)
	}
	resp := systemdRoundTrip(t, Config{Addr: "127.0.0.1:0", Alerts: alertMgr}, "infra.alerts.config", nil)
	if resp.Kind != "infra.alerts.config" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Rules []store.InfraAlertRule `json:"rules"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) != 3 || out.Rules[0].Kind != alerts.RuleDiskUsage || !out.Rules[0].Enabled {
		t.Fatalf("rules mismatch: %+v", out.Rules)
	}
	if !strings.Contains(string(resp.Payload), `"server_id"`) || !strings.Contains(string(resp.Payload), `"updated_at"`) {
		t.Fatalf("expected snake_case alert rule payload, got %s", resp.Payload)
	}
}

func TestAlertsConfigSetRPCPersistsRule(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	infraMgr, err := infra.New(infra.Config{})
	if err != nil {
		t.Fatal(err)
	}
	alertMgr, err := alerts.New(alerts.Config{Store: st, Metrics: infraMgr})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"server_id": "local",
		"kind":      alerts.RuleDiskUsage,
		"enabled":   false,
		"threshold": 85,
	})
	resp := systemdRoundTrip(t, Config{Addr: "127.0.0.1:0", Alerts: alertMgr}, "infra.alerts.config_set", payload)
	if resp.Kind != "infra.alerts.config_set" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	rules, err := st.ListInfraAlertRules(alerts.ServerLocal)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Kind == alerts.RuleDiskUsage && (r.Enabled || r.Threshold != 85) {
			t.Fatalf("persisted rule mismatch: %+v", r)
		}
	}
}

// AC issue #42: infra.service.list returns units; degrades on non-systemd hosts.
func TestSystemdServiceList(t *testing.T) {
	fc := &fakeSystemdClient{units: []systemd.Unit{
		{Name: "nginx.service", LoadState: "loaded", ActiveState: "active", SubState: "running", EnabledOnBoot: "enabled"},
		{Name: "sshd.service", LoadState: "loaded", ActiveState: "active", SubState: "running", EnabledOnBoot: "enabled"},
	}}
	mgr, err := systemd.New(systemd.Config{Client: fc})
	if err != nil {
		t.Fatal(err)
	}
	resp := systemdRoundTrip(t, Config{Addr: "127.0.0.1:0", Systemd: mgr}, "infra.service.list", nil)
	if resp.Kind != "infra.service.list" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Available bool           `json:"available"`
		Units     []systemd.Unit `json:"units"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Available || len(out.Units) != 2 {
		t.Fatalf("unexpected list: %+v", out)
	}
	if !out.Units[1].Protected || out.Units[1].ProtectReason == "" {
		t.Fatalf("sshd not decorated protected: %+v", out.Units[1])
	}
}

// AC issue #42: list degrades to typed unavailable reason on non-systemd host.
func TestSystemdServiceList_NonSystemd(t *testing.T) {
	mgr, err := systemd.New(systemd.Config{Client: &fakeSystemdClient{available: systemd.ErrNotSystemd}})
	if err != nil {
		t.Fatal(err)
	}
	resp := systemdRoundTrip(t, Config{Addr: "127.0.0.1:0", Systemd: mgr}, "infra.service.list", nil)
	if resp.Kind != "infra.service.list" {
		t.Fatalf("kind = %q", resp.Kind)
	}
	var out struct {
		Available bool   `json:"available"`
		Reason    string `json:"unavailable_reason"`
	}
	_ = json.Unmarshal(resp.Payload, &out)
	if out.Available || out.Reason != systemd.ReasonNotSystemd {
		t.Fatalf("expected unavailable not_systemd, got %+v", out)
	}
}

// AC issue #42: infra.service.get returns single-unit detail.
func TestSystemdServiceGet(t *testing.T) {
	fc := &fakeSystemdClient{details: map[string]systemd.UnitDetail{
		"nginx.service": {Unit: systemd.Unit{Name: "nginx.service", Description: "Nginx", ActiveState: "active", SubState: "running", LoadState: "loaded", EnabledOnBoot: "enabled"}},
	}}
	mgr, err := systemd.New(systemd.Config{Client: fc})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"name": "nginx.service"})
	resp := systemdRoundTrip(t, Config{Addr: "127.0.0.1:0", Systemd: mgr}, "infra.service.get", payload)
	if resp.Kind != "infra.service.get" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Available bool               `json:"available"`
		Unit      systemd.UnitDetail `json:"unit"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Available || out.Unit.Name != "nginx.service" || out.Unit.Description != "Nginx" {
		t.Fatalf("unexpected get: %+v", out)
	}
}

// AC issue #42: action rejected without valid token; token single-use; audit row on success.
func TestSystemdServiceAction_TokenSingleUseAndAudit(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	fc := &fakeSystemdClient{}
	mgr, err := systemd.New(systemd.Config{Client: fc})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Addr: "127.0.0.1:0", Systemd: mgr, Review: rm}

	// Missing token -> rejected, no client call.
	payload, _ := json.Marshal(map[string]any{"name": "nginx.service", "action": "restart"})
	resp := systemdRoundTrip(t, cfg, "infra.service.action", payload)
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("missing token kind = %q", resp.Kind)
	}
	if len(fc.actions) != 0 {
		t.Fatalf("client called without token: %v", fc.actions)
	}

	// Valid token -> action runs; audit recorded.
	action, projectID, files := serviceLifecycleTokenBinding("nginx.service", systemd.ActionRestart)
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"name": "nginx.service", "action": "restart", "confirmation_token": tok.Token})
	resp = systemdRoundTrip(t, cfg, "infra.service.action", payload)
	if resp.Kind != "infra.service.action" {
		t.Fatalf("ok kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(fc.actions) != 1 || fc.actions[0] != "nginx.service:restart" {
		t.Fatalf("client not called once: %v", fc.actions)
	}

	// Single-use: replay same token -> token_used.
	resp = systemdRoundTrip(t, cfg, "infra.service.action", payload)
	if resp.Kind != "error.token_used" {
		t.Fatalf("reused token kind = %q", resp.Kind)
	}
	if len(fc.actions) != 1 {
		t.Fatalf("reused token re-invoked client: %v", fc.actions)
	}

	entries, err := rm.ListAudit("infra.service.action", "infra", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected audit row, got none")
	}
	var sawSuccess bool
	for _, e := range entries {
		if strings.Contains(e.Summary, "succeeded") && strings.Contains(e.Summary, "restart") && strings.Contains(e.Summary, "nginx.service") {
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Fatalf("missing success audit row: %+v", entries)
	}
}

// Host reboot requires a valid single-use token; success runs the client once
// and records an audit row.
func TestSystemReboot_TokenRequiredAndAudit(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	fc := &fakeSystemdClient{}
	mgr, err := systemd.New(systemd.Config{Client: fc})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Addr: "127.0.0.1:0", Systemd: mgr, Review: rm}

	// Missing token -> rejected, host not rebooted.
	payload, _ := json.Marshal(map[string]any{})
	resp := systemdRoundTrip(t, cfg, "infra.system.reboot", payload)
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("missing token kind = %q", resp.Kind)
	}
	if fc.reboots != 0 {
		t.Fatalf("rebooted without token: %d", fc.reboots)
	}

	// Valid token -> reboot runs once; audit recorded.
	action, projectID, files := systemRebootTokenBinding()
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"confirmation_token": tok.Token})
	resp = systemdRoundTrip(t, cfg, "infra.system.reboot", payload)
	if resp.Kind != "infra.system.reboot" {
		t.Fatalf("ok kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if fc.reboots != 1 {
		t.Fatalf("reboot not called once: %d", fc.reboots)
	}

	// Single-use: replay same token -> token_used, host not rebooted again.
	resp = systemdRoundTrip(t, cfg, "infra.system.reboot", payload)
	if resp.Kind != "error.token_used" {
		t.Fatalf("reused token kind = %q", resp.Kind)
	}
	if fc.reboots != 1 {
		t.Fatalf("reused token re-invoked reboot: %d", fc.reboots)
	}

	entries, err := rm.ListAudit("infra.system.reboot", "infra", 10)
	if err != nil {
		t.Fatal(err)
	}
	var sawSuccess bool
	for _, e := range entries {
		if strings.Contains(e.Summary, "succeeded") {
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Fatalf("missing success audit row: %+v", entries)
	}
}

// AC issue #42: protected-unit guard rejects stop/disable BEFORE token consumed.
func TestSystemdServiceAction_ProtectedUnitRejectedBeforeToken(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	fc := &fakeSystemdClient{}
	mgr, err := systemd.New(systemd.Config{Client: fc})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Addr: "127.0.0.1:0", Systemd: mgr, Review: rm}

	// Mint a valid token for stop on sshd to prove the guard refuses BEFORE
	// the token is consumed (token remains valid afterwards).
	action, projectID, files := serviceLifecycleTokenBinding("sshd.service", systemd.ActionStop)
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"name":               "sshd.service",
		"action":             "stop",
		"confirmation_token": tok.Token,
	})
	resp := systemdRoundTrip(t, cfg, "infra.service.action", payload)
	if resp.Kind != "error.protected_unit" {
		t.Fatalf("protected kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(fc.actions) != 0 {
		t.Fatalf("guard let action through to client: %v", fc.actions)
	}

	// The token was NOT consumed: same token can still mint a legitimate
	// (non-protected) action. Verify by consuming it directly.
	if err := rm.ConsumeToken(tok.Token, action, projectID, files, ""); err != nil {
		t.Fatalf("guard consumed token: %v", err)
	}
}

type fakeWebserverRunner struct {
	output string
	err    error
	calls  []string
}

func (f *fakeWebserverRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return f.output, f.err
}

func newTestWebserverManager(t *testing.T, sys *fakeSystemdClient, runner *fakeWebserverRunner, paths map[webserver.Kind][]string) *webserver.Manager {
	t.Helper()
	if sys == nil {
		sys = &fakeSystemdClient{units: []systemd.Unit{{Name: "nginx.service", ActiveState: "active", EnabledOnBoot: "enabled"}}}
	}
	mgr, err := webserver.New(webserver.Config{Systemd: sys, Runner: runner, Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func TestWebserverListOverWS(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "nginx.conf")
	mustWriteFile(t, cfg, "server_name app.example.com;\n")
	mgr := newTestWebserverManager(t, &fakeSystemdClient{units: []systemd.Unit{
		{Name: "nginx.service", Description: "Nginx", ActiveState: "active", EnabledOnBoot: "enabled"},
	}}, nil, map[webserver.Kind][]string{webserver.KindNginx: {cfg}})

	resp := systemdRoundTrip(t, Config{Addr: "127.0.0.1:0", Webservers: mgr}, "infra.webserver.list", nil)
	if resp.Kind != "infra.webserver.list" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Available  bool                 `json:"available"`
		Webservers []webserver.Instance `json:"webservers"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Available || len(out.Webservers) != 1 || out.Webservers[0].ID != "nginx:nginx.service" {
		t.Fatalf("unexpected webservers: %+v", out)
	}
	if len(out.Webservers[0].Domains) != 1 || out.Webservers[0].Domains[0].Host != "app.example.com" {
		t.Fatalf("domains not returned: %+v", out.Webservers[0].Domains)
	}
}

func TestWebserverValidateReturnsFailedOutputWithoutToken(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "nginx.conf")
	mustWriteFile(t, cfg, "server_name app.example.com;\n")
	runner := &fakeWebserverRunner{output: "nginx: bad config", err: errors.New("exit 1")}
	mgr := newTestWebserverManager(t, nil, runner, map[webserver.Kind][]string{webserver.KindNginx: {cfg}})
	payload, _ := json.Marshal(map[string]any{"id": "nginx:nginx.service"})

	resp := systemdRoundTrip(t, Config{Addr: "127.0.0.1:0", Webservers: mgr}, "infra.webserver.validate", payload)
	if resp.Kind != "infra.webserver.validate" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out webserver.ValidationResult
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if out.OK || out.Output != "nginx: bad config" {
		t.Fatalf("unexpected validate result: %+v", out)
	}
	if len(runner.calls) != 1 || runner.calls[0] != "nginx -t" {
		t.Fatalf("wrong runner calls: %+v", runner.calls)
	}
}

func TestWebserverActionTokenSingleUseAndAudit(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	sys := &fakeSystemdClient{units: []systemd.Unit{{Name: "nginx.service", ActiveState: "active"}}}
	mgr := newTestWebserverManager(t, sys, nil, map[webserver.Kind][]string{webserver.KindNginx: nil})
	cfg := Config{Addr: "127.0.0.1:0", Webservers: mgr, Review: rm}

	payload, _ := json.Marshal(map[string]any{"id": "nginx:nginx.service", "action": "restart"})
	resp := systemdRoundTrip(t, cfg, "infra.webserver.action", payload)
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("missing token kind = %q payload=%s", resp.Kind, resp.Payload)
	}
	if len(sys.actions) != 0 {
		t.Fatalf("client called without token: %v", sys.actions)
	}

	action, projectID, files := webserverActionTokenBinding("nginx:nginx.service", "restart")
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"id": "nginx:nginx.service", "action": "restart", "confirmation_token": tok.Token})
	resp = systemdRoundTrip(t, cfg, "infra.webserver.action", payload)
	if resp.Kind != "infra.webserver.action" {
		t.Fatalf("ok kind = %q payload=%s", resp.Kind, resp.Payload)
	}
	if len(sys.actions) != 1 || sys.actions[0] != "nginx.service:restart" {
		t.Fatalf("wrong actions: %+v", sys.actions)
	}

	resp = systemdRoundTrip(t, cfg, "infra.webserver.action", payload)
	if resp.Kind != "error.token_used" {
		t.Fatalf("reused token kind = %q payload=%s", resp.Kind, resp.Payload)
	}
	if len(sys.actions) != 1 {
		t.Fatalf("reused token re-invoked client: %+v", sys.actions)
	}
	entries, err := rm.ListAudit("infra.webserver.action", "infra", 10)
	if err != nil {
		t.Fatal(err)
	}
	var sawSuccess bool
	for _, e := range entries {
		if strings.Contains(e.Summary, "succeeded") && strings.Contains(e.Data, `"unit":"nginx.service"`) {
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Fatalf("missing webserver action audit: %+v", entries)
	}
}

// AC issue #43: infra.process.list returns mapped process rows from /proc.
func TestProcessListOverWS(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, 100, "worker", "1000", "worker\x00--serve\x00", 200, 100, 1000, 12)
	mustWriteFile(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	mgr, err := agentprocess.New(agentprocess.Config{
		ProcRoot:     root,
		PageSize:     1024,
		ClockTicks:   100,
		NumCPU:       1,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
		LookupUser:   func(string) string { return "app" },
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"sort": "cpu", "limit": 5})
	resp := systemdRoundTrip(t, Config{Addr: "127.0.0.1:0", Processes: mgr}, "infra.process.list", payload)
	if resp.Kind != "infra.process.list" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Processes []agentprocess.Process `json:"processes"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Processes) != 1 || out.Processes[0].PID != 100 || out.Processes[0].User != "app" {
		t.Fatalf("unexpected processes: %+v", out.Processes)
	}
}

// AC issue #43: guarded process kill rejects missing token and audits success.
func TestProcessKill_TokenRequiredAndAudit(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	root := filepath.Join(dir, "proc")
	writeProcFixture(t, root, 77, "worker", "1000", "worker\x00", 1, 1, 1, 1)
	mustWriteFile(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	var signals []syscall.Signal
	pm, err := agentprocess.New(agentprocess.Config{
		ProcRoot:     root,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
		Signal: func(_ context.Context, pid int, sig syscall.Signal) error {
			signals = append(signals, sig)
			_ = os.RemoveAll(filepath.Join(root, fmt.Sprintf("%d", pid)))
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Addr: "127.0.0.1:0", Processes: pm, Review: rm}

	payload, _ := json.Marshal(map[string]any{"pid": 77, "start_time_ticks": 1})
	resp := systemdRoundTrip(t, cfg, "infra.process.kill", payload)
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("missing token kind = %q", resp.Kind)
	}
	if len(signals) != 0 {
		t.Fatalf("signal without token: %v", signals)
	}

	action, projectID, files := processKillTokenBinding(77, 1, agentprocess.SignalTerm)
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"pid": 77, "start_time_ticks": 1, "confirmation_token": tok.Token})
	resp = systemdRoundTrip(t, cfg, "infra.process.kill", payload)
	if resp.Kind != "infra.process.kill" {
		t.Fatalf("ok kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(signals) != 1 || signals[0] != syscall.SIGTERM {
		t.Fatalf("signals = %v", signals)
	}
	entries, err := rm.ListAudit("infra.process.kill", "infra", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || !strings.Contains(entries[0].Summary, "succeeded") {
		t.Fatalf("missing success audit: %+v", entries)
	}
}

// Review #3329181602: confirmation binding includes start_time_ticks so a
// token cannot authorize a reused PID.
func TestProcessKill_RejectsPIDReuseAfterConfirmation(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	root := filepath.Join(dir, "proc")
	writeProcFixture(t, root, 77, "worker", "1000", "worker\x00", 1, 1, 1000, 1)
	mustWriteFile(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	var signalled bool
	pm, err := agentprocess.New(agentprocess.Config{
		ProcRoot:     root,
		AgentPID:     999,
		TmuxPanePIDs: func(context.Context) []int { return nil },
		Signal: func(context.Context, int, syscall.Signal) error {
			signalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Addr: "127.0.0.1:0", Processes: pm, Review: rm}
	action, projectID, files := processKillTokenBinding(77, 1000, agentprocess.SignalTerm)
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	writeProcFixture(t, root, 77, "other", "1000", "other\x00", 1, 1, 2000, 1)
	payload, _ := json.Marshal(map[string]any{"pid": 77, "start_time_ticks": 1000, "confirmation_token": tok.Token})
	resp := systemdRoundTrip(t, cfg, "infra.process.kill", payload)
	if resp.Kind != "error.process_identity_mismatch" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if signalled {
		t.Fatal("reused pid was signalled")
	}
}

// AC issue #43: protected PID guard rejects before token consumption/signalling.
func TestProcessKill_ProtectedPIDRejectedBeforeSignal(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	root := filepath.Join(dir, "proc")
	writeProcFixture(t, root, 66, "bash", "1000", "bash\x00", 1, 1, 1, 1)
	mustWriteFile(t, filepath.Join(root, "uptime"), "200.00 0.00\n")
	var signalled bool
	pm, err := agentprocess.New(agentprocess.Config{
		ProcRoot: root,
		AgentPID: 999,
		TmuxPanePIDs: func(context.Context) []int {
			return []int{66}
		},
		Signal: func(context.Context, int, syscall.Signal) error {
			signalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Addr: "127.0.0.1:0", Processes: pm, Review: rm}
	action, projectID, files := processKillTokenBinding(66, 1, agentprocess.SignalTerm)
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"pid": 66, "start_time_ticks": 1, "confirmation_token": tok.Token})
	resp := systemdRoundTrip(t, cfg, "infra.process.kill", payload)
	if resp.Kind != "error.protected_pid" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if signalled {
		t.Fatal("protected pid was signalled")
	}
	if err := rm.ConsumeToken(tok.Token, action, projectID, files, ""); err != nil {
		t.Fatalf("guard consumed token: %v", err)
	}
}

func mustWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeProcFixture(t *testing.T, root string, pid int, comm, uid, cmdline string, utime, stime, start, rss int) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fields := []string{
		"S", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
		fmt.Sprintf("%d", utime), fmt.Sprintf("%d", stime), "0", "0", "20", "0", "1", "0", fmt.Sprintf("%d", start), "0", fmt.Sprintf("%d", rss),
	}
	mustWriteFile(t, filepath.Join(dir, "stat"), fmt.Sprintf("%d (%s) %s\n", pid, comm, strings.Join(fields, " ")))
	mustWriteFile(t, filepath.Join(dir, "status"), "Name:\t"+comm+"\nUid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n")
	mustWriteFile(t, filepath.Join(dir, "cmdline"), cmdline)
	mustWriteFile(t, filepath.Join(dir, "statm"), "100 "+fmt.Sprintf("%d", rss)+" 0 0 0 0 0\n")
	mustWriteFile(t, filepath.Join(dir, "comm"), comm+"\n")
}

// --- issue #44 firewall dispatch tests ---

type fakeFWBackend struct {
	kind      firewall.BackendKind
	available error
	rules     []firewall.Rule
	added     []firewall.Rule
	removed   []firewall.Rule
}

func (f *fakeFWBackend) Kind() firewall.BackendKind        { return f.kind }
func (f *fakeFWBackend) Available(_ context.Context) error { return f.available }
func (f *fakeFWBackend) Rules(_ context.Context) ([]firewall.Rule, error) {
	return append([]firewall.Rule(nil), f.rules...), nil
}
func (f *fakeFWBackend) Add(_ context.Context, r firewall.Rule) error {
	f.added = append(f.added, r)
	f.rules = append(f.rules, r)
	return nil
}
func (f *fakeFWBackend) Remove(_ context.Context, r firewall.Rule) error {
	f.removed = append(f.removed, r)
	return nil
}

type fakeFWSockets struct{ sockets []firewall.Socket }

func (f fakeFWSockets) Listening(_ context.Context) ([]firewall.Socket, error) {
	return append([]firewall.Socket(nil), f.sockets...), nil
}

type fakeFWSSH struct{ ports []int }

func (f fakeFWSSH) SSHPorts(_ context.Context) []int { return append([]int(nil), f.ports...) }

func newFirewallTestMgr(t *testing.T, b firewall.Backend, sshPorts []int, sockets []firewall.Socket) *firewall.Manager {
	t.Helper()
	mgr, err := firewall.New(firewall.Config{
		Backends: []firewall.Backend{b},
		Sockets:  fakeFWSockets{sockets: sockets},
		SSH:      fakeFWSSH{ports: sshPorts},
	})
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

// AC #44.1: infra.firewall.status returns sockets, rules, and the detected backend.
func TestFirewallStatus_ReturnsSocketsRulesAndBackend(t *testing.T) {
	b := &fakeFWBackend{kind: firewall.BackendUFW, rules: []firewall.Rule{
		{Action: firewall.ActionAllow, Protocol: firewall.ProtoTCP, Port: 22},
	}}
	sockets := []firewall.Socket{{Protocol: firewall.ProtoTCP, Address: "0.0.0.0", Port: 22, Process: "sshd", PID: 100}}
	fwm := newFirewallTestMgr(t, b, []int{22}, sockets)
	resp := systemdRoundTrip(t, Config{Addr: "127.0.0.1:0", Firewall: fwm}, "infra.firewall.status", nil)
	if resp.Kind != "infra.firewall.status" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Backend   string            `json:"backend"`
		Available bool              `json:"available"`
		Rules     []firewall.Rule   `json:"rules"`
		Sockets   []firewall.Socket `json:"sockets"`
		SSHPorts  []int             `json:"ssh_ports"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if out.Backend != "ufw" || !out.Available || len(out.Rules) != 1 || len(out.Sockets) != 1 || len(out.SSHPorts) != 1 {
		t.Fatalf("unexpected status: %+v", out)
	}
}

// AC #44.2: read-only fallback when neither backend is present.
func TestFirewallStatus_ReadOnlyFallback(t *testing.T) {
	mgr, err := firewall.New(firewall.Config{
		Backends: []firewall.Backend{
			&fakeFWBackend{kind: firewall.BackendUFW, available: errors.New("ufw absent")},
			&fakeFWBackend{kind: firewall.BackendFirewalld, available: errors.New("firewalld absent")},
		},
		Sockets: fakeFWSockets{sockets: []firewall.Socket{{Protocol: firewall.ProtoTCP, Port: 22, Process: "sshd"}}},
		SSH:     fakeFWSSH{ports: []int{22}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := systemdRoundTrip(t, Config{Addr: "127.0.0.1:0", Firewall: mgr}, "infra.firewall.status", nil)
	if resp.Kind != "infra.firewall.status" {
		t.Fatalf("kind = %q", resp.Kind)
	}
	var out struct {
		Backend   string            `json:"backend"`
		Available bool              `json:"available"`
		Reason    string            `json:"unavailable_reason"`
		Sockets   []firewall.Socket `json:"sockets"`
	}
	_ = json.Unmarshal(resp.Payload, &out)
	if out.Available || out.Backend != "none" || out.Reason != "no_backend" {
		t.Fatalf("unexpected: %+v", out)
	}
	if len(out.Sockets) != 1 {
		t.Fatalf("sockets should still be reported: %+v", out.Sockets)
	}
}

// AC #44.3: rule_add requires a valid confirmation token, mutates the
// detected backend, and produces an audit row.
func TestFirewallRuleAdd_TokenAndAudit(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	b := &fakeFWBackend{kind: firewall.BackendUFW}
	fwm := newFirewallTestMgr(t, b, []int{22}, nil)
	cfg := Config{Addr: "127.0.0.1:0", Firewall: fwm, Review: rm}

	rule := firewall.Rule{Action: firewall.ActionAllow, Protocol: firewall.ProtoTCP, Port: 80}
	payload, _ := json.Marshal(map[string]any{"action": "allow", "protocol": "tcp", "port": 80})
	resp := systemdRoundTrip(t, cfg, "infra.firewall.rule_add", payload)
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("missing token kind = %q", resp.Kind)
	}
	if len(b.added) != 0 {
		t.Fatal("backend Add called without valid token")
	}
	tokAction, projectID, files := firewallRuleTokenBinding("rule_add", rule)
	tok, err := rm.MintConfirmationToken(tokAction, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"action": "allow", "protocol": "tcp", "port": 80, "confirmation_token": tok.Token})
	resp = systemdRoundTrip(t, cfg, "infra.firewall.rule_add", payload)
	if resp.Kind != "infra.firewall.rule_add" {
		t.Fatalf("ok kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(b.added) != 1 || b.added[0] != rule {
		t.Fatalf("backend not mutated: %+v", b.added)
	}
	entries, err := rm.ListAudit("infra.firewall.rule_add", "infra", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || !strings.Contains(entries[0].Summary, "succeeded") {
		t.Fatalf("missing success audit: %+v", entries)
	}
}

// AC #44.4: anti-lockout guard refuses any edit that would deny the
// active SSH port — resolved from the live connection (the SSHResolver),
// not user input — and the backend is never called.
func TestFirewall_AntiLockoutOnSSHPort_RefusedBeforeBackend(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	b := &fakeFWBackend{kind: firewall.BackendUFW, rules: []firewall.Rule{
		{Action: firewall.ActionAllow, Protocol: firewall.ProtoTCP, Port: 2222},
	}}
	// SSH resolved from "live connection" to a non-default port.
	fwm := newFirewallTestMgr(t, b, []int{2222}, nil)
	cfg := Config{Addr: "127.0.0.1:0", Firewall: fwm, Review: rm}

	// Adding a deny rule covering the SSH port: refused.
	denyRule := firewall.Rule{Action: firewall.ActionDeny, Protocol: firewall.ProtoTCP, Port: 2222}
	tokAction, projectID, files := firewallRuleTokenBinding("rule_add", denyRule)
	tok, err := rm.MintConfirmationToken(tokAction, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"action": "deny", "protocol": "tcp", "port": 2222, "confirmation_token": tok.Token})
	resp := systemdRoundTrip(t, cfg, "infra.firewall.rule_add", payload)
	if resp.Kind != "error.anti_lockout" {
		t.Fatalf("deny add kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	if len(b.added) != 0 {
		t.Fatal("backend Add called despite anti-lockout")
	}

	// Removing the allow rule covering the SSH port: refused.
	allowRule := firewall.Rule{Action: firewall.ActionAllow, Protocol: firewall.ProtoTCP, Port: 2222}
	tokAction, projectID, files = firewallRuleTokenBinding("rule_remove", allowRule)
	tok, err = rm.MintConfirmationToken(tokAction, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"action": "allow", "protocol": "tcp", "port": 2222, "confirmation_token": tok.Token})
	resp = systemdRoundTrip(t, cfg, "infra.firewall.rule_remove", payload)
	if resp.Kind != "error.anti_lockout" {
		t.Fatalf("remove kind = %q", resp.Kind)
	}
	if len(b.removed) != 0 {
		t.Fatal("backend Remove called despite anti-lockout")
	}
}

// AC (Phase 0): session.approval and session.set_mode dispatch and return OK
// against a fake runtime.
func TestSession_ApprovalAndSetModeOverWS(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pm, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "p1" }
	if _, err := pm.CreateEmpty("demo"); err != nil {
		t.Fatal(err)
	}
	sm := sessions.New(st, pm, fakeSessionRuntime{})
	sm.IDGen = func() string { return "s1" }
	if _, err := sm.Start(context.Background(), "p1", "codex", "manual", "structured"); err != nil {
		t.Fatal(err)
	}

	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Projects: pm, Sessions: sm})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	send := func(id, kind string, payload map[string]any) Frame {
		b, _ := json.Marshal(payload)
		req, _ := json.Marshal(Frame{ID: id, Kind: kind, Payload: b})
		if err := c.Write(ctx, websocket.MessageText, req); err != nil {
			t.Fatalf("write %s: %v", kind, err)
		}
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read %s: %v", kind, err)
		}
		var resp Frame
		if err := json.Unmarshal(data, &resp); err != nil {
			t.Fatalf("unmarshal %s: %v", kind, err)
		}
		return resp
	}

	resp := send("a", "session.approval", map[string]any{
		"session_id": "s1", "request_id": "req_1", "decision": "allow",
	})
	if resp.Kind != "session.approval" {
		t.Fatalf("approval kind = %q want session.approval", resp.Kind)
	}

	resp = send("m", "session.set_mode", map[string]any{
		"session_id": "s1", "mode": "plan",
	})
	if resp.Kind != "session.set_mode" {
		t.Fatalf("set_mode kind = %q want session.set_mode", resp.Kind)
	}
}

// AC (Phase 3): allowing a structured approval requires a valid, action-bound
// confirmation_token; deny needs none.
func TestSession_ApprovalConsumesConfirmationToken(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pm, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "p1" }
	if _, err := pm.CreateEmpty("demo"); err != nil {
		t.Fatal(err)
	}
	rm := review.New(pm, st, review.HeuristicSummarizer{})
	sm := sessions.New(st, pm, fakeSessionRuntime{})
	sm.IDGen = func() string { return "s1" }
	if _, err := sm.Start(context.Background(), "p1", "claude", "manual", "structured"); err != nil {
		t.Fatal(err)
	}

	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Projects: pm, Sessions: sm, Review: rm})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	send := func(id, kind string, payload map[string]any) Frame {
		b, _ := json.Marshal(payload)
		req, _ := json.Marshal(Frame{ID: id, Kind: kind, Payload: b})
		if err := c.Write(ctx, websocket.MessageText, req); err != nil {
			t.Fatalf("write %s: %v", kind, err)
		}
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read %s: %v", kind, err)
		}
		var resp Frame
		if err := json.Unmarshal(data, &resp); err != nil {
			t.Fatalf("unmarshal %s: %v", kind, err)
		}
		return resp
	}

	// allow without a token is rejected.
	resp := send("a", "session.approval", map[string]any{
		"session_id": "s1", "request_id": "req_1", "decision": "allow",
	})
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("untokened allow kind = %q want error.token_invalid", resp.Kind)
	}

	// allow with a token bound to (session.approve, p1, [], req_1) succeeds.
	tok, err := rm.MintConfirmationToken("session.approve", "p1", nil, "req_1")
	if err != nil {
		t.Fatal(err)
	}
	resp = send("b", "session.approval", map[string]any{
		"session_id": "s1", "request_id": "req_1", "decision": "allow",
		"confirmation_token": tok.Token,
	})
	if resp.Kind != "session.approval" {
		t.Fatalf("tokened allow kind = %q want session.approval", resp.Kind)
	}

	// deny needs no token.
	resp = send("d", "session.approval", map[string]any{
		"session_id": "s1", "request_id": "req_2", "decision": "deny",
	})
	if resp.Kind != "session.approval" {
		t.Fatalf("deny kind = %q want session.approval", resp.Kind)
	}
}

// AC: storage.clean requires a valid single-use confirmation token bound to
// the exact category, and every attempt (rejected or successful) is
// audited — mirroring TestDockerContainerAction_RequiresBoundConfirmationTokenAndAudits.
func TestStorageClean_RequiresConfirmationTokenAndAudits(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})

	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cache", "pip"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".cache", "pip", "w.whl"), make([]byte, 1000), 0o644); err != nil {
		t.Fatal(err)
	}
	storageMgr, err := storage.New(storage.Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]any{"category": "pip_cache"})
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Storage: storageMgr, Review: rm}, "storage.clean", payload)
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("missing token response kind = %q", resp.Kind)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".cache", "pip", "w.whl")); statErr != nil {
		t.Fatalf("missing token cleaned the cache: %v", statErr)
	}

	action, projectID, files := storageCleanTokenBinding("pip_cache")
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"category": "pip_cache", "confirmation_token": tok.Token})
	resp = dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Storage: storageMgr, Review: rm}, "storage.clean", payload)
	if resp.Kind != "storage.clean" {
		t.Fatalf("valid token response kind = %q, payload %s", resp.Kind, resp.Payload)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".cache", "pip", "w.whl")); !os.IsNotExist(statErr) {
		t.Fatalf("valid token did not clean the cache: %v", statErr)
	}

	entries, err := rm.ListAudit("storage.clean", "storage", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("audit entries = %d want 2: %+v", len(entries), entries)
	}
	if !strings.Contains(entries[0].Summary, "succeeded") || !strings.Contains(entries[1].Summary, "invalid") {
		t.Fatalf("audit entries missing outcome metadata: %+v", entries)
	}

	// The token is single-use.
	resp = dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Storage: storageMgr, Review: rm}, "storage.clean", payload)
	if resp.Kind != "error.token_used" {
		t.Fatalf("reused token response kind = %q", resp.Kind)
	}
}

// AC: storage.delete refuses a protected path before any token is consumed
// or the filesystem is touched.
func TestStorageDelete_RejectsProtectedPathBeforeTokenConsumption(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})
	storageMgr, err := storage.New(storage.Config{HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]any{"path": "/etc", "recursive": true})
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Storage: storageMgr, Review: rm}, "storage.delete", payload)
	if resp.Kind != "error.protected_path" {
		t.Fatalf("protected path response kind = %q, payload %s", resp.Kind, resp.Payload)
	}
	if _, statErr := os.Stat("/etc"); statErr != nil {
		t.Fatalf("/etc must be untouched: %v", statErr)
	}
	entries, err := rm.ListAudit("storage.delete", "storage", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.Contains(entries[0].Summary, "failed") {
		t.Fatalf("expected one failed audit entry, got %+v", entries)
	}
}

// AC: storage.delete requires a valid confirmation token bound to the exact
// path, removes the target on success, and audits both outcomes.
func TestStorageDelete_RequiresConfirmationTokenAndAudits(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rm := review.New(nil, st, review.HeuristicSummarizer{})

	home := t.TempDir()
	target := filepath.Join(home, "old-log.txt")
	if err := os.WriteFile(target, make([]byte, 77), 0o644); err != nil {
		t.Fatal(err)
	}
	storageMgr, err := storage.New(storage.Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]any{"path": target})
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Storage: storageMgr, Review: rm}, "storage.delete", payload)
	if resp.Kind != "error.token_invalid" {
		t.Fatalf("missing token response kind = %q", resp.Kind)
	}
	if _, statErr := os.Stat(target); statErr != nil {
		t.Fatalf("missing token deleted the file: %v", statErr)
	}

	action, projectID, files := storageDeleteTokenBinding(target)
	tok, err := rm.MintConfirmationToken(action, projectID, files, "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"path": target, "confirmation_token": tok.Token})
	resp = dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Storage: storageMgr, Review: rm}, "storage.delete", payload)
	if resp.Kind != "storage.delete" {
		t.Fatalf("valid token response kind = %q, payload %s", resp.Kind, resp.Payload)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("valid token did not delete the file: %v", statErr)
	}

	entries, err := rm.ListAudit("storage.delete", "storage", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || !strings.Contains(entries[0].Summary, "succeeded") || !strings.Contains(entries[1].Summary, "invalid") {
		t.Fatalf("expected succeeded+invalid audit entries, got %+v", entries)
	}
}

// AC: storage.deep_scan is an unguarded read (no confirmation token) that
// returns the deep-scan result over the wire, and its own caching means an
// immediate second call is served without re-walking unless force is set.
func TestStorageDeepScan_ReturnsResultAndCaches(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "big.bin"), make([]byte, 2000), 0o644); err != nil {
		t.Fatal(err)
	}
	storageMgr, err := storage.New(storage.Config{HomeDir: t.TempDir(), DeepScanRoot: root})
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]any{"min_size_bytes": 500})
	resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Storage: storageMgr}, "storage.deep_scan", payload)
	if resp.Kind != "storage.deep_scan" {
		t.Fatalf("response kind = %q, payload %s", resp.Kind, resp.Payload)
	}
	var out storage.DeepScanResult
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.LargeFiles) != 1 || out.LargeFilesTotalBytes != 2000 {
		t.Fatalf("unexpected result: %+v", out)
	}
	firstGeneratedAt := out.GeneratedAt

	// A second call with the same threshold returns the cached snapshot —
	// same generated_at — rather than re-walking.
	resp2 := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0", Storage: storageMgr}, "storage.deep_scan", payload)
	var out2 storage.DeepScanResult
	if err := json.Unmarshal(resp2.Payload, &out2); err != nil {
		t.Fatal(err)
	}
	if !out2.GeneratedAt.Equal(firstGeneratedAt) {
		t.Fatalf("expected cached generated_at %v, got %v", firstGeneratedAt, out2.GeneratedAt)
	}
}

func TestHandleWS_RequiresPairingKey(t *testing.T) {
	const key = "test-pairing-key"
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", ControlPlaneKey: key, RequirePairing: true})
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, resp, err := websocket.Dial(ctx, wsURL, nil); err == nil {
		t.Fatal("dial without pairing key should be rejected")
	} else if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	wrong := &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer wrong"}}}
	if _, _, err := websocket.Dial(ctx, wsURL, wrong); err == nil {
		t.Fatal("dial with wrong pairing key should be rejected")
	}

	ok := &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + key}}}
	c, _, err := websocket.Dial(ctx, wsURL, ok)
	if err != nil {
		t.Fatalf("dial with valid pairing key: %v", err)
	}
	c.Close(websocket.StatusNormalClosure, "")
}

func TestHandleWS_PairingDisabledAllowsNoKey(t *testing.T) {
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", RequirePairing: false})
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial with pairing disabled: %v", err)
	}
	c.Close(websocket.StatusNormalClosure, "")
}
