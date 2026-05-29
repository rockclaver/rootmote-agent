package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/claver/agent/internal/cliauth"
	"github.com/rockclaver/claver/agent/internal/docker"
	gh "github.com/rockclaver/claver/agent/internal/github"
	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/review"
	"github.com/rockclaver/claver/agent/internal/sessions"
	"github.com/rockclaver/claver/agent/internal/store"
	"github.com/rockclaver/claver/agent/internal/version"
)

type fakeSessionRuntime struct{}

func (fakeSessionRuntime) Start(_ context.Context, spec sessions.RuntimeSpec) error {
	_, _ = spec.Output.Write([]byte("ready\n"))
	return nil
}
func (fakeSessionRuntime) Attach(context.Context, sessions.RuntimeSpec) error { return nil }
func (fakeSessionRuntime) SendPrompt(context.Context, string, string) error   { return nil }
func (fakeSessionRuntime) Interrupt(context.Context, string) error            { return nil }
func (fakeSessionRuntime) Stop(context.Context, string) error                 { return nil }
func (fakeSessionRuntime) Capture(context.Context, string) (string, error)    { return "", nil }
func (fakeSessionRuntime) Alive(context.Context, string) bool                 { return true }

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
	if _, err := sm.Start(context.Background(), "p1", "codex"); err != nil {
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
	if _, err := sm.Start(context.Background(), "p1", "codex"); err != nil {
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
	payload, _ := json.Marshal(map[string]any{"id": "abc"})
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

func dockerRoundTrip(t *testing.T, mgr *docker.Manager, kind string, payload []byte) Frame {
	t.Helper()
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Docker: mgr})
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
	v           docker.VersionInfo
	err         error
	containers  []docker.ContainerSummary
	detail      docker.ContainerDetail
	images      []docker.ImageSummary
	imageDetail docker.ImageDetail
	volumes     []docker.VolumeSummary
	networks    []docker.NetworkSummary
	daemon      docker.DaemonInfo
	logs        []docker.LogEntry
	streamLogs  []docker.LogEntry
	streamErr   error
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
	for _, entry := range f.streamLogs {
		emit(entry)
	}
	return f.streamErr
}

type fakeErr struct{ cause error }

func (e fakeErr) Error() string { return "fake: " + e.cause.Error() }
func (e fakeErr) Unwrap() error { return e.cause }

func mustWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
