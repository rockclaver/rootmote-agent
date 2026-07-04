// Phase 9 AC6: end-to-end smoke harness driving the dockerized rootmote-agent
// through the protocol subset that doesn't require a real Claude/Codex agent
// or GitHub OAuth: connect → create project → write a file into the project
// workspace → diff.status sees the change → mint confirmation → review.approve
// → audit.list records the decision.
//
// Run as: rootmote-e2e-smoke -ws ws://127.0.0.1:7676/ws -workspace-root /var/lib/rootmote/projects
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"nhooyr.io/websocket"
)

type frame struct {
	ID      string          `json:"id"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func main() {
	wsURL := flag.String("ws", "ws://127.0.0.1:7676/ws", "agent WebSocket URL")
	workspaceRoot := flag.String("workspace-root", "/var/lib/rootmote/projects", "directory where the agent stores project workspaces")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, *wsURL, nil)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	rt := &runner{c: c, ctx: ctx}

	// 1. health
	if h := rt.call("h1", "server.health", nil); h.Kind != "server.health" {
		log.Fatalf("health kind: %s", h.Kind)
	}
	fmt.Println("✓ server.health")

	// 2. project.create
	resp := rt.call("p1", "project.create", map[string]any{"name": "smoke"})
	if resp.Kind != "project.create" {
		log.Fatalf("project.create: %s %s", resp.Kind, resp.Payload)
	}
	var proj struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(resp.Payload, &proj)
	fmt.Printf("✓ project.create id=%s\n", proj.ID)

	// 3. seed a file in the project workspace so diff has something to show.
	workspace := filepath.Join(*workspaceRoot, proj.ID)
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("hello smoke\n"), 0o644); err != nil {
		log.Fatalf("seed file: %v", err)
	}
	fmt.Println("✓ wrote README.md into workspace")

	// 4. diff.status sees the file
	resp = rt.call("d1", "diff.status", map[string]any{"project_id": proj.ID})
	if resp.Kind != "diff.status" {
		log.Fatalf("diff.status: %s %s", resp.Kind, resp.Payload)
	}
	var diff struct {
		Files []struct {
			Path  string `json:"path"`
			Group string `json:"group"`
		} `json:"files"`
	}
	_ = json.Unmarshal(resp.Payload, &diff)
	if len(diff.Files) == 0 {
		log.Fatalf("diff.status: expected at least one file, got 0")
	}
	fmt.Printf("✓ diff.status saw %d changed file(s)\n", len(diff.Files))

	// 5. mint a confirmation token bound to approving README.md
	resp = rt.call("c1", "auth.confirm", map[string]any{
		"action":     "review.approve",
		"project_id": proj.ID,
		"files":      []string{"README.md"},
	})
	if resp.Kind != "auth.confirm" {
		log.Fatalf("auth.confirm: %s %s", resp.Kind, resp.Payload)
	}
	var tok struct {
		Token string `json:"confirmation_token"`
	}
	_ = json.Unmarshal(resp.Payload, &tok)
	fmt.Println("✓ auth.confirm minted token")

	// 6. approve with the token
	resp = rt.call("a1", "review.approve", map[string]any{
		"project_id":         proj.ID,
		"files":              []string{"README.md"},
		"confirmation_token": tok.Token,
	})
	if resp.Kind != "review.approve" {
		log.Fatalf("review.approve: %s %s", resp.Kind, resp.Payload)
	}
	fmt.Println("✓ review.approve")

	// 7. audit.list records the decision
	resp = rt.call("au1", "audit.list", map[string]any{"project_id": proj.ID, "limit": 10})
	if resp.Kind != "audit.list" {
		log.Fatalf("audit.list: %s %s", resp.Kind, resp.Payload)
	}
	var audit struct {
		Entries []struct {
			Type string `json:"type"`
		} `json:"entries"`
	}
	_ = json.Unmarshal(resp.Payload, &audit)
	approved := false
	for _, e := range audit.Entries {
		if e.Type == "review.approve" {
			approved = true
			break
		}
	}
	if !approved {
		log.Fatalf("audit.list: no review.approve entry: %+v", audit.Entries)
	}
	fmt.Printf("✓ audit.list has %d entries with review.approve recorded\n", len(audit.Entries))

	fmt.Println("E2E smoke PASS")
}

type runner struct {
	c   *websocket.Conn
	ctx context.Context
}

func (r *runner) call(id, kind string, payload any) frame {
	var raw json.RawMessage
	if payload != nil {
		raw, _ = json.Marshal(payload)
	}
	req, _ := json.Marshal(frame{ID: id, Kind: kind, Payload: raw})
	if err := r.c.Write(r.ctx, websocket.MessageText, req); err != nil {
		log.Fatalf("write %s: %v", kind, err)
	}
	_, data, err := r.c.Read(r.ctx)
	if err != nil {
		log.Fatalf("read %s: %v", kind, err)
	}
	var resp frame
	if err := json.Unmarshal(data, &resp); err != nil {
		log.Fatalf("unmarshal %s: %v", kind, err)
	}
	if resp.ID != id {
		log.Fatalf("id mismatch on %s: got %q want %q", kind, resp.ID, id)
	}
	return resp
}
