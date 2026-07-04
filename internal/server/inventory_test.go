package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/inventory"
)

func TestInventoryCapabilitiesOverWS(t *testing.T) {
	inv := inventory.New(inventory.Config{
		Now: func() time.Time { return time.Unix(1_800_000_000, 0) },
	})
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Inventory: inv})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	req, _ := json.Marshal(Frame{ID: "1", Kind: "inventory.capabilities"})
	_ = c.Write(ctx, websocket.MessageText, req)
	resp := readFrame(t, ctx, c, "1")
	if resp.Kind != "inventory.capabilities" {
		t.Fatalf("kind = %s payload=%s", resp.Kind, resp.Payload)
	}
	var out struct {
		Snapshot inventory.Snapshot `json:"snapshot"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Snapshot.Docker.UnavailableReason != inventory.ReasonNotConfigured {
		t.Fatalf("docker reason = %q", out.Snapshot.Docker.UnavailableReason)
	}
	if out.Snapshot.AIClis["claude"].UnavailableReason != inventory.ReasonNotConfigured {
		t.Fatalf("claude reason = %+v", out.Snapshot.AIClis["claude"])
	}
}

func TestInventoryUnavailableWhenNotWired(t *testing.T) {
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0"})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	req, _ := json.Marshal(Frame{ID: "1", Kind: "inventory.capabilities"})
	_ = c.Write(ctx, websocket.MessageText, req)
	resp := readFrame(t, ctx, c, "1")
	if resp.Kind != "error.unavailable" {
		t.Fatalf("expected error.unavailable, got %s", resp.Kind)
	}
}
