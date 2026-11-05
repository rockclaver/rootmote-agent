package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

type certsPriv struct{}

func (certsPriv) Call(_ context.Context, action string, _ ...string) ([]byte, error) {
	if action == "certs-list" {
		return []byte(`[{"name":"example.com","expiresAt":"2030-01-01T00:00:00Z"}]`), nil
	}
	return []byte("[]"), nil
}

// inventory.discover reads Let's Encrypt certificates through the privilege
// helper, and always answers with every list present (never null), even
// with nothing else configured.
func TestInventoryDiscover_ReadsCertsThroughHelper(t *testing.T) {
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Priv: certsPriv{}})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	req, _ := json.Marshal(Frame{ID: "1", Kind: "inventory.discover"})
	_ = c.Write(ctx, websocket.MessageText, req)
	resp := readFrame(t, ctx, c, "1")
	if resp.Kind != "inventory.discover" {
		t.Fatalf("got %s: %s", resp.Kind, resp.Payload)
	}
	var out struct {
		Certs              []struct{ Name string } `json:"certs"`
		PM2Apps            []any                   `json:"pm2Apps"`
		PHPFPMUnits        []string                `json:"phpFpmUnits"`
		SupervisorPrograms []any                   `json:"supervisorPrograms"`
		DatabaseUnits      []any                   `json:"databaseUnits"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Certs) != 1 || out.Certs[0].Name != "example.com" {
		t.Fatalf("certs = %+v", out.Certs)
	}
	if out.PM2Apps == nil || out.PHPFPMUnits == nil || out.SupervisorPrograms == nil || out.DatabaseUnits == nil {
		t.Fatalf("lists must be [] not null: %s", resp.Payload)
	}
}
