package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/claver-agent/internal/aiproposal"
	"github.com/rockclaver/claver-agent/internal/notifications"
	"github.com/rockclaver/claver-agent/internal/runbook"
	"github.com/rockclaver/claver-agent/internal/store"
)

type stubRunbookProposer struct{ p runbook.Proposal }

func (s stubRunbookProposer) Propose(_ context.Context, _ runbook.Alert, _ runbook.Grounding) (runbook.Proposal, error) {
	return s.p, nil
}

// AC: "Each proposal renders as an approval card following the existing infra
// mutation flow." Verify infra.runbook.list returns the runbook a fired alert
// produced, and infra.runbook.get returns full details (steps + proposal_ids).
func TestRunbook_ListAndGetOverWS(t *testing.T) {
	apm := aiproposal.New()
	hub := notifications.NewHub()
	rbm, err := runbook.New(runbook.Config{
		AIProposals:   apm,
		Notifications: hub,
		Throttle:      time.Millisecond,
		Proposer: stubRunbookProposer{p: runbook.Proposal{
			Summary: "restart api",
			Risk:    runbook.RiskMedium,
			Steps: []runbook.Step{{
				Kind:        aiproposal.KindServiceAction,
				Params:      map[string]any{"name": "api.service", "action": "restart"},
				Description: "restart api",
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rb := rbm.Handle(context.Background(), runbook.Alert{
		ServerID: "local", Rule: "unit_failed", Target: "api.service",
	})
	if rb.ID == "" {
		t.Fatal("runbook not created")
	}

	wsURL, stop := startTestServerWith(t, Config{
		Addr: "127.0.0.1:0", Runbook: rbm, AIProposals: apm, Notifications: hub,
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	// list
	req, _ := json.Marshal(Frame{ID: "1", Kind: "infra.runbook.list"})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	var resp Frame
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(data, &resp)
		if resp.ID == "1" {
			break
		}
	}
	var listResp struct {
		Runbooks []runbook.Runbook `json:"runbooks"`
	}
	_ = json.Unmarshal(resp.Payload, &listResp)
	if len(listResp.Runbooks) != 1 || listResp.Runbooks[0].ID != rb.ID {
		t.Fatalf("list returned %+v", listResp.Runbooks)
	}
	if listResp.Runbooks[0].Summary != "restart api" {
		t.Fatalf("summary mismatch: %+v", listResp.Runbooks[0])
	}

	// get
	getReq, _ := json.Marshal(Frame{
		ID: "2", Kind: "infra.runbook.get",
		Payload: json.RawMessage(`{"id":"` + rb.ID + `"}`),
	})
	if err := c.Write(ctx, websocket.MessageText, getReq); err != nil {
		t.Fatal(err)
	}
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(data, &resp)
		if resp.ID == "2" {
			break
		}
	}
	var getResp struct {
		Runbook runbook.Runbook `json:"runbook"`
	}
	_ = json.Unmarshal(resp.Payload, &getResp)
	if getResp.Runbook.ID != rb.ID || len(getResp.Runbook.Steps) != 1 {
		t.Fatalf("get returned %+v", getResp.Runbook)
	}
	if len(getResp.Runbook.ProposalIDs) != 1 || getResp.Runbook.ProposalIDs[0] == "" {
		t.Fatalf("proposal_ids missing: %+v", getResp.Runbook.ProposalIDs)
	}
}

func TestRunbook_GetMissingReturnsNotFound(t *testing.T) {
	apm := aiproposal.New()
	rbm, _ := runbook.New(runbook.Config{AIProposals: apm, Proposer: stubRunbookProposer{}})

	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Runbook: rbm})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, _ := websocket.Dial(ctx, wsURL, nil)
	defer c.Close(websocket.StatusNormalClosure, "")

	req, _ := json.Marshal(Frame{
		ID: "1", Kind: "infra.runbook.get",
		Payload: json.RawMessage(`{"id":"nope"}`),
	})
	_ = c.Write(ctx, websocket.MessageText, req)
	var resp Frame
	for {
		_, data, _ := c.Read(ctx)
		_ = json.Unmarshal(data, &resp)
		if resp.ID == "1" {
			break
		}
	}
	if resp.Kind != "error.not_found" && resp.Kind != "error.unavailable" && resp.Kind != "error.bad_payload" {
		t.Fatalf("expected error kind, got %s payload=%s", resp.Kind, string(resp.Payload))
	}
}

func TestPush_RegisterUnregisterListOverWS(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", PushDevices: st})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	send := func(id, kind, payload string) Frame {
		req, _ := json.Marshal(Frame{ID: id, Kind: kind, Payload: json.RawMessage(payload)})
		if err := c.Write(ctx, websocket.MessageText, req); err != nil {
			t.Fatal(err)
		}
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var f Frame
			_ = json.Unmarshal(data, &f)
			if f.ID == id {
				return f
			}
		}
	}

	if r := send("1", "push.register", `{"token":"fcm-1","apns_token":"apns-1","platform":"ios"}`); r.Kind == "error" {
		t.Fatalf("register failed: %s", r.Payload)
	}
	if r := send("2", "push.register", `{"token":"fcm-2","platform":"android"}`); r.Kind == "error" {
		t.Fatalf("register failed: %s", r.Payload)
	}

	r := send("3", "push.list", `{}`)
	var listResp struct {
		Devices []store.PushDevice `json:"devices"`
	}
	_ = json.Unmarshal(r.Payload, &listResp)
	if len(listResp.Devices) != 2 {
		t.Fatalf("list returned %d devices: %+v", len(listResp.Devices), listResp.Devices)
	}
	for _, d := range listResp.Devices {
		if d.Token == "fcm-1" && d.APNsToken != "apns-1" {
			t.Fatalf("apns_token not relayed through push.register: %+v", d)
		}
	}

	if r := send("4", "push.unregister", `{"token":"fcm-1"}`); r.Kind == "error" {
		t.Fatalf("unregister failed: %s", r.Payload)
	}
	r = send("5", "push.list", `{}`)
	listResp.Devices = nil
	_ = json.Unmarshal(r.Payload, &listResp)
	if len(listResp.Devices) != 1 || listResp.Devices[0].Token != "fcm-2" {
		t.Fatalf("post-unregister: %+v", listResp.Devices)
	}

	// Bad payload rejected.
	if r := send("6", "push.register", `{}`); r.Kind != "error.bad_payload" {
		t.Fatalf("empty token should error, got %s", r.Kind)
	}
}

func TestPush_UnavailableWhenNotWired(t *testing.T) {
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0"})
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, _ := websocket.Dial(ctx, wsURL, nil)
	defer c.Close(websocket.StatusNormalClosure, "")
	req, _ := json.Marshal(Frame{ID: "1", Kind: "push.list", Payload: json.RawMessage(`{}`)})
	_ = c.Write(ctx, websocket.MessageText, req)
	var resp Frame
	for {
		_, data, _ := c.Read(ctx)
		_ = json.Unmarshal(data, &resp)
		if resp.ID == "1" {
			break
		}
	}
	if resp.Kind != "error.not_found" && resp.Kind != "error.unavailable" && resp.Kind != "error.bad_payload" {
		t.Fatalf("expected error, got %s", resp.Kind)
	}
}
