package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/claver-agent/internal/actions"
	"github.com/rockclaver/claver-agent/internal/store"
)

// readFrame reads frames until it sees one matching id.
func readFrame(t *testing.T, ctx context.Context, c *websocket.Conn, id string) Frame {
	t.Helper()
	var resp Frame
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		_ = json.Unmarshal(data, &resp)
		if resp.ID == id {
			return resp
		}
	}
}

// AC (Phase 1): "Agent exposes action job RPCs: submit, list, get, cancel."
// Drive the full ledger lifecycle over the WebSocket transport with an inline
// read-only planner so the job reaches a terminal "observed" state.
func TestAction_SubmitListGetOverWS(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	am, err := actions.New(actions.Config{
		Store:    st,
		Dispatch: func(f func()) { f() }, // inline so submit completes synchronously
		Planner: actions.PlannerFunc(func(context.Context, actions.Request) (actions.Result, error) {
			return actions.Result{Status: actions.StatusObserved, Summary: "all healthy"}, nil
		}),
	})
	if err != nil {
		t.Fatalf("new actions: %v", err)
	}

	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Actions: am})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	// submit
	subReq, _ := json.Marshal(Frame{
		ID: "1", Kind: "action.submit",
		Payload: json.RawMessage(`{"text":"is the api ok","worker":"claude"}`),
	})
	_ = c.Write(ctx, websocket.MessageText, subReq)
	resp := readFrame(t, ctx, c, "1")
	if resp.Kind != "action.submit" {
		t.Fatalf("submit kind = %s payload=%s", resp.Kind, resp.Payload)
	}
	var subResp struct {
		Job actions.Job `json:"job"`
	}
	_ = json.Unmarshal(resp.Payload, &subResp)
	jobID := subResp.Job.ID
	if jobID == "" {
		t.Fatal("no job id")
	}

	// get -> should be observed with events
	getReq, _ := json.Marshal(Frame{ID: "2", Kind: "action.get", Payload: json.RawMessage(`{"id":"` + jobID + `"}`)})
	_ = c.Write(ctx, websocket.MessageText, getReq)
	resp = readFrame(t, ctx, c, "2")
	var getResp struct {
		Job actions.Job `json:"job"`
	}
	_ = json.Unmarshal(resp.Payload, &getResp)
	if getResp.Job.Status != actions.StatusObserved {
		t.Fatalf("status = %q, want observed", getResp.Job.Status)
	}
	if len(getResp.Job.Events) == 0 {
		t.Fatal("expected event trail")
	}

	// list
	listReq, _ := json.Marshal(Frame{ID: "3", Kind: "action.list"})
	_ = c.Write(ctx, websocket.MessageText, listReq)
	resp = readFrame(t, ctx, c, "3")
	var listResp struct {
		Jobs []actions.Job `json:"jobs"`
	}
	_ = json.Unmarshal(resp.Payload, &listResp)
	if len(listResp.Jobs) != 1 || listResp.Jobs[0].ID != jobID {
		t.Fatalf("list = %+v", listResp.Jobs)
	}
}

func TestAction_SubmitRequiresText(t *testing.T) {
	st, _ := store.Open(":memory:")
	t.Cleanup(func() { st.Close() })
	am, _ := actions.New(actions.Config{
		Store:    st,
		Dispatch: func(f func()) { f() },
		Planner:  actions.PlannerFunc(func(context.Context, actions.Request) (actions.Result, error) { return actions.Result{Status: actions.StatusObserved}, nil }),
	})
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Actions: am})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, _ := websocket.Dial(ctx, wsURL, nil)
	defer c.Close(websocket.StatusNormalClosure, "")

	req, _ := json.Marshal(Frame{ID: "1", Kind: "action.submit", Payload: json.RawMessage(`{"text":"  "}`)})
	_ = c.Write(ctx, websocket.MessageText, req)
	resp := readFrame(t, ctx, c, "1")
	if resp.Kind != "error.bad_payload" {
		t.Fatalf("expected error.bad_payload, got %s", resp.Kind)
	}
}

func TestAction_UnavailableWhenNotWired(t *testing.T) {
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0"})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, _ := websocket.Dial(ctx, wsURL, nil)
	defer c.Close(websocket.StatusNormalClosure, "")

	req, _ := json.Marshal(Frame{ID: "1", Kind: "action.list"})
	_ = c.Write(ctx, websocket.MessageText, req)
	resp := readFrame(t, ctx, c, "1")
	if resp.Kind != "error.unavailable" {
		t.Fatalf("expected error.unavailable, got %s", resp.Kind)
	}
}
