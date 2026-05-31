package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/claver/agent/internal/memory"
	"github.com/rockclaver/claver/agent/internal/store"
)

var rtSeq atomic.Int64

// roundTrip dials the test server, sends one frame, and returns the response.
// Each call uses a unique frame id so the server's replay-dedupe does not
// short-circuit a repeated kind (e.g. two memory.list calls in one test).
func roundTrip(t *testing.T, wsURL, kind string, payload map[string]any) Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	var raw json.RawMessage
	if payload != nil {
		raw, _ = json.Marshal(payload)
	}
	id := fmt.Sprintf("%s-%d", kind, rtSeq.Add(1))
	req, _ := json.Marshal(Frame{ID: id, Kind: kind, Payload: raw})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp Frame
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func newMemoryTestServer(t *testing.T) (string, *memory.Manager, func()) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.CreateProject(store.Project{ID: "p1", Name: "Demo"}); err != nil {
		t.Fatalf("project: %v", err)
	}
	mem := memory.New(st)
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0", Memory: mem})
	cleanup := func() { stop(); _ = st.Close() }
	return wsURL, mem, cleanup
}

func TestMemoryRPC_CRUDAndJournalExport(t *testing.T) {
	wsURL, _, cleanup := newMemoryTestServer(t)
	defer cleanup()

	// create
	resp := roundTrip(t, wsURL, "memory.create", map[string]any{
		"project_id": "p1", "kind": "convention", "title": "Use tabs", "body": "gofmt",
	})
	if resp.Kind != "memory.create" {
		t.Fatalf("create resp: %s %s", resp.Kind, resp.Payload)
	}
	var created MemoryDTO
	_ = json.Unmarshal(resp.Payload, &created)
	if created.ID == "" || created.Title != "Use tabs" {
		t.Fatalf("bad created: %+v", created)
	}

	// invalid kind => bad_payload
	bad := roundTrip(t, wsURL, "memory.create", map[string]any{
		"project_id": "p1", "kind": "nope", "title": "x",
	})
	if bad.Kind != "error.bad_payload" {
		t.Fatalf("expected error.bad_payload, got %s", bad.Kind)
	}

	// list
	resp = roundTrip(t, wsURL, "memory.list", map[string]any{"project_id": "p1"})
	var listOut struct {
		Memories []MemoryDTO `json:"memories"`
	}
	_ = json.Unmarshal(resp.Payload, &listOut)
	if len(listOut.Memories) != 1 {
		t.Fatalf("list = %d", len(listOut.Memories))
	}

	// update
	resp = roundTrip(t, wsURL, "memory.update", map[string]any{
		"id": created.ID, "kind": "gotcha", "title": "Watch WAL", "body": "b",
	})
	var updated MemoryDTO
	_ = json.Unmarshal(resp.Payload, &updated)
	if updated.Kind != "gotcha" || updated.Title != "Watch WAL" {
		t.Fatalf("update failed: %+v", updated)
	}

	// delete
	resp = roundTrip(t, wsURL, "memory.delete", map[string]any{"id": created.ID})
	if resp.Kind != "memory.delete" {
		t.Fatalf("delete resp: %s", resp.Kind)
	}
	resp = roundTrip(t, wsURL, "memory.list", map[string]any{"project_id": "p1"})
	_ = json.Unmarshal(resp.Payload, &listOut)
	if len(listOut.Memories) != 0 {
		t.Fatalf("expected empty after delete, got %d", len(listOut.Memories))
	}

	// journal export (empty)
	resp = roundTrip(t, wsURL, "journal.export", map[string]any{"project_id": "p1"})
	var exp struct {
		Markdown string `json:"markdown"`
	}
	_ = json.Unmarshal(resp.Payload, &exp)
	if exp.Markdown == "" {
		t.Fatalf("expected markdown export")
	}
}

// AC: "AI-proposed memory requires confirmation before persisting" — exercised
// over the wire: a pending proposal is listed, then memory.confirm persists it.
func TestMemoryRPC_ProposalConfirmFlow(t *testing.T) {
	wsURL, mem, cleanup := newMemoryTestServer(t)
	defer cleanup()

	// Seed a session-end proposal via the manager (as the summarizer would).
	mem.Transcript = func(string) (string, error) { return "work", nil }
	mem.Summarizer = stubSummarizer{}
	if err := mem.OnSessionEnd(context.Background(), store.Session{ID: "s1", ProjectID: "p1", Agent: "claude"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp := roundTrip(t, wsURL, "memory.proposals", map[string]any{"project_id": "p1"})
	var props struct {
		Proposals []MemoryProposalDTO `json:"proposals"`
	}
	_ = json.Unmarshal(resp.Payload, &props)
	if len(props.Proposals) != 1 {
		t.Fatalf("expected 1 proposal, got %d", len(props.Proposals))
	}

	// Not yet persisted.
	resp = roundTrip(t, wsURL, "memory.list", map[string]any{"project_id": "p1"})
	var listOut struct {
		Memories []MemoryDTO `json:"memories"`
	}
	_ = json.Unmarshal(resp.Payload, &listOut)
	if len(listOut.Memories) != 0 {
		t.Fatalf("proposal persisted before confirm: %d", len(listOut.Memories))
	}

	// Confirm persists it.
	resp = roundTrip(t, wsURL, "memory.confirm", map[string]any{"id": props.Proposals[0].ID})
	if resp.Kind != "memory.confirm" {
		t.Fatalf("confirm resp: %s %s", resp.Kind, resp.Payload)
	}
	resp = roundTrip(t, wsURL, "memory.list", map[string]any{"project_id": "p1"})
	_ = json.Unmarshal(resp.Payload, &listOut)
	if len(listOut.Memories) != 1 {
		t.Fatalf("confirmed memory not persisted: %d", len(listOut.Memories))
	}

	// Journal entry should exist with one page and no further cursor.
	resp = roundTrip(t, wsURL, "journal.list", map[string]any{"project_id": "p1", "limit": 10})
	var jl struct {
		Entries    []JournalEntryDTO `json:"entries"`
		NextCursor int64             `json:"next_cursor"`
	}
	_ = json.Unmarshal(resp.Payload, &jl)
	if len(jl.Entries) != 1 || jl.NextCursor != 0 {
		t.Fatalf("journal.list = %+v next=%d", jl.Entries, jl.NextCursor)
	}
}

type stubSummarizer struct{}

func (stubSummarizer) Summarize(_ context.Context, _, _, _ string) (memory.SessionSummary, error) {
	return memory.SessionSummary{
		Bullets:  []string{"Did the thing"},
		Proposed: []memory.ProposedMemory{{Kind: "decision", Title: "Chose SQLite", Body: "user-owned"}},
	}, nil
}

func TestMemoryRPC_Unavailable(t *testing.T) {
	wsURL, stop := startTestServerWith(t, Config{Addr: "127.0.0.1:0"})
	defer stop()
	resp := roundTrip(t, wsURL, "memory.list", map[string]any{"project_id": "p1"})
	if resp.Kind != "error.unavailable" {
		t.Fatalf("expected error.unavailable, got %s", resp.Kind)
	}
}
