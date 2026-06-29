package sessions

import (
	"encoding/json"
	"os"
	"testing"
)

// goldenFixture is shared verbatim with the Dart client test
// (test/agent_event_test.dart) so both languages prove they decode the exact
// same bytes of the normalized contract.
const goldenFixture = "fixtures/normalized_events.json"

func loadGolden(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(goldenFixture)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	return m
}

func mustDecode(t *testing.T, raw json.RawMessage, v any) {
	t.Helper()
	if len(raw) == 0 {
		t.Fatalf("missing golden entry for %T", v)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode %T: %v", v, err)
	}
}

// TestNormalizedSchema_DecodesGolden proves every normalized event type in the
// shared fixture decodes into its Go struct with the expected field values.
func TestNormalizedSchema_DecodesGolden(t *testing.T) {
	g := loadGolden(t)

	var md MessageDelta
	mustDecode(t, g[EvMessageDelta], &md)
	if md.Role != "assistant" || md.Text != "Hel" {
		t.Fatalf("message_delta: %+v", md)
	}

	var msg Message
	mustDecode(t, g[EvMessage], &msg)
	if msg.Text != "Hello, world" || len(msg.Blocks) != 1 || msg.Blocks[0].Kind != "text" {
		t.Fatalf("message: %+v", msg)
	}

	var r Reasoning
	mustDecode(t, g[EvReasoning], &r)
	if r.Text == "" {
		t.Fatalf("reasoning empty")
	}

	var tc ToolCall
	mustDecode(t, g[EvToolCall], &tc)
	if tc.CallID != "call_1" || tc.Name != "Bash" || tc.Status != ToolCompleted || tc.Result != "total 0" {
		t.Fatalf("tool_call: %+v", tc)
	}
	var args struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(tc.Args, &args); err != nil || args.Command != "ls -la" {
		t.Fatalf("tool_call args: %v %+v", err, args)
	}

	var d Diff
	mustDecode(t, g[EvDiff], &d)
	if d.Path != "main.go" || d.CallID != "call_2" || d.Patch == "" {
		t.Fatalf("diff: %+v", d)
	}

	var p Plan
	mustDecode(t, g[EvPlan], &p)
	if !p.Gating || len(p.Items) != 2 || p.Items[0].Status != "completed" || p.Items[1].Title != "Write fix" {
		t.Fatalf("plan: %+v", p)
	}

	var ar ApprovalRequest
	mustDecode(t, g[EvApprovalRequest], &ar)
	if ar.RequestID != "req_1" || ar.Kind != ApprovalCommand || len(ar.Options) != 3 {
		t.Fatalf("approval_request: %+v", ar)
	}

	var u Usage
	mustDecode(t, g[EvUsage], &u)
	if u.Input != 1200 || u.Output != 340 || u.Cache != 100 || u.CostUSD != 0.0123 {
		t.Fatalf("usage: %+v", u)
	}

	var turn Turn
	mustDecode(t, g[EvTurn], &turn)
	if turn.State != TurnComplete || turn.StopReason != "end_turn" {
		t.Fatalf("turn: %+v", turn)
	}

	var e ErrorEvent
	mustDecode(t, g[EvError], &e)
	if e.Message == "" || !e.Fatal {
		t.Fatalf("error: %+v", e)
	}

	// The fixture and the schema must stay in lockstep: every golden key is a
	// known event type and every known type appears in the golden file.
	known := map[string]bool{
		EvMessageDelta: true, EvMessage: true, EvReasoning: true, EvToolCall: true,
		EvDiff: true, EvPlan: true, EvApprovalRequest: true, EvUsage: true,
		EvTurn: true, EvError: true,
	}
	for k := range g {
		if !known[k] {
			t.Fatalf("golden has unknown event type %q", k)
		}
	}
	for k := range known {
		if _, ok := g[k]; !ok {
			t.Fatalf("golden missing event type %q", k)
		}
	}
}

// TestNormalizedEvent_RoundTrip checks the runtime helper produces a
// store.SessionEvent whose Data decodes back to the original payload.
func TestNormalizedEvent_RoundTrip(t *testing.T) {
	ev, err := normalizedEvent("s1", EvUsage, Usage{Input: 5, Output: 7, Cache: 1, CostUSD: 0.5})
	if err != nil {
		t.Fatal(err)
	}
	if ev.SessionID != "s1" || ev.Type != EvUsage {
		t.Fatalf("event meta: %+v", ev)
	}
	var u Usage
	if err := json.Unmarshal([]byte(ev.Data), &u); err != nil {
		t.Fatal(err)
	}
	if u.Input != 5 || u.Output != 7 || u.Cache != 1 || u.CostUSD != 0.5 {
		t.Fatalf("roundtrip: %+v", u)
	}
}

func TestNormalizeTransport(t *testing.T) {
	cases := map[string]string{
		"":           TransportTerminal,
		"terminal":   TransportTerminal,
		"structured": TransportStructured,
		"bogus":      TransportTerminal,
	}
	for in, want := range cases {
		if got := normalizeTransport(in); got != want {
			t.Fatalf("normalizeTransport(%q) = %q want %q", in, got, want)
		}
	}
}
