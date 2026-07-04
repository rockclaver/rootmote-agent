package sessions

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/store"
)

type collectedEvent struct {
	ev        store.SessionEvent
	ephemeral bool
}

type eventCollector struct {
	mu  sync.Mutex
	evs []collectedEvent
}

func (c *eventCollector) emit(ev store.SessionEvent)      { c.add(ev, false) }
func (c *eventCollector) ephemeral(ev store.SessionEvent) { c.add(ev, true) }
func (c *eventCollector) add(ev store.SessionEvent, eph bool) {
	c.mu.Lock()
	c.evs = append(c.evs, collectedEvent{ev: ev, ephemeral: eph})
	c.mu.Unlock()
}

func (c *eventCollector) byType(t string) []collectedEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []collectedEvent
	for _, e := range c.evs {
		if e.ev.Type == t {
			out = append(out, e)
		}
	}
	return out
}

func (c *eventCollector) waitForType(t *testing.T, typ string, d time.Duration) collectedEvent {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if m := c.byType(typ); len(m) > 0 {
			return m[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q event", typ)
	return collectedEvent{}
}

// waitForCount waits until at least n events of typ have been collected and
// returns the nth (1-indexed). Unlike waitForType it does not return on a stale
// earlier event, so a test can feed a second event of an already-seen type and
// act on it only after the conn has actually processed it.
func (c *eventCollector) waitForCount(t *testing.T, typ string, n int, d time.Duration) collectedEvent {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if m := c.byType(typ); len(m) >= n {
			return m[n-1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d %q events", n, typ)
	return collectedEvent{}
}

// lineCapture is a non-blocking io.Writer that pushes each complete line written
// to it onto a channel, so a test can read what the conn sent to the CLI without
// blocking the conn's writes (unlike io.Pipe).
type lineCapture struct {
	mu  sync.Mutex
	buf []byte
	ch  chan string
}

func newLineCapture() *lineCapture { return &lineCapture{ch: make(chan string, 64)} }

func (l *lineCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	l.buf = append(l.buf, p...)
	for {
		i := indexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		line := string(l.buf[:i])
		l.buf = l.buf[i+1:]
		l.ch <- line
	}
	l.mu.Unlock()
	return len(p), nil
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func (l *lineCapture) read(t *testing.T) map[string]any {
	t.Helper()
	select {
	case s := <-l.ch:
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("conn wrote non-JSON line %q: %v", s, err)
		}
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading conn output")
		return nil
	}
}

type connHarness struct {
	conn   *claudeConn
	stdout *io.PipeWriter
	out    *lineCapture
	coll   *eventCollector
}

func newConnHarness(t *testing.T) *connHarness {
	t.Helper()
	stdoutR, stdoutW := io.Pipe()
	out := newLineCapture()
	coll := &eventCollector{}
	conn := newClaudeConn(structuredSink{sessionID: "s1", emit: coll.emit, ephemeral: coll.ephemeral}, out)
	go conn.run(stdoutR)
	t.Cleanup(func() { _ = stdoutW.Close() })
	return &connHarness{conn: conn, stdout: stdoutW, out: out, coll: coll}
}

func (h *connHarness) feed(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(h.stdout, line+"\n"); err != nil {
		t.Fatalf("feed: %v", err)
	}
}

func TestClaudeConn_TranslatesOutput(t *testing.T) {
	h := newConnHarness(t)
	h.feed(t, `{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Hello"}],"usage":{"input_tokens":1,"output_tokens":2}}}`)
	h.feed(t, `{"type":"result","subtype":"success","is_error":false,"result":"Hello","stop_reason":"end_turn","total_cost_usd":0.01,"usage":{"input_tokens":1,"output_tokens":2,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}`)

	msg := h.coll.waitForType(t, EvMessage, time.Second)
	var m Message
	if err := json.Unmarshal([]byte(msg.ev.Data), &m); err != nil || m.Text != "Hello" {
		t.Fatalf("message = %v %q", err, msg.ev.Data)
	}
	if msg.ev.SessionID != "s1" {
		t.Fatalf("session id = %q", msg.ev.SessionID)
	}
	h.coll.waitForType(t, EvUsage, time.Second)
	h.coll.waitForType(t, EvTurn, time.Second)
}

func TestClaudeConn_SendPromptWritesUserMessage(t *testing.T) {
	h := newConnHarness(t)
	if err := h.conn.sendUser("hello world"); err != nil {
		t.Fatal(err)
	}
	m := h.out.read(t)
	if m["type"] != "user" {
		t.Fatalf("type = %v", m["type"])
	}
	msg, _ := m["message"].(map[string]any)
	if msg["role"] != "user" || msg["content"] != "hello world" {
		t.Fatalf("message = %v", msg)
	}
}

func TestClaudeConn_Initialize(t *testing.T) {
	h := newConnHarness(t)
	errc := make(chan error, 1)
	go func() { errc <- h.conn.initialize(context.Background()) }()

	req := h.out.read(t)
	if req["type"] != "control_request" {
		t.Fatalf("type = %v", req["type"])
	}
	reqID, _ := req["request_id"].(string)
	if reqID == "" {
		t.Fatal("missing request_id")
	}
	if r, _ := req["request"].(map[string]any); r["subtype"] != "initialize" {
		t.Fatalf("subtype = %v", r["subtype"])
	}
	h.feed(t, `{"type":"control_response","response":{"subtype":"success","request_id":"`+reqID+`","response":{}}}`)

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("initialize: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("initialize did not return")
	}
}

func TestClaudeConn_ApprovalAllowEchoesInput(t *testing.T) {
	h := newConnHarness(t)
	h.feed(t, `{"type":"control_request","request_id":"req-1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"ls -la"}}}`)

	ar := h.coll.waitForType(t, EvApprovalRequest, time.Second)
	var req ApprovalRequest
	if err := json.Unmarshal([]byte(ar.ev.Data), &req); err != nil || req.RequestID != "req-1" {
		t.Fatalf("approval = %v %q", err, ar.ev.Data)
	}

	if err := h.conn.approve("req-1", DecisionAllow, ""); err != nil {
		t.Fatal(err)
	}
	resp := h.out.read(t)
	if resp["type"] != "control_response" {
		t.Fatalf("type = %v", resp["type"])
	}
	inner, _ := resp["response"].(map[string]any)
	if inner["request_id"] != "req-1" {
		t.Fatalf("request_id = %v", inner["request_id"])
	}
	rd, _ := inner["response"].(map[string]any)
	if rd["behavior"] != "allow" {
		t.Fatalf("behavior = %v", rd["behavior"])
	}
	ui, _ := rd["updatedInput"].(map[string]any)
	if ui["command"] != "ls -la" {
		t.Fatalf("updatedInput = %v", rd["updatedInput"])
	}
}

func TestClaudeConn_ApprovalDeny(t *testing.T) {
	h := newConnHarness(t)
	h.feed(t, `{"type":"control_request","request_id":"req-2","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"rm -rf /"}}}`)
	h.coll.waitForType(t, EvApprovalRequest, time.Second)

	if err := h.conn.approve("req-2", DecisionDeny, "nope"); err != nil {
		t.Fatal(err)
	}
	resp := h.out.read(t)
	inner, _ := resp["response"].(map[string]any)
	rd, _ := inner["response"].(map[string]any)
	if rd["behavior"] != "deny" || rd["message"] != "nope" {
		t.Fatalf("deny response = %v", rd)
	}
}

func TestClaudeConn_AllowAlwaysSuppressesReprompt(t *testing.T) {
	h := newConnHarness(t)
	// First Bash approval prompts the user.
	h.feed(t, `{"type":"control_request","request_id":"req-1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"ls"}}}`)
	h.coll.waitForType(t, EvApprovalRequest, time.Second)
	if err := h.conn.approve("req-1", DecisionAllowAlways, ""); err != nil {
		t.Fatal(err)
	}
	h.out.read(t) // consume the allow response for req-1

	// A second Bash call is auto-allowed by the standing rule: a control_response
	// is written immediately and no new approval prompt is emitted.
	h.feed(t, `{"type":"control_request","request_id":"req-2","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"pwd"}}}`)
	resp := h.out.read(t)
	inner, _ := resp["response"].(map[string]any)
	if inner["request_id"] != "req-2" {
		t.Fatalf("auto-allow request_id = %v", inner["request_id"])
	}
	rd, _ := inner["response"].(map[string]any)
	if rd["behavior"] != "allow" {
		t.Fatalf("auto-allow behavior = %v", rd)
	}
	if got := h.coll.byType(EvApprovalRequest); len(got) != 1 {
		t.Fatalf("approval_request count = %d, want 1 (second auto-allowed)", len(got))
	}
}

func TestClaudeConn_AllowAlwaysScopedToTool(t *testing.T) {
	h := newConnHarness(t)
	h.feed(t, `{"type":"control_request","request_id":"req-1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"ls"}}}`)
	h.coll.waitForType(t, EvApprovalRequest, time.Second)
	if err := h.conn.approve("req-1", DecisionAllowAlways, ""); err != nil {
		t.Fatal(err)
	}
	h.out.read(t)

	// A different tool is not covered by the Bash rule and still prompts.
	h.feed(t, `{"type":"control_request","request_id":"req-2","request":{"subtype":"can_use_tool","tool_name":"Edit","input":{"file_path":"/x"}}}`)
	deadline := time.Now().Add(time.Second)
	var prompts []collectedEvent
	for time.Now().Before(deadline) {
		if prompts = h.coll.byType(EvApprovalRequest); len(prompts) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(prompts) != 2 {
		t.Fatalf("approval_request count = %d, want 2 (Edit not covered)", len(prompts))
	}
	var req ApprovalRequest
	if err := json.Unmarshal([]byte(prompts[1].ev.Data), &req); err != nil || req.RequestID != "req-2" {
		t.Fatalf("second prompt = %v %q", err, prompts[1].ev.Data)
	}
}

func TestClaudeConn_InterruptAndSetMode(t *testing.T) {
	h := newConnHarness(t)

	for _, tc := range []struct {
		call    func() error
		subtype string
		extra   func(map[string]any) bool
	}{
		{func() error { return h.conn.interrupt(context.Background()) }, "interrupt", nil},
		{func() error { return h.conn.setMode(context.Background(), "plan") }, "set_permission_mode", func(r map[string]any) bool { return r["mode"] == "plan" }},
	} {
		errc := make(chan error, 1)
		go func() { errc <- tc.call() }()
		req := h.out.read(t)
		r, _ := req["request"].(map[string]any)
		if r["subtype"] != tc.subtype {
			t.Fatalf("subtype = %v want %s", r["subtype"], tc.subtype)
		}
		if tc.extra != nil && !tc.extra(r) {
			t.Fatalf("extra check failed for %s: %v", tc.subtype, r)
		}
		reqID, _ := req["request_id"].(string)
		h.feed(t, `{"type":"control_response","response":{"subtype":"success","request_id":"`+reqID+`","response":{}}}`)
		select {
		case err := <-errc:
			if err != nil {
				t.Fatalf("%s: %v", tc.subtype, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not return", tc.subtype)
		}
	}
}

const claudeStub = `#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"subtype":"initialize"'*)
      id=` + "`" + `printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p'` + "`" + `
      printf '{"type":"control_response","response":{"subtype":"success","request_id":"%s","response":{}}}\n' "$id"
      ;;
    *'"type":"user"'*)
      printf '%s\n' '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"hi there"}],"usage":{"input_tokens":1,"output_tokens":2,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}}'
      printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"result":"hi there","stop_reason":"end_turn","total_cost_usd":0.001,"usage":{"input_tokens":1,"output_tokens":2,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}'
      ;;
  esac
done
`

func TestClaudeStructuredRuntime_StubEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub uses a POSIX shell")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "claude")
	if err := os.WriteFile(stub, []byte(claudeStub), 0o755); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(dir, "work")

	coll := &eventCollector{}
	rt := NewClaudeStructuredRuntime(dir, "", nil)
	spec := RuntimeSpec{
		SessionID:     "s1",
		Agent:         "claude",
		RunMode:       "manual",
		Transport:     TransportStructured,
		WorkDir:       work,
		Emit:          coll.emit,
		EmitEphemeral: coll.ephemeral,
	}
	if err := rt.Start(context.Background(), spec); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = rt.Stop(context.Background(), "s1") })

	if !rt.Alive(context.Background(), "s1") {
		t.Fatal("expected session alive after start")
	}
	if err := rt.SendPrompt(context.Background(), "s1", "hi"); err != nil {
		t.Fatalf("send prompt: %v", err)
	}

	msg := coll.waitForType(t, EvMessage, 3*time.Second)
	var m Message
	if err := json.Unmarshal([]byte(msg.ev.Data), &m); err != nil || m.Text != "hi there" {
		t.Fatalf("message = %v %q", err, msg.ev.Data)
	}
	u := coll.waitForType(t, EvUsage, 3*time.Second)
	var usage Usage
	if err := json.Unmarshal([]byte(u.ev.Data), &usage); err != nil || usage.Input != 1 || usage.Output != 2 {
		t.Fatalf("usage = %v %q", err, u.ev.Data)
	}
	coll.waitForType(t, EvTurn, 3*time.Second)

	if err := rt.Stop(context.Background(), "s1"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if rt.Alive(context.Background(), "s1") {
		t.Fatal("expected session not alive after stop")
	}
}
