package sessions

// phase7_test.go holds the Phase 7 (verification & hardening) automated tests:
//   - reconnect/replay loses no persisted event and duplicates no delta;
//   - malformed/unknown protocol lines are logged and skipped without tearing
//     the session down;
//   - a child crash surfaces a fatal error event and ends the session.
//
// The live, env-gated end-to-end flows live in live_e2e_test.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/store"
)

// warnRecorder captures structuredSink.warn calls so a test can assert a
// dropped/unknown protocol line was logged rather than silently swallowed.
type warnRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warnRecorder) warn(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, fmt.Sprintf(format, args...))
}

func (w *warnRecorder) all() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.msgs...)
}

func (w *warnRecorder) contains(sub string) bool {
	for _, m := range w.all() {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

func TestStructuredSink_PublishesStderrAsErrorEvents(t *testing.T) {
	coll := &eventCollector{}
	sink := structuredSink{sessionID: "s1", emit: coll.emit}

	sink.publishStderr(strings.NewReader("\nprotocol mismatch\n"), "codex stderr")

	got := coll.waitForType(t, EvError, time.Second)
	var ev ErrorEvent
	if err := json.Unmarshal([]byte(got.ev.Data), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Fatal {
		t.Fatalf("stderr event should be non-fatal: %+v", ev)
	}
	if !strings.Contains(ev.Message, "codex stderr: protocol mismatch") {
		t.Fatalf("stderr message = %q", ev.Message)
	}
}

// AC: "Reconnect during a live turn loses no persisted events and duplicates no
// deltas (automated)." AppendSessionEvent and fanout are not atomic, so an event
// persisted just before a reconnect's replay snapshot and fanned out just after
// the subscriber registered would arrive twice. The subscriber must drop the
// racing duplicate while still delivering genuinely new events and ephemeral
// deltas (which are never persisted).
func TestSubscribe_DeduplicatesReplayLiveBoundary(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", TransportStructured); err != nil {
		t.Fatal(err)
	}
	// One persisted event already in the log before the (re)connect.
	evA, err := m.Publish(store.SessionEvent{SessionID: "s1", Type: EvMessage, Data: "A"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, cleanup, err := m.Subscribe(ctx, "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Replay carries evA; now fan it out again to mimic the append/fanout race
	// at the replay/live boundary. The subscriber must not re-emit it.
	m.fanout(evA)
	// A genuinely new persisted event must still arrive exactly once.
	evB, err := m.Publish(store.SessionEvent{SessionID: "s1", Type: EvMessage, Data: "B"})
	if err != nil {
		t.Fatal(err)
	}
	// Ephemeral deltas (seq 0) are never persisted; they must always pass.
	m.publishEphemeral(store.SessionEvent{SessionID: "s1", Type: EvMessageDelta, Data: "d"})

	var got []store.SessionEvent
	timeout := time.After(time.Second)
loop:
	for {
		select {
		case ev := <-ch:
			got = append(got, ev)
		case <-timeout:
			break loop
		}
	}

	seen := map[int64]int{}
	deltas := 0
	for _, ev := range got {
		if ev.Seq == 0 {
			deltas++
			continue
		}
		seen[ev.Seq]++
	}
	if seen[evA.Seq] != 1 {
		t.Fatalf("evA (seq %d) delivered %d times, want 1 (race duplicate not dropped); got=%+v", evA.Seq, seen[evA.Seq], got)
	}
	if seen[evB.Seq] != 1 {
		t.Fatalf("evB (seq %d) delivered %d times, want 1", evB.Seq, seen[evB.Seq])
	}
	if deltas != 1 {
		t.Fatalf("ephemeral delta delivered %d times, want 1", deltas)
	}
	for seq, n := range seen {
		if n != 1 {
			t.Fatalf("persisted seq %d delivered %d times, want 1", seq, n)
		}
	}
}

// Subscribing concurrently with a stream of publishes exercises the replay/live
// boundary under the race detector: every persisted event must arrive exactly
// once regardless of whether it landed in the replay snapshot or the live feed.
func TestSubscribe_ConcurrentReconnectNoLossNoDup(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", TransportStructured); err != nil {
		t.Fatal(err)
	}
	const n = 200

	publisherDone := make(chan struct{})
	go func() {
		defer close(publisherDone)
		for i := 0; i < n; i++ {
			_, _ = m.Publish(store.SessionEvent{SessionID: "s1", Type: EvMessage, Data: fmt.Sprintf("m%d", i)})
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, cleanup, err := m.Subscribe(ctx, "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	seen := map[int64]bool{}
	count := 0
	deadline := time.After(10 * time.Second)
	for count < n {
		select {
		case ev := <-ch:
			if ev.Type != EvMessage {
				continue
			}
			if seen[ev.Seq] {
				t.Fatalf("duplicate persisted seq %d delivered", ev.Seq)
			}
			seen[ev.Seq] = true
			count++
		case <-deadline:
			t.Fatalf("received only %d/%d message events (event loss)", count, n)
		}
	}
	<-publisherDone
}

// AC: "Malformed/unknown protocol lines are logged and skipped without tearing
// down the session." A malformed claude line is logged and dropped; the read
// loop survives and translates the next valid line.
func TestClaudeConn_LogsAndSkipsMalformedLine(t *testing.T) {
	stdoutR, stdoutW := io.Pipe()
	out := newLineCapture()
	coll := &eventCollector{}
	warns := &warnRecorder{}
	conn := newClaudeConn(structuredSink{sessionID: "s1", emit: coll.emit, ephemeral: coll.ephemeral, warn: warns.warn}, out)
	go conn.run(stdoutR)
	t.Cleanup(func() { _ = stdoutW.Close() })

	if _, err := io.WriteString(stdoutW, "this is not json\n"); err != nil {
		t.Fatal(err)
	}
	valid := `{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}}` + "\n"
	if _, err := io.WriteString(stdoutW, valid); err != nil {
		t.Fatal(err)
	}

	msg := coll.waitForType(t, EvMessage, time.Second)
	var mm Message
	if err := json.Unmarshal([]byte(msg.ev.Data), &mm); err != nil || mm.Text != "ok" {
		t.Fatalf("valid line after malformed one not translated: %v %q", err, msg.ev.Data)
	}
	if !warns.contains("malformed") {
		t.Fatalf("malformed line not logged; warnings=%v", warns.all())
	}
}

// The codex read loop logs and skips a malformed line, then keeps translating.
func TestCodexConn_LogsAndSkipsMalformedLine(t *testing.T) {
	stdoutR, stdoutW := io.Pipe()
	out := newLineCapture()
	coll := &eventCollector{}
	warns := &warnRecorder{}
	conn := newCodexConn(structuredSink{sessionID: "s1", emit: coll.emit, ephemeral: coll.ephemeral, warn: warns.warn}, out)
	go conn.run(stdoutR)
	t.Cleanup(func() { _ = stdoutW.Close() })

	if _, err := io.WriteString(stdoutW, "}{ not json\n"); err != nil {
		t.Fatal(err)
	}
	valid := `{"method":"item/completed","params":{"item":{"type":"agentMessage","id":"m1","text":"hello"},"threadId":"th","turnId":"tn"}}` + "\n"
	if _, err := io.WriteString(stdoutW, valid); err != nil {
		t.Fatal(err)
	}

	msg := coll.waitForType(t, EvMessage, time.Second)
	var mm Message
	if err := json.Unmarshal([]byte(msg.ev.Data), &mm); err != nil || mm.Text != "hello" {
		t.Fatalf("valid line after malformed one not translated: %v %q", err, msg.ev.Data)
	}
	if !warns.contains("malformed") {
		t.Fatalf("malformed line not logged; warnings=%v", warns.all())
	}
}

// An unknown server->client request is logged and declined with a JSON-RPC
// error so the app-server is never left waiting, and the session is not torn
// down.
func TestCodexConn_DeclinesAndLogsUnknownServerRequest(t *testing.T) {
	stdoutR, stdoutW := io.Pipe()
	out := newLineCapture()
	coll := &eventCollector{}
	warns := &warnRecorder{}
	conn := newCodexConn(structuredSink{sessionID: "s1", emit: coll.emit, ephemeral: coll.ephemeral, warn: warns.warn}, out)
	go conn.run(stdoutR)
	t.Cleanup(func() { _ = stdoutW.Close() })

	if _, err := io.WriteString(stdoutW, `{"id":7,"method":"some/unknownRequest","params":{}}`+"\n"); err != nil {
		t.Fatal(err)
	}

	frame := out.read(t)
	if got, ok := frame["id"].(float64); !ok || got != 7 {
		t.Fatalf("declined response id = %v, want 7", frame["id"])
	}
	errObj, ok := frame["error"].(map[string]any)
	if !ok {
		t.Fatalf("declined response has no error object: %v", frame)
	}
	if code, _ := errObj["code"].(float64); code != -32601 {
		t.Fatalf("declined response code = %v, want -32601", errObj["code"])
	}
	if !warns.contains("unsupported server request") {
		t.Fatalf("unknown request not logged; warnings=%v", warns.all())
	}
}

// AC: "child crash marks the session ended and surfaces an error event." onExit
// (the cmd.Wait goroutine) publishes a fatal error and drops the proc so Alive
// reports the child gone; the reaper then ends the row.
func TestClaudeRuntime_ChildCrashEmitsFatalError(t *testing.T) {
	r := NewClaudeStructuredRuntime("", "", nil)
	coll := &eventCollector{}
	proc := &claudeProc{conn: newClaudeConn(structuredSink{sessionID: "s1", emit: coll.emit}, io.Discard), cancel: func() {}}
	r.mu.Lock()
	r.procs["s1"] = proc
	r.mu.Unlock()

	if !r.Alive(context.Background(), "s1") {
		t.Fatal("expected session alive before exit")
	}
	r.onExit("s1", proc)
	if r.Alive(context.Background(), "s1") {
		t.Fatal("expected session not alive after crash")
	}
	ev := coll.waitForType(t, EvError, time.Second)
	var ee ErrorEvent
	if err := json.Unmarshal([]byte(ev.ev.Data), &ee); err != nil || !ee.Fatal {
		t.Fatalf("crash error event = %v %q (want fatal)", err, ev.ev.Data)
	}
}

// A deliberate Stop must not be reported as a crash error.
func TestClaudeRuntime_CleanStopSuppressesCrashError(t *testing.T) {
	r := NewClaudeStructuredRuntime("", "", nil)
	coll := &eventCollector{}
	proc := &claudeProc{conn: newClaudeConn(structuredSink{sessionID: "s1", emit: coll.emit}, io.Discard), cancel: func() {}}
	proc.stopping.Store(true)
	r.mu.Lock()
	r.procs["s1"] = proc
	r.mu.Unlock()

	r.onExit("s1", proc)
	if errs := coll.byType(EvError); len(errs) != 0 {
		t.Fatalf("clean stop emitted %d error events, want 0", len(errs))
	}
}

func TestCodexRuntime_ChildCrashEmitsFatalError(t *testing.T) {
	r := NewCodexStructuredRuntime("", "", nil)
	coll := &eventCollector{}
	proc := &codexProc{conn: newCodexConn(structuredSink{sessionID: "s1", emit: coll.emit}, io.Discard), cancel: func() {}}
	r.mu.Lock()
	r.procs["s1"] = proc
	r.mu.Unlock()

	if !r.Alive(context.Background(), "s1") {
		t.Fatal("expected session alive before exit")
	}
	r.onExit("s1", proc)
	if r.Alive(context.Background(), "s1") {
		t.Fatal("expected session not alive after crash")
	}
	ev := coll.waitForType(t, EvError, time.Second)
	var ee ErrorEvent
	if err := json.Unmarshal([]byte(ev.ev.Data), &ee); err != nil || !ee.Fatal {
		t.Fatalf("crash error event = %v %q (want fatal)", err, ev.ev.Data)
	}
}

// The reaper marks an active session whose runtime child has disappeared as
// ended and persists a lifecycle "dead" event subscribers can observe.
func TestReapOnce_MarksDeadStructuredSessionEnded(t *testing.T) {
	m, rt := newTestManager(t)
	sess, err := m.Start(context.Background(), "p1", "claude", "manual", TransportStructured)
	if err != nil {
		t.Fatal(err)
	}
	rt.dead = true // the child is gone

	m.reapOnce(context.Background())

	got, err := m.Store.GetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EndedAt == nil {
		t.Fatal("expected dead session to be marked ended")
	}
	evs, _ := m.Store.SessionEventsAfter(sess.ID, 0)
	sawDead := false
	for _, ev := range evs {
		if ev.Type == "lifecycle" && ev.Data == "dead" {
			sawDead = true
		}
	}
	if !sawDead {
		t.Fatalf("expected a lifecycle dead event, got %+v", evs)
	}
}
