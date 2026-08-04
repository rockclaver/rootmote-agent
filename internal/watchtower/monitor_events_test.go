package watchtower

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// erroringThenOKDoer fails every request until failUntil calls have been
// made, then answers 200 ok and records the sent envelope's raw payload.
type erroringThenOKDoer struct {
	failUntil   int
	calls       int
	sentPayload []byte
}

func (d *erroringThenOKDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	if d.calls <= d.failUntil {
		return nil, errors.New("erroringThenOKDoer: simulated relay unreachable")
	}
	if req.Body != nil {
		b := make([]byte, 0)
		buf := make([]byte, 4096)
		for {
			n, err := req.Body.Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				break
			}
		}
		var env envelope
		if jsonErr := json.Unmarshal(b, &env); jsonErr == nil {
			d.sentPayload = env.Payload
		}
	}
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	_, _ = rec.WriteString(`{"ok":true}`)
	return rec.Result(), nil
}

// --- AC8: offline queue survives doer errors and preserves firstFailureAt --

func TestEnqueueFlush_SurvivesDoerErrorsPreservesFirstFailureAt(t *testing.T) {
	dir := t.TempDir()
	fixedNow := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	doer := &erroringThenOKDoer{failUntil: 2}
	c := &Client{DataDir: dir, AgentVersion: "1.2.3", HTTP: doer, Now: func() time.Time { return fixedNow }}
	if err := saveCreds(dir, &Creds{RelayURL: "http://relay.example", AgentID: "agt_1", ServerID: "srv_1", Secret: "abcdef00", Seq: 0}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)

	firstFailure := fixedNow.Add(-10 * time.Minute)
	earlierFirstFailure := firstFailure.Add(-1 * time.Minute)
	// A firing/resolved pair for one monitor is bounded to two events on
	// flush so the relay can reconstruct the incident and its recovery.
	events := []MonitorEvent{
		{EventID: "mevt_fire", MonitorKind: "disk_capacity", Target: "/", FromState: "pending", ToState: "firing", Severity: "critical", FirstFailureAt: firstFailure, OccurredAt: fixedNow.Add(-9 * time.Minute), Summary: "disk / at 92%"},
		{EventID: "mevt_resolve", MonitorKind: "disk_capacity", Target: "/", FromState: "recovering", ToState: "resolved", Severity: "critical", FirstFailureAt: earlierFirstFailure, OccurredAt: fixedNow, Summary: "disk / recovered"},
	}
	for _, ev := range events {
		if err := c.EnqueueMonitorEvent(ev); err != nil {
			t.Fatalf("EnqueueMonitorEvent: %v", err)
		}
	}

	// Flush attempts 1 and 2 fail (doer errors); the queue must survive
	// untouched, including the earliest firstFailureAt.
	if err := c.FlushQueue(context.Background()); err == nil {
		t.Fatal("FlushQueue: expected error on attempt 1, got nil")
	}
	if err := c.FlushQueue(context.Background()); err == nil {
		t.Fatal("FlushQueue: expected error on attempt 2, got nil")
	}
	queued, err := loadMonitorQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 2 {
		t.Fatalf("queue length after 2 failed flushes = %d, want 2 (untouched)", len(queued))
	}
	if !queued[0].FirstFailureAt.Equal(firstFailure) {
		t.Fatalf("queued[0].FirstFailureAt = %v, want %v (must survive failed flush attempts)", queued[0].FirstFailureAt, firstFailure)
	}

	// Attempt 3 succeeds: the queue is condensed to the firing/resolved pair
	// with the earliest firstFailureAt preserved, then cleared on success.
	if err := c.FlushQueue(context.Background()); err != nil {
		t.Fatalf("FlushQueue: expected success on attempt 3, got %v", err)
	}
	if doer.sentPayload == nil {
		t.Fatal("FlushQueue: no request sent on successful attempt")
	}
	var sent monitorEventsPayload
	if err := json.Unmarshal(doer.sentPayload, &sent); err != nil {
		t.Fatalf("decode sent payload: %v", err)
	}
	if len(sent.Events) != 2 || sent.Events[0].EventID != "mevt_fire" || sent.Events[1].EventID != "mevt_resolve" {
		t.Fatalf("condensed batch = %+v, want stable-id firing + resolved", sent.Events)
	}
	if sent.Events[0].FromState != "pending" || sent.Events[0].ToState != "firing" {
		t.Fatalf("first transition = %s->%s, want pending->firing", sent.Events[0].FromState, sent.Events[0].ToState)
	}
	if sent.Events[1].FromState != "recovering" || sent.Events[1].ToState != "resolved" {
		t.Fatalf("second transition = %s->%s, want recovering->resolved", sent.Events[1].FromState, sent.Events[1].ToState)
	}
	wantEarliest := earlierFirstFailure.UTC().Format(time.RFC3339)
	for i, event := range sent.Events {
		if event.FirstFailureAt != wantEarliest {
			t.Fatalf("event[%d] firstFailureAt = %s, want %s", i, event.FirstFailureAt, wantEarliest)
		}
	}

	remaining, err := loadMonitorQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("queue after successful flush = %d events, want 0 (cleared)", len(remaining))
	}
}

// reconnectDoer fails the first heartbeat, accepts the next one, then
// signals when Run automatically flushes the queued monitor batch.
type reconnectDoer struct {
	heartbeats int
	flushed    chan struct{}
}

func (d *reconnectDoer) Do(req *http.Request) (*http.Response, error) {
	switch req.URL.Path {
	case "/v1/agents/heartbeat":
		d.heartbeats++
		if d.heartbeats == 1 {
			return nil, errors.New("relay offline")
		}
	case "/v1/monitor-events/batch":
		select {
		case <-d.flushed:
		default:
			close(d.flushed)
		}
	}
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	_, _ = rec.WriteString(`{"ok":true}`)
	return rec.Result(), nil
}

func TestRun_FlushesOfflineQueueAfterHeartbeatReconnect(t *testing.T) {
	dir := t.TempDir()
	doer := &reconnectDoer{flushed: make(chan struct{})}
	c := &Client{DataDir: dir, AgentVersion: "1.0.0", HTTP: doer}
	if err := saveCreds(dir, &Creds{
		RelayURL: "http://relay.example", AgentID: "agt_r", ServerID: "srv_r", Secret: "abcdef00",
	}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)
	if err := c.EnqueueMonitorEvent(MonitorEvent{
		MonitorKind: "disk_capacity", Target: "/", FromState: "pending", ToState: "firing",
		FirstFailureAt: time.Now().Add(-time.Minute), OccurredAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, time.Millisecond)

	select {
	case <-doer.flushed:
	case <-time.After(time.Second):
		t.Fatal("queued monitor event was not flushed after heartbeat reconnected")
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		queued, err := loadMonitorQueue(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(queued) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue still contains %d events after successful reconnect flush", len(queued))
		}
		time.Sleep(time.Millisecond)
	}
}

// --- AC8: SendMonitorEvents builds a correctly-signed envelope ------------

func TestSendMonitorEvents_BuildsCorrectlySignedEnvelope(t *testing.T) {
	dir := t.TempDir()
	fixedNow := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	doer := &captureDoer{}
	c := &Client{DataDir: dir, AgentVersion: "9.9.9", HTTP: doer, Now: func() time.Time { return fixedNow }}
	if err := saveCreds(dir, &Creds{RelayURL: "http://relay.example", AgentID: "agt_v", ServerID: "srv_v", Secret: "abcdef00", Seq: 5}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)
	ev := MonitorEvent{
		EventID: "mevt_123", MonitorKind: "docker_container", Target: "web",
		FromState: "pending", ToState: "firing",
		Severity: "critical", FirstFailureAt: fixedNow.Add(-time.Minute), OccurredAt: fixedNow,
		Summary: "web is exited", Attributes: map[string]string{"state": "exited"},
	}
	if err := c.SendMonitorEvents(context.Background(), []MonitorEvent{ev}); err != nil {
		t.Fatalf("SendMonitorEvents: %v", err)
	}
	if got := c.Creds().Seq; got != 6 {
		t.Fatalf("seq after send = %d, want 6 (incremented once)", got)
	}

	var env envelope
	if err := json.Unmarshal(doer.lastBody, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.AgentID != "agt_v" || env.ServerID != "srv_v" || env.SequenceNumber != 6 {
		t.Fatalf("envelope identity = %+v, want agt_v/srv_v/6", env)
	}
	var payload monitorEventsPayload
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Kind != "monitor_events" {
		t.Fatalf("payload.Kind = %q, want monitor_events", payload.Kind)
	}
	if len(payload.Events) != 1 || payload.Events[0].EventID != "mevt_123" ||
		payload.Events[0].MonitorKind != "docker_container" || payload.Events[0].Target != "web" {
		t.Fatalf("payload.Events = %+v, want stable-id docker_container/web event", payload.Events)
	}

	wantHash := PayloadHash(env.Payload)
	if env.PayloadHash != wantHash {
		t.Fatalf("payloadHash = %s, want sha256(payload) = %s", env.PayloadHash, wantHash)
	}
	wantSigningString := SigningString(env.AgentID, env.ServerID, env.SequenceNumber, env.Timestamp, env.Nonce, env.PayloadHash)
	wantSig, err := Sign("abcdef00", wantSigningString)
	if err != nil {
		t.Fatal(err)
	}
	if env.Signature != wantSig {
		t.Fatalf("signature mismatch: got %s want %s (Sign/SigningString recompute)", env.Signature, wantSig)
	}
}

// --- condenseMonitorEvents unit coverage ----------------------------------

func TestCondenseMonitorEvents_KeepsBoundedIncidentHistory(t *testing.T) {
	t0 := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	events := []MonitorEvent{
		{MonitorKind: "systemd_unit", Target: "nginx.service", FromState: "pending", ToState: "firing", FirstFailureAt: t0.Add(2 * time.Minute)},
		{MonitorKind: "systemd_unit", Target: "nginx.service", FromState: "recovering", ToState: "resolved", FirstFailureAt: t0.Add(1 * time.Minute)},
		{MonitorKind: "disk_capacity", Target: "/", FromState: "pending", ToState: "firing", FirstFailureAt: t0},
	}
	out := condenseMonitorEvents(events)
	if len(out) != 3 {
		t.Fatalf("condensed length = %d, want firing/resolved plus disk firing", len(out))
	}
	if out[0].FromState != "pending" || out[0].ToState != "firing" ||
		out[1].FromState != "recovering" || out[1].ToState != "resolved" {
		t.Fatalf("systemd history = %+v, %+v; want firing then resolved", out[0], out[1])
	}
	for i := 0; i < 2; i++ {
		if !out[i].FirstFailureAt.Equal(t0.Add(time.Minute)) {
			t.Fatalf("systemd event[%d] FirstFailureAt = %v, want earliest %v", i, out[i].FirstFailureAt, t0.Add(time.Minute))
		}
	}
	if out[2].MonitorKind != "disk_capacity" || out[2].ToState != "firing" {
		t.Fatalf("last event = %+v, want disk_capacity firing", out[2])
	}
}
