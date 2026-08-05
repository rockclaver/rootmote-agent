package watchtower

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/store"
)

// relayForbiddenKeys mirrors watchtower/internal/server/remediation.go's
// remediationForbiddenKeys exactly (that package lives in the relay's
// separate Go module, so it cannot be imported here) -- any of these keys
// appearing anywhere in a posted remediation-event body would smuggle
// unredacted command/output/credential/token material past the relay
// boundary.
var relayForbiddenKeys = []string{
	"command", "commands", "stdout", "stderr", "output", "script",
	"credential", "credentials", "secret", "password", "privatekey",
	"confirmationtoken", "token",
}

// collectKeysLower walks an arbitrary decoded JSON value and returns every
// object key seen at any depth, lowercased, so the forbidden-key check
// cannot be defeated by casing.
func collectKeysLower(v any, out map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			out[strings.ToLower(k)] = true
			collectKeysLower(vv, out)
		}
	case []any:
		for _, vv := range t {
			collectKeysLower(vv, out)
		}
	}
}

func assertNoForbiddenKeys(t *testing.T, body []byte) {
	t.Helper()
	var generic any
	if err := json.Unmarshal(body, &generic); err != nil {
		t.Fatalf("decode body as generic JSON: %v", err)
	}
	keys := map[string]bool{}
	collectKeysLower(generic, keys)
	for _, forbidden := range relayForbiddenKeys {
		if keys[forbidden] {
			t.Fatalf("forbidden key %q present in posted remediation event body: %s", forbidden, body)
		}
	}
}

func TestSendRemediationEvent_PostsSignedEnvelopeToIncidentPath(t *testing.T) {
	var gotPaths []string
	var gotBodies [][]byte
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		gotBodies = append(gotBodies, body)
		w.WriteHeader(http.StatusOK)
	}))
	defer relay.Close()

	dir := t.TempDir()
	fixedNow := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	c := &Client{DataDir: dir, AgentVersion: "1.0.0", HTTP: relay.Client(), Now: func() time.Time { return fixedNow }}
	if err := saveCreds(dir, &Creds{RelayURL: relay.URL, AgentID: "agt_rem", ServerID: "srv_rem", Secret: "abcdef00", Seq: 3}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)

	ev1 := RemediationEvent{
		EventID: "ex-1#1", Kind: "execution_failed", Actor: "agent",
		Detail: "step 0 failed", ExecutionID: "ex-1", RunbookID: "rb-1",
		ContentHash: "hash1",
	}
	if err := c.SendRemediationEvent(context.Background(), "inc_01", ev1); err != nil {
		t.Fatalf("SendRemediationEvent #1: %v", err)
	}
	if got := c.Creds().Seq; got != 4 {
		t.Fatalf("seq after first send = %d, want 4", got)
	}

	ev2 := RemediationEvent{
		EventID: "ex-1#2", Kind: "internal_verification_passed", Actor: "agent",
		ExecutionID: "ex-1", RunbookID: "rb-1", ContentHash: "hash1",
	}
	if err := c.SendRemediationEvent(context.Background(), "inc_01", ev2); err != nil {
		t.Fatalf("SendRemediationEvent #2: %v", err)
	}
	if got := c.Creds().Seq; got != 5 {
		t.Fatalf("seq after second send = %d, want 5 (incremented again)", got)
	}

	if len(gotPaths) != 2 {
		t.Fatalf("relay received %d requests, want 2", len(gotPaths))
	}
	for i, p := range gotPaths {
		if !strings.Contains(p, "/inc_01/") || !strings.HasSuffix(p, "/remediation-events") {
			t.Fatalf("request %d path = %q, want to contain incident id and end in /remediation-events", i, p)
		}
	}

	// Sequence numbers must differ across the two envelopes -- the second
	// send must not reuse the first's.
	var env1, env2 envelope
	if err := json.Unmarshal(gotBodies[0], &env1); err != nil {
		t.Fatalf("decode envelope 1: %v", err)
	}
	if err := json.Unmarshal(gotBodies[1], &env2); err != nil {
		t.Fatalf("decode envelope 2: %v", err)
	}
	if env1.SequenceNumber != 4 || env2.SequenceNumber != 5 {
		t.Fatalf("envelope sequence numbers = %d, %d, want 4, 5", env1.SequenceNumber, env2.SequenceNumber)
	}

	var payload1 remediationEventPayload
	if err := json.Unmarshal(env1.Payload, &payload1); err != nil {
		t.Fatalf("decode payload 1: %v", err)
	}
	if payload1.Kind != "remediation_event" {
		t.Fatalf("payload.Kind = %q, want remediation_event", payload1.Kind)
	}
	if payload1.IncidentID != "inc_01" {
		t.Fatalf("payload.IncidentID = %q, want inc_01", payload1.IncidentID)
	}
	if payload1.Event.Kind != "execution_failed" || payload1.Event.Detail != "step 0 failed" {
		t.Fatalf("payload.Event = %+v, want it to mirror the posted event", payload1.Event)
	}

	// The full posted bytes -- envelope, payload, and event alike -- must
	// never carry a forbidden key.
	assertNoForbiddenKeys(t, gotBodies[0])
	assertNoForbiddenKeys(t, gotBodies[1])

	// Verify the signature and payload hash the exact way the relay's
	// verifier would, on both envelopes.
	seen := map[string]bool{}
	if err := referenceVerify("abcdef00", "agt_rem", "srv_rem", gotBodies[0], fixedNow, 5*time.Minute, seen); err != nil {
		t.Fatalf("valid envelope 1 rejected by reference verifier: %v", err)
	}
	if err := referenceVerify("abcdef00", "agt_rem", "srv_rem", gotBodies[1], fixedNow, 5*time.Minute, seen); err != nil {
		t.Fatalf("valid envelope 2 rejected by reference verifier: %v", err)
	}
}

func TestSendRemediationEvent_RequiresEnrollment(t *testing.T) {
	dir := t.TempDir()
	c := &Client{DataDir: dir, AgentVersion: "1.0.0", HTTP: &captureDoer{}}
	err := c.SendRemediationEvent(context.Background(), "inc_01", RemediationEvent{EventID: "ex-1#1", Kind: "execution_failed"})
	if err != ErrNotEnrolled {
		t.Fatalf("SendRemediationEvent before enrollment = %v, want ErrNotEnrolled", err)
	}
}

func TestSendRemediationEvent_RelayErrorReturnsError(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer relay.Close()

	dir := t.TempDir()
	c := &Client{DataDir: dir, AgentVersion: "1.0.0", HTTP: relay.Client(), Now: time.Now}
	if err := saveCreds(dir, &Creds{RelayURL: relay.URL, AgentID: "agt", ServerID: "srv", Secret: "abcdef00", Seq: 0}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)

	err := c.SendRemediationEvent(context.Background(), "inc_01", RemediationEvent{EventID: "ex-1#1", Kind: "execution_failed"})
	if err == nil {
		t.Fatal("SendRemediationEvent against a 500 relay = nil error, want non-nil")
	}
	// Must not panic reaching here, and the sequence must still have been
	// persisted (incremented before the request, per the crash-safety
	// contract) even though the send itself failed.
	if got := c.Creds().Seq; got != 1 {
		t.Fatalf("seq after failed send = %d, want 1 (still incremented before the request)", got)
	}
}

func newTestStoreWithExecution(t *testing.T, execID, incidentID, runbookID, runbookHash string) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.CreateRunbook(store.Runbook{ID: runbookID, IncidentID: incidentID, ContentHash: runbookHash, Content: "{}"}); err != nil {
		t.Fatalf("seed runbook: %v", err)
	}
	if _, _, err := s.CreateExecution(store.RemediationExecution{
		ID: execID, IncidentID: incidentID, RunbookID: runbookID, RunbookHash: runbookHash,
		Status: store.RemediationVerifying, Kind: store.RemediationKindExecute,
	}); err != nil {
		t.Fatalf("seed execution: %v", err)
	}
	return s
}

func TestRemediationProjector_Project_NilClientIsNoop(t *testing.T) {
	p := RemediationProjector{}
	err := p.Project(context.Background(), store.RemediationEvent{ExecutionID: "ex-1", Seq: 1, Type: "internal_verification", Data: `{"passed":true}`, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("Project with nil Client = %v, want nil", err)
	}
}

func TestRemediationProjector_Project_UnenrolledClientIsNoop(t *testing.T) {
	dir := t.TempDir()
	c := &Client{DataDir: dir, AgentVersion: "1.0.0", HTTP: &captureDoer{}}
	p := RemediationProjector{Client: c}
	err := p.Project(context.Background(), store.RemediationEvent{ExecutionID: "ex-1", Seq: 1, Type: "internal_verification", Data: `{"passed":true}`, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("Project with unenrolled Client = %v, want nil", err)
	}
}

func TestRemediationProjector_Project_UnmappedKindIsNoop(t *testing.T) {
	dir := t.TempDir()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("relay should never be called for an unmapped event kind, got request to %s", r.URL.Path)
	}))
	defer relay.Close()
	c := &Client{DataDir: dir, AgentVersion: "1.0.0", HTTP: relay.Client(), Now: time.Now}
	if err := saveCreds(dir, &Creds{RelayURL: relay.URL, AgentID: "agt", ServerID: "srv", Secret: "abcdef00", Seq: 0}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)

	s := newTestStoreWithExecution(t, "ex-1", "inc_01", "rb-1", "hash1")
	var logged []string
	p := RemediationProjector{Client: c, Store: s, Logf: func(format string, args ...any) { logged = append(logged, format) }}

	err := p.Project(context.Background(), store.RemediationEvent{ExecutionID: "ex-1", Seq: 1, Type: "step_result", Data: `{"output":"secret stuff","exit_code":0}`, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("Project(step_result) = %v, want nil", err)
	}
	if len(logged) == 0 {
		t.Fatal("Project(step_result) logged nothing, want a debug notice for the skipped kind")
	}
}

func TestRemediationProjector_Project_MapsAndPostsEvent(t *testing.T) {
	var gotPath string
	var gotBody []byte
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer relay.Close()

	dir := t.TempDir()
	c := &Client{DataDir: dir, AgentVersion: "1.0.0", HTTP: relay.Client(), Now: time.Now}
	if err := saveCreds(dir, &Creds{RelayURL: relay.URL, AgentID: "agt", ServerID: "srv", Secret: "abcdef00", Seq: 0}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)

	s := newTestStoreWithExecution(t, "ex-1", "inc_01", "rb-1", "hash1")
	p := RemediationProjector{Client: c, Store: s}

	occurredAt := time.Date(2026, 8, 5, 12, 30, 0, 0, time.UTC)
	err := p.Project(context.Background(), store.RemediationEvent{
		ExecutionID: "ex-1", Seq: 7, Type: "internal_verification",
		Data: `{"passed":false,"detail":"service still crashing","error":"probe timeout"}`, CreatedAt: occurredAt,
	})
	if err != nil {
		t.Fatalf("Project(internal_verification) = %v", err)
	}
	if !strings.Contains(gotPath, "/inc_01/") {
		t.Fatalf("relay request path = %q, want it scoped to inc_01 (resolved from the execution's store row)", gotPath)
	}

	var env envelope
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	var payload remediationEventPayload
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Event.Kind != relayKindInternalVerificationFail {
		t.Fatalf("payload.Event.Kind = %q, want %q", payload.Event.Kind, relayKindInternalVerificationFail)
	}
	if payload.Event.RunbookID != "rb-1" || payload.Event.ContentHash != "hash1" {
		t.Fatalf("payload.Event = %+v, want RunbookID/ContentHash resolved from the store's execution row", payload.Event)
	}
	if payload.Event.EventID == "" {
		t.Fatal("payload.Event.EventID is empty, want a stable id derived from executionId+seq")
	}
	assertNoForbiddenKeys(t, gotBody)
}
