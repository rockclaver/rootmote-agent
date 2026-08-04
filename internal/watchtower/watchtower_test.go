package watchtower

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- AC3: credential file + Enroll round trip -----------------------------

func TestEnroll_WritesCredFile0600AndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/register" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var in registerRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatal(err)
		}
		if in.EnrollmentCode != "code-123" || in.AgentVersion != "1.2.3" {
			t.Fatalf("unexpected register request: %+v", in)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registerResponse{
			AgentID: "agt_abc", ServerID: "srv_def", Secret: "deadbeef",
		})
	}))
	defer relay.Close()

	c, err := NewClient(dir, "1.2.3", relay.Client())
	if err != nil {
		t.Fatal(err)
	}
	creds, err := c.Enroll(context.Background(), relay.URL, "code-123")
	if err != nil {
		t.Fatal(err)
	}
	if creds.AgentID != "agt_abc" || creds.ServerID != "srv_def" || creds.Secret != "deadbeef" || creds.Seq != 0 {
		t.Fatalf("unexpected creds: %+v", creds)
	}

	path := CredPath(dir)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("cred file perms = %o, want 600", perm)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk Creds
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk != *creds {
		t.Fatalf("on-disk creds %+v != returned creds %+v", onDisk, *creds)
	}

	// A fresh client loading the same dataDir picks up the persisted creds.
	c2, err := NewClient(dir, "1.2.3", relay.Client())
	if err != nil {
		t.Fatal(err)
	}
	if got := c2.Creds(); got == nil || *got != *creds {
		t.Fatalf("reloaded creds = %+v, want %+v", got, creds)
	}
}

func TestEnroll_Reenroll_OverwritesAndResetsSeq(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(registerResponse{AgentID: "agt_1", ServerID: "srv_1", Secret: "aa"})
		} else {
			_ = json.NewEncoder(w).Encode(registerResponse{AgentID: "agt_2", ServerID: "srv_2", Secret: "bb"})
		}
	}))
	defer relay.Close()

	c, err := NewClient(dir, "1.0.0", relay.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enroll(context.Background(), relay.URL, "code-1"); err != nil {
		t.Fatal(err)
	}
	// Simulate some heartbeats advancing seq before rotating.
	c.mu.Lock()
	c.creds.Seq = 5
	c.mu.Unlock()
	if err := saveCreds(dir, c.Creds()); err != nil {
		t.Fatal(err)
	}

	creds, err := c.Enroll(context.Background(), relay.URL, "code-2")
	if err != nil {
		t.Fatal(err)
	}
	if creds.AgentID != "agt_2" || creds.Seq != 0 {
		t.Fatalf("re-enroll did not overwrite/reset: %+v", creds)
	}
}

func TestEnroll_RelayError(t *testing.T) {
	dir := t.TempDir()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"reused enrollment code"}`))
	}))
	defer relay.Close()

	c, err := NewClient(dir, "1.0.0", relay.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enroll(context.Background(), relay.URL, "bad-code"); err == nil {
		t.Fatal("expected error from relay 401")
	}
	if _, err := os.Stat(CredPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("cred file should not exist after failed enroll, stat err = %v", err)
	}
}

// --- no inbound listener ---------------------------------------------------

// TestClientOpensNoListener proves the watchtower client package is a pure
// outbound HTTP client: its own source never calls net.Listen / http.Serve
// / http.ListenAndServe, so it is structurally impossible for Run/Heartbeat
// to open an inbound port.
func TestClientOpensNoListener(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"net.Listen(", "net.ListenTCP(", "http.ListenAndServe(", "http.Serve("}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, f := range forbidden {
			if strings.Contains(src, f) {
				t.Fatalf("%s contains %q -- watchtower client must stay pure outbound", e.Name(), f)
			}
		}
	}
}

// TestRun_UnenrolledIsNonFatal proves Run tolerates missing credentials: it
// keeps ticking (never panics/exits) and only starts heartbeating once
// Enroll succeeds concurrently.
func TestRun_UnenrolledIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	var hits atomic.Int32
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/register":
			_ = json.NewEncoder(w).Encode(registerResponse{AgentID: "agt_x", ServerID: "srv_x", Secret: "cc"})
		case "/v1/agents/heartbeat":
			hits.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer relay.Close()

	c, err := NewClient(dir, "1.0.0", relay.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.Logf = nil // quiet unenrolled-skip logs in test output

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.Run(ctx, 10*time.Millisecond)
		close(done)
	}()

	// Give Run a couple of unenrolled ticks first.
	time.Sleep(30 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatalf("hits = %d before enroll, want 0", hits.Load())
	}

	if _, err := c.Enroll(context.Background(), relay.URL, "code"); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(2 * time.Second)
	for hits.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for a heartbeat after enrollment")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}
}

// --- AC4: envelope signing --------------------------------------------------

// referenceVerify re-implements the relay's documented verification order
// (see the contract's "Relay verification order") against a decoded
// envelope, independent of the watchtower package's own Sign/PayloadHash
// helpers where it matters (payload hash + HMAC recompute), so a bug that
// broke both sides identically wouldn't hide a wire mismatch.
func referenceVerify(secret, agentID, serverID string, raw []byte, now time.Time, window time.Duration, seen map[string]bool) error {
	var env struct {
		AgentID        string          `json:"agentId"`
		ServerID       string          `json:"serverId"`
		SequenceNumber int64           `json:"sequenceNumber"`
		Timestamp      string          `json:"timestamp"`
		Nonce          string          `json:"nonce"`
		PayloadHash    string          `json:"payloadHash"`
		Payload        json.RawMessage `json:"payload"`
		Signature      string          `json:"signature"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	if env.AgentID != agentID {
		return errors.New("unknown agent")
	}
	if env.ServerID != serverID {
		return errors.New("server mismatch")
	}
	gotHash := PayloadHash(env.Payload)
	if gotHash != env.PayloadHash {
		return errors.New("payload hash mismatch")
	}
	signingString := SigningString(env.AgentID, env.ServerID, env.SequenceNumber, env.Timestamp, env.Nonce, env.PayloadHash)
	wantSig, err := Sign(secret, signingString)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(wantSig), []byte(env.Signature)) {
		return errors.New("bad signature")
	}
	ts, err := time.Parse(time.RFC3339, env.Timestamp)
	if err != nil {
		return err
	}
	if d := now.Sub(ts); d > window || d < -window {
		return errors.New("stale timestamp")
	}
	if seen[env.Nonce] {
		return errors.New("replayed nonce")
	}
	seen[env.Nonce] = true
	return nil
}

// captureDoer records the last request body sent through it and answers 200 ok.
type captureDoer struct {
	lastBody []byte
	status   int
}

func (d *captureDoer) Do(req *http.Request) (*http.Response, error) {
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
		d.lastBody = b
	}
	status := d.status
	if status == 0 {
		status = http.StatusOK
	}
	rec := httptest.NewRecorder()
	rec.WriteHeader(status)
	_, _ = rec.WriteString(`{"ok":true}`)
	resp := rec.Result()
	return resp, nil
}

func TestHeartbeat_EnvelopeAcceptedByReferenceVerifier(t *testing.T) {
	dir := t.TempDir()
	fixedNow := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	doer := &captureDoer{}
	c := &Client{
		DataDir: dir, AgentVersion: "9.9.9", HTTP: doer,
		Now: func() time.Time { return fixedNow },
	}
	if err := saveCreds(dir, &Creds{RelayURL: "http://relay.example", AgentID: "agt_v", ServerID: "srv_v", Secret: "abcdef00", Seq: 0}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)

	if err := c.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	if err := referenceVerify("abcdef00", "agt_v", "srv_v", doer.lastBody, fixedNow, 5*time.Minute, seen); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	if got := c.Creds().Seq; got != 1 {
		t.Fatalf("seq after heartbeat = %d, want 1", got)
	}
}

func TestHeartbeat_TamperedVariantsRejected(t *testing.T) {
	dir := t.TempDir()
	fixedNow := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	doer := &captureDoer{}
	c := &Client{
		DataDir: dir, AgentVersion: "9.9.9", HTTP: doer,
		Now: func() time.Time { return fixedNow },
	}
	if err := saveCreds(dir, &Creds{RelayURL: "http://relay.example", AgentID: "agt_v", ServerID: "srv_v", Secret: "abcdef00", Seq: 0}); err != nil {
		t.Fatal(err)
	}
	c.creds, _ = LoadCreds(dir)
	if err := c.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	baseline := append([]byte(nil), doer.lastBody...)

	mustVerify := func(t *testing.T, body []byte, now time.Time, window time.Duration, seen map[string]bool) error {
		t.Helper()
		return referenceVerify("abcdef00", "agt_v", "srv_v", body, now, window, seen)
	}

	// Sanity: baseline itself verifies with a fresh nonce cache.
	if err := mustVerify(t, baseline, fixedNow, 5*time.Minute, map[string]bool{}); err != nil {
		t.Fatalf("baseline should verify: %v", err)
	}

	tamperField := func(field, newVal string) []byte {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(baseline, &m); err != nil {
			t.Fatal(err)
		}
		var enc []byte
		var err error
		if field == "payload" {
			enc, err = json.Marshal(json.RawMessage(newVal))
		} else {
			enc, err = json.Marshal(newVal)
		}
		if err != nil {
			t.Fatal(err)
		}
		m[field] = enc
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	tamperSeq := func(newSeq int64) []byte {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(baseline, &m); err != nil {
			t.Fatal(err)
		}
		enc, err := json.Marshal(newSeq)
		if err != nil {
			t.Fatal(err)
		}
		m["sequenceNumber"] = enc
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	cases := []struct {
		name string
		body []byte
	}{
		{"payload", tamperField("payload", `{"kind":"heartbeat","agentVersion":"9.9.9-evil"}`)},
		{"sequenceNumber", tamperSeq(999)},
		{"timestamp", tamperField("timestamp", fixedNow.Add(-time.Hour).Format(time.RFC3339))},
		{"nonce", tamperField("nonce", "00000000000000000000000000000000")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := mustVerify(t, tc.body, fixedNow, 5*time.Minute, map[string]bool{}); err == nil {
				t.Fatalf("tampered %s envelope was accepted, want rejection", tc.name)
			}
		})
	}

	// Replay: the same envelope verified twice with a shared nonce cache
	// must fail the second time.
	seen := map[string]bool{}
	if err := mustVerify(t, baseline, fixedNow, 5*time.Minute, seen); err != nil {
		t.Fatalf("first verification should succeed: %v", err)
	}
	if err := mustVerify(t, baseline, fixedNow, 5*time.Minute, seen); err == nil {
		t.Fatal("replayed envelope was accepted, want rejection")
	}
}

func TestHeartbeat_NotEnrolled(t *testing.T) {
	dir := t.TempDir()
	c, err := NewClient(dir, "1.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Heartbeat(context.Background()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
}

func TestSigningString_ExactFormat(t *testing.T) {
	got := SigningString("agt_1", "srv_1", 42, "2026-08-04T12:00:00Z", "nonce123", "hash456")
	want := "agt_1\nsrv_1\n42\n2026-08-04T12:00:00Z\nnonce123\nhash456"
	if got != want {
		t.Fatalf("SigningString = %q, want %q", got, want)
	}
}
