package push

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rockclaver/claver-agent/internal/notifications"
	"github.com/rockclaver/claver-agent/internal/store"
)

// fakeHTTP records requests and replies with a script of canned responses.
type fakeHTTP struct {
	mu        sync.Mutex
	requests  []*http.Request
	reqBody   []string
	script    []*http.Response
	scriptErr []error
	i         int
}

func (f *fakeHTTP) Do(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body := ""
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}
	f.requests = append(f.requests, r)
	f.reqBody = append(f.reqBody, body)
	if f.i >= len(f.script) {
		return nil, errors.New("fakeHTTP: no more scripted responses")
	}
	resp, err := f.script[f.i], f.scriptErr[f.i]
	f.i++
	return resp, err
}

func (f *fakeHTTP) push(status int, body string) {
	f.script = append(f.script, &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	})
	f.scriptErr = append(f.scriptErr, nil)
}

func TestRegister_ReturnsToken(t *testing.T) {
	hc := &fakeHTTP{}
	hc.push(200, `{"token":"tok-123"}`)
	tok, err := Register(context.Background(), "https://notify.example.com/", "test-host", hc)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-123" {
		t.Fatalf("token = %q, want tok-123", tok)
	}
	if hc.requests[0].URL.String() != "https://notify.example.com/v1/register" {
		t.Fatalf("register URL = %s", hc.requests[0].URL)
	}
	var body map[string]string
	_ = json.Unmarshal([]byte(hc.reqBody[0]), &body)
	if body["label"] != "test-host" {
		t.Fatalf("label missing from register body: %s", hc.reqBody[0])
	}
}

func TestRegister_RejectsErrorStatus(t *testing.T) {
	hc := &fakeHTTP{}
	hc.push(500, `boom`)
	if _, err := Register(context.Background(), "https://notify.example.com", "", hc); err == nil {
		t.Fatal("expected error")
	}
}

func TestRegister_RejectsEmptyToken(t *testing.T) {
	hc := &fakeHTTP{}
	hc.push(200, `{}`)
	if _, err := Register(context.Background(), "https://notify.example.com", "", hc); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestRelayClient_SendPostsAuthenticatedRequest(t *testing.T) {
	hc := &fakeHTTP{}
	hc.push(200, `{"results":[{"token":"device-1","ok":true}]}`)
	c := NewRelayClient("https://notify.example.com", "tok-123", hc)

	err := c.Send(context.Background(), Message{
		Token: "device-1", Title: "AI runbook", Body: "restart x",
		Data: map[string]string{"runbook_id": "rb1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hc.requests) != 1 {
		t.Fatalf("requests=%d, want 1", len(hc.requests))
	}
	req := hc.requests[0]
	if req.URL.String() != "https://notify.example.com/v1/notify" {
		t.Fatalf("URL = %s", req.URL)
	}
	if req.Header.Get("Authorization") != "Bearer tok-123" {
		t.Fatalf("missing bearer token: %s", req.Header.Get("Authorization"))
	}
	if !strings.Contains(hc.reqBody[0], `"runbook_id":"rb1"`) {
		t.Fatalf("data payload missing: %s", hc.reqBody[0])
	}
}

func TestRelayClient_Send_RejectsEmptyToken(t *testing.T) {
	c := NewRelayClient("https://notify.example.com", "tok-123", &fakeHTTP{})
	if err := c.Send(context.Background(), Message{}); err == nil {
		t.Fatal("expected error for empty device token")
	}
}

func TestRelayClient_Send_MapsUnregisteredResult(t *testing.T) {
	hc := &fakeHTTP{}
	hc.push(200, `{"results":[{"token":"dead","ok":false,"unregistered":true,"error":"gone"}]}`)
	c := NewRelayClient("https://notify.example.com", "tok-123", hc)
	err := c.Send(context.Background(), Message{Token: "dead"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsUnregistered(err) {
		t.Fatalf("expected unregistered error, got %v", err)
	}
}

func TestRelayClient_Send_HTTPErrorStatus(t *testing.T) {
	hc := &fakeHTTP{}
	hc.push(401, `unauthorized`)
	c := NewRelayClient("https://notify.example.com", "bad-token", hc)
	err := c.Send(context.Background(), Message{Token: "d"})
	if err == nil {
		t.Fatal("expected error")
	}
	if IsUnregistered(err) {
		t.Fatal("401 must not be treated as unregistered")
	}
}

func TestIsUnregistered_RequiresRelayError(t *testing.T) {
	if IsUnregistered(errors.New("plain error")) {
		t.Fatal("non-RelayError must not be unregistered")
	}
	if IsUnregistered(&RelayError{Unregistered: false}) {
		t.Fatal("Unregistered=false must report false")
	}
}

// stubSender records every Send and lets the test trigger errors.
type stubSender struct {
	mu     sync.Mutex
	sent   []Message
	errFor map[string]error
}

func (s *stubSender) Send(_ context.Context, m Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, m)
	if e := s.errFor[m.Token]; e != nil {
		return e
	}
	return nil
}

func TestHub_ForwardSelectedTypesAndPrunesUnregistered(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	for _, tok := range []string{"good-1", "good-2", "dead-3"} {
		if err := st.PutPushDevice(store.PushDevice{Token: tok, Platform: "ios"}); err != nil {
			t.Fatal(err)
		}
	}

	sender := &stubSender{errFor: map[string]error{
		"dead-3": &RelayError{Unregistered: true, Message: "gone"},
	}}
	hub := &Hub{
		Sender: sender,
		Store:  st,
		Types:  map[string]bool{"infra.runbook": true},
	}

	// Wrong type: ignored.
	hub.Forward(context.Background(), notifications.Notification{Type: "infra.alert"})
	if len(sender.sent) != 0 {
		t.Fatalf("non-selected type forwarded: %+v", sender.sent)
	}

	// Selected type: fan-out + prune.
	hub.Forward(context.Background(), notifications.Notification{
		ID: "n1", Type: "infra.runbook", Title: "AI runbook", Body: "x",
		Data: map[string]any{"runbook_id": "rb1", "step_count": 3},
	})
	if len(sender.sent) != 3 {
		t.Fatalf("sent=%d want 3", len(sender.sent))
	}
	for _, m := range sender.sent {
		if m.Data["runbook_id"] != "rb1" {
			t.Fatalf("data missing runbook_id: %+v", m.Data)
		}
		if m.Data["step_count"] != "3" {
			t.Fatalf("nested int not JSON-encoded: %+v", m.Data)
		}
		if m.Data["type"] != "infra.runbook" || m.Data["notif_id"] != "n1" {
			t.Fatalf("envelope keys missing: %+v", m.Data)
		}
	}

	devs, _ := st.ListPushDevices()
	if len(devs) != 2 {
		t.Fatalf("dead token not pruned: %+v", devs)
	}
	for _, d := range devs {
		if d.Token == "dead-3" {
			t.Fatal("dead-3 should be gone")
		}
	}
}

func TestHub_SubscribeBridgesNotificationHub(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.PutPushDevice(store.PushDevice{Token: "d1"})

	sender := &stubSender{}
	hub := &Hub{Sender: sender, Store: st, Types: map[string]bool{"infra.runbook": true}}
	nh := notifications.NewHub()
	cleanup := hub.Subscribe(context.Background(), nh)
	defer cleanup()

	_ = nh.Publish(context.Background(), notifications.Notification{
		Type: "infra.runbook", Title: "T", Body: "B",
	})
	if len(sender.sent) != 1 || sender.sent[0].Title != "T" {
		t.Fatalf("subscribe bridge missed message: %+v", sender.sent)
	}
}
