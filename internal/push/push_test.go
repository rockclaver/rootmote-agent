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

	"github.com/rockclaver/rootmote-agent/internal/notifications"
	"github.com/rockclaver/rootmote-agent/internal/store"
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
	tok, err := Register(context.Background(), "https://notify.example.com/", "test-host", "", hc)
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

func TestRegister_SendsEnrollSecret(t *testing.T) {
	hc := &fakeHTTP{}
	hc.push(200, `{"token":"tok-xyz"}`)
	if _, err := Register(context.Background(), "https://notify.example.com/", "host", "enroll-secret", hc); err != nil {
		t.Fatal(err)
	}
	if got := hc.requests[0].Header.Get("Authorization"); got != "Bearer enroll-secret" {
		t.Fatalf("Authorization = %q, want Bearer enroll-secret", got)
	}
}

func TestRegister_OmitsAuthWhenNoSecret(t *testing.T) {
	hc := &fakeHTTP{}
	hc.push(200, `{"token":"t"}`)
	if _, err := Register(context.Background(), "https://notify.example.com/", "host", "", hc); err != nil {
		t.Fatal(err)
	}
	if got := hc.requests[0].Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty", got)
	}
}

func TestRegister_RejectsErrorStatus(t *testing.T) {
	hc := &fakeHTTP{}
	hc.push(500, `boom`)
	if _, err := Register(context.Background(), "https://notify.example.com", "", "", hc); err == nil {
		t.Fatal("expected error")
	}
}

func TestRegister_RejectsEmptyToken(t *testing.T) {
	hc := &fakeHTTP{}
	hc.push(200, `{}`)
	if _, err := Register(context.Background(), "https://notify.example.com", "", "", hc); err == nil {
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

func TestHub_ForwardRoutesByPolicyAndPrunesUnregistered(t *testing.T) {
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
	hub := &Hub{Sender: sender, Store: st}

	// A kind that defaults closed (session_finished): ignored.
	hub.Forward(context.Background(), notifications.Notification{Type: "session_finished"})
	if len(sender.sent) != 0 {
		t.Fatalf("closed-by-default kind forwarded: %+v", sender.sent)
	}

	// infra.runbook defaults open: fan-out + prune.
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

// TestHub_ForwardAlertFireVsClear reproduces the specific noise fix: a fired
// alert pushes, its "recovered" clear does not, by default.
func TestHub_ForwardAlertFireVsClear(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.PutPushDevice(store.PushDevice{Token: "d1"}); err != nil {
		t.Fatal(err)
	}
	sender := &stubSender{}
	hub := &Hub{Sender: sender, Store: st}

	hub.Forward(context.Background(), notifications.Notification{
		Type: "infra.alert", Title: "fired", Data: map[string]any{"clear": false},
	})
	hub.Forward(context.Background(), notifications.Notification{
		Type: "infra.alert", Title: "cleared", Data: map[string]any{"clear": true},
	})
	if len(sender.sent) != 1 || sender.sent[0].Title != "fired" {
		t.Fatalf("want only the fired edge pushed, got: %+v", sender.sent)
	}
}

// TestHub_ForwardActionCompletedPushes covers the explicit requirement that
// action.completed always pushes -- success or failure, the operator is
// actively waiting on it.
func TestHub_ForwardActionCompletedPushes(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.PutPushDevice(store.PushDevice{Token: "d1"}); err != nil {
		t.Fatal(err)
	}
	sender := &stubSender{}
	hub := &Hub{Sender: sender, Store: st}

	hub.Forward(context.Background(), notifications.Notification{
		Type: "action.completed", Title: "Action succeeded",
		Data: map[string]any{"status": "succeeded"},
	})
	hub.Forward(context.Background(), notifications.Notification{
		Type: "action.completed", Title: "Action failed",
		Data: map[string]any{"status": "failed"},
	})
	if len(sender.sent) != 2 {
		t.Fatalf("action.completed should always push regardless of outcome, got: %+v", sender.sent)
	}
}

// TestHub_ForwardOverrideWinsOverDefault covers both directions of a
// persisted notification_prefs override: forcing a normally-silent kind on,
// and forcing a normally-loud one off.
func TestHub_ForwardOverrideWinsOverDefault(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.PutPushDevice(store.PushDevice{Token: "d1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutNotificationPref(store.NotificationPref{Type: "infra.alert.cleared", PushEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutNotificationPref(store.NotificationPref{Type: "infra.alert.fired", PushEnabled: false}); err != nil {
		t.Fatal(err)
	}
	sender := &stubSender{}
	hub := &Hub{Sender: sender, Store: st}

	hub.Forward(context.Background(), notifications.Notification{
		Type: "infra.alert", Title: "fired", Data: map[string]any{"clear": false},
	})
	hub.Forward(context.Background(), notifications.Notification{
		Type: "infra.alert", Title: "cleared", Data: map[string]any{"clear": true},
	})
	if len(sender.sent) != 1 || sender.sent[0].Title != "cleared" {
		t.Fatalf("overrides did not flip eligibility as configured: %+v", sender.sent)
	}
}

// TestHub_ForwardStampsPerDeviceServerID covers the deep-link routing fix:
// each device gets ITS OWN client-side server id in the payload, not the
// agent's internal rule-bucket id, and devices that never sent one are left
// with whatever the notification producer already put there.
func TestHub_ForwardStampsPerDeviceServerID(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.PutPushDevice(store.PushDevice{Token: "d1", ClientServerID: "client-abc"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPushDevice(store.PushDevice{Token: "d2"}); err != nil {
		t.Fatal(err)
	}
	sender := &stubSender{}
	hub := &Hub{Sender: sender, Store: st}

	hub.Forward(context.Background(), notifications.Notification{
		Type: "infra.runbook", Title: "T",
		Data: map[string]any{"server_id": "local"},
	})
	if len(sender.sent) != 2 {
		t.Fatalf("sent=%d want 2", len(sender.sent))
	}
	byToken := map[string]Message{}
	for _, m := range sender.sent {
		byToken[m.Token] = m
	}
	if byToken["d1"].Data["server_id"] != "client-abc" {
		t.Fatalf("d1 should get its own client_server_id, got: %+v", byToken["d1"].Data)
	}
	if byToken["d2"].Data["server_id"] != "local" {
		t.Fatalf("d2 (no client_server_id) should keep the producer's value, got: %+v", byToken["d2"].Data)
	}
}

func TestHub_ForwardPrefixesLabelOnTitleAndData(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.PutPushDevice(store.PushDevice{Token: "d1", Platform: "ios"}); err != nil {
		t.Fatal(err)
	}

	sender := &stubSender{}
	hub := &Hub{
		Sender: sender,
		Store:  st,
		Label:  "vps-1",
	}

	hub.Forward(context.Background(), notifications.Notification{
		ID: "n1", Type: "infra.alert", Title: "Infrastructure alert",
		Body: "sshd.service entered failed state",
	})
	if len(sender.sent) != 1 {
		t.Fatalf("sent=%d want 1", len(sender.sent))
	}
	got := sender.sent[0]
	if got.Title != "vps-1: Infrastructure alert" {
		t.Fatalf("title not labelled: %q", got.Title)
	}
	if got.Body != "sshd.service entered failed state" {
		t.Fatalf("body altered: %q", got.Body)
	}
	if got.Data["server_label"] != "vps-1" {
		t.Fatalf("data missing server_label: %+v", got.Data)
	}

	// No Label configured: title passes through unmodified and no
	// server_label key is added.
	sender.sent = nil
	hub.Label = ""
	hub.Forward(context.Background(), notifications.Notification{
		ID: "n2", Type: "infra.alert", Title: "Infrastructure alert", Body: "x",
	})
	if len(sender.sent) != 1 || sender.sent[0].Title != "Infrastructure alert" {
		t.Fatalf("unlabelled forward mutated title: %+v", sender.sent)
	}
	if _, ok := sender.sent[0].Data["server_label"]; ok {
		t.Fatalf("unlabelled forward set server_label: %+v", sender.sent[0].Data)
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
	hub := &Hub{Sender: sender, Store: st}
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
