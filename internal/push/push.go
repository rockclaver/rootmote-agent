// Package push delivers agent-side notifications to registered mobile
// devices via a central claver-notify relay.
//
// Earlier versions of this package spoke to Firebase Cloud Messaging's HTTP
// v1 API directly, which meant every self-hosted agent had to provision its
// own Firebase project and service-account key. That per-install setup cost
// is gone: the relay (github.com/rockclaver/claver-notify) holds the one
// shared FCM service-account credential, and every agent authenticates to
// it with a lightweight bearer token obtained via Register.
//
// The package surfaces three things:
//   - Register: self-service enrollment against a relay deployment.
//   - RelayClient.Send: deliver one Message through the relay.
//   - Hub: subscribes to notifications.Hub, fans selected notification kinds
//     out to every device registered in the store.
package push

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rockclaver/claver-agent/internal/notifications"
	"github.com/rockclaver/claver-agent/internal/store"
)

// Message is the minimal message shape we hand to the relay. We include
// both title/body (so the OS draws the system banner / wakes the screen)
// AND a data payload (so the foreground client can deep-link without
// re-fetching the body). Apple and Android both deliver data to the app.
type Message struct {
	Token string            // FCM device token (required)
	Title string            // notification.title
	Body  string            // notification.body
	Data  map[string]string // arbitrary key/value pairs (deep_link, runbook_id, ...)
}

// HTTPDoer is satisfied by *http.Client and any test stub.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func defaultHTTPClient(c HTTPDoer) HTTPDoer {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Register calls a claver-notify deployment's self-service enrollment
// endpoint and returns a fresh bearer token for this installation. label is
// an optional human-readable hint (e.g. hostname) the relay stores alongside
// the token so an operator can identify it later; it need not be unique.
func Register(ctx context.Context, baseURL, label string, httpClient HTTPDoer) (string, error) {
	httpClient = defaultHTTPClient(httpClient)
	body, err := json.Marshal(map[string]string{"label": label})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(baseURL, "/")+"/v1/register", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("notify relay register: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("notify relay register: status=%d body=%s",
			resp.StatusCode, truncate(string(rb), 256))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", fmt.Errorf("notify relay register: parse response: %w", err)
	}
	if out.Token == "" {
		return "", errors.New("notify relay register: empty token")
	}
	return out.Token, nil
}

// RelayClient sends messages through a central claver-notify relay instead
// of talking to FCM directly. Construct with NewRelayClient. Safe for
// concurrent use (it is stateless beyond its HTTP client).
type RelayClient struct {
	// BaseURL is the claver-notify deployment, e.g. "https://notify.example.com".
	BaseURL string
	// Token authenticates this agent installation to the relay. Obtain one
	// via Register and persist it (see cmd/claver-agent).
	Token string
	HTTP  HTTPDoer
}

// NewRelayClient constructs a RelayClient. httpClient defaults sensibly.
func NewRelayClient(baseURL, token string, httpClient HTTPDoer) *RelayClient {
	return &RelayClient{BaseURL: baseURL, Token: token, HTTP: defaultHTTPClient(httpClient)}
}

type relayNotifyRequest struct {
	Messages []relayMessage `json:"messages"`
}

type relayMessage struct {
	Token string            `json:"token"`
	Title string            `json:"title"`
	Body  string            `json:"body"`
	Data  map[string]string `json:"data,omitempty"`
}

type relayNotifyResponse struct {
	Results []struct {
		Token        string `json:"token"`
		OK           bool   `json:"ok"`
		Unregistered bool   `json:"unregistered"`
		Error        string `json:"error"`
	} `json:"results"`
}

// Send delivers one message via the relay's /v1/notify endpoint. Returns a
// *RelayError the caller can inspect with IsUnregistered to prune dead
// tokens from the device registry.
func (c *RelayClient) Send(ctx context.Context, m Message) error {
	if m.Token == "" {
		return errors.New("push: empty device token")
	}
	reqBody, err := json.Marshal(relayNotifyRequest{Messages: []relayMessage{{
		Token: m.Token, Title: m.Title, Body: m.Body, Data: m.Data,
	}}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.BaseURL, "/")+"/v1/notify", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := defaultHTTPClient(c.HTTP).Do(req)
	if err != nil {
		return fmt.Errorf("notify relay: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return &RelayError{HTTPStatus: resp.StatusCode,
			Message: fmt.Sprintf("notify relay: status=%d body=%s", resp.StatusCode, truncate(string(rb), 256))}
	}
	var out relayNotifyResponse
	if err := json.Unmarshal(rb, &out); err != nil {
		return fmt.Errorf("notify relay: parse response: %w", err)
	}
	if len(out.Results) != 1 {
		return fmt.Errorf("notify relay: expected 1 result, got %d", len(out.Results))
	}
	if r := out.Results[0]; !r.OK {
		return &RelayError{Unregistered: r.Unregistered, Message: r.Error}
	}
	return nil
}

// RelayError wraps a per-message failure reported by the notify relay,
// whether that's a transport-level HTTP error or a per-token FCM rejection
// the relay normalized for us.
type RelayError struct {
	HTTPStatus   int
	Unregistered bool
	Message      string
}

func (e *RelayError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("notify relay: status=%d", e.HTTPStatus)
}

// IsUnregistered reports whether err indicates the device token is no longer
// valid (uninstalled / token rotated). The caller should drop the token.
func IsUnregistered(err error) bool {
	var re *RelayError
	return errors.As(err, &re) && re.Unregistered
}

// Sender is the narrow surface Hub needs. Decoupled so tests can stub.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Hub wires the agent's notifications.Hub to a Sender + the device registry
// in store. On every selected notification it queries the registry once and
// fans the message out to every device, pruning tokens the relay reports as
// unregistered.
//
// Selection is opt-in by notification Type: we only push high-signal events
// (alerts, runbooks) and not chatty things like session lifecycle ticks.
type Hub struct {
	Sender Sender
	Store  *store.Store
	// Types lists the notification types to forward. Empty -> no forwarding.
	Types map[string]bool
	// Logf, when non-nil, receives one-line operational messages (token
	// pruned, send error). Defaults to a no-op so tests stay quiet.
	Logf func(format string, args ...any)
}

// Forward pushes one notification to every registered device.
func (h *Hub) Forward(ctx context.Context, n notifications.Notification) {
	if h == nil || h.Sender == nil || h.Store == nil {
		return
	}
	if !h.Types[n.Type] {
		return
	}
	devices, err := h.Store.ListPushDevices()
	if err != nil {
		h.log("push: list devices: %v", err)
		return
	}
	data := flattenData(n)
	for _, d := range devices {
		err := h.Sender.Send(ctx, Message{
			Token: d.Token,
			Title: n.Title,
			Body:  n.Body,
			Data:  data,
		})
		if err == nil {
			continue
		}
		if IsUnregistered(err) {
			if delErr := h.Store.DeletePushDevice(d.Token); delErr != nil {
				h.log("push: prune token: %v", delErr)
			}
			continue
		}
		h.log("push: send %s...: %v", truncate(d.Token, 12), err)
	}
}

// Subscribe wires Forward onto the given notification hub. Returns a cleanup
// that unsubscribes. Returns nil cleanup when hub or h are nil.
func (h *Hub) Subscribe(ctx context.Context, nh *notifications.Hub) func() {
	if h == nil || nh == nil {
		return func() {}
	}
	return nh.Subscribe(func(n notifications.Notification) {
		h.Forward(ctx, n)
	})
}

func (h *Hub) log(format string, args ...any) {
	if h.Logf != nil {
		h.Logf(format, args...)
	}
}

// flattenData reshapes the notification's typed Data map into the FCM
// data-payload shape (string -> string). Nested values are JSON-encoded so
// the client can decode them back to structured payloads when it needs them
// (e.g. proposal_ids).
func flattenData(n notifications.Notification) map[string]string {
	out := map[string]string{
		"type":     n.Type,
		"notif_id": n.ID,
	}
	for k, v := range n.Data {
		switch s := v.(type) {
		case string:
			out[k] = s
		case nil:
			// drop
		default:
			b, err := json.Marshal(v)
			if err == nil {
				out[k] = string(b)
			}
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
