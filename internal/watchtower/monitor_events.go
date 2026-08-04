package watchtower

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// MonitorEvent is one Phase 2 local-monitor state transition (issue #78),
// mirroring the wire event fields in the monitor-events/batch contract.
// Only firing/resolved transitions are ever emitted -- a transient
// pending->healthy bounce never reaches here.
type MonitorEvent struct {
	// MonitorID is the relay's monitor id when known to the agent, else "":
	// the relay resolves the row by (agentId's server, kind, target).
	EventID        string
	MonitorID      string
	MonitorKind    string
	Target         string
	FromState      string
	ToState        string
	Severity       string
	FirstFailureAt time.Time
	OccurredAt     time.Time
	Summary        string
	Attributes     map[string]string
}

// NewMonitorEventID mints the stable id persisted with a queued transition.
// The same id is reused across envelope retries, allowing relay idempotency.
func NewMonitorEventID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "mevt_" + hex.EncodeToString(raw[:]), nil
}

// monitorEventWire is the exact JSON shape one event takes inside the
// monitor_events payload -- times as RFC3339 strings, matching the wire
// contract byte-for-byte.
type monitorEventWire struct {
	EventID        string            `json:"eventId"`
	MonitorID      string            `json:"monitorId"`
	MonitorKind    string            `json:"monitorKind"`
	Target         string            `json:"target"`
	FromState      string            `json:"fromState"`
	ToState        string            `json:"toState"`
	Severity       string            `json:"severity"`
	FirstFailureAt string            `json:"firstFailureAt"`
	OccurredAt     string            `json:"occurredAt"`
	Summary        string            `json:"summary"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

func toMonitorEventWire(e MonitorEvent) monitorEventWire {
	return monitorEventWire{
		EventID:        e.EventID,
		MonitorID:      e.MonitorID,
		MonitorKind:    e.MonitorKind,
		Target:         e.Target,
		FromState:      e.FromState,
		ToState:        e.ToState,
		Severity:       e.Severity,
		FirstFailureAt: e.FirstFailureAt.UTC().Format(time.RFC3339),
		OccurredAt:     e.OccurredAt.UTC().Format(time.RFC3339),
		Summary:        e.Summary,
		Attributes:     e.Attributes,
	}
}

func fromMonitorEventWire(w monitorEventWire) (MonitorEvent, error) {
	firstFailureAt, err := time.Parse(time.RFC3339, w.FirstFailureAt)
	if err != nil && w.FirstFailureAt != "" {
		return MonitorEvent{}, fmt.Errorf("watchtower: parse firstFailureAt: %w", err)
	}
	occurredAt, err := time.Parse(time.RFC3339, w.OccurredAt)
	if err != nil && w.OccurredAt != "" {
		return MonitorEvent{}, fmt.Errorf("watchtower: parse occurredAt: %w", err)
	}
	return MonitorEvent{
		MonitorID:      w.MonitorID,
		EventID:        w.EventID,
		MonitorKind:    w.MonitorKind,
		Target:         w.Target,
		FromState:      w.FromState,
		ToState:        w.ToState,
		Severity:       w.Severity,
		FirstFailureAt: firstFailureAt,
		OccurredAt:     occurredAt,
		Summary:        w.Summary,
		Attributes:     w.Attributes,
	}, nil
}

type monitorEventsPayload struct {
	Kind   string             `json:"kind"`
	Events []monitorEventWire `json:"events"`
}

// SendMonitorEvents builds and signs one event envelope carrying a
// {kind:"monitor_events"} payload and POSTs it to
// relayURL/v1/monitor-events/batch. As with Heartbeat, the sequence number
// is incremented and persisted to the credential file BEFORE the request is
// sent so a crash mid-request never reuses a sequence number the relay may
// already have processed. A nil/empty events slice is a no-op. Returns
// ErrNotEnrolled if Enroll has not succeeded yet.
func (c *Client) SendMonitorEvents(ctx context.Context, events []MonitorEvent) error {
	if len(events) == 0 {
		return nil
	}
	c.mu.Lock()
	if c.creds == nil {
		c.mu.Unlock()
		return ErrNotEnrolled
	}
	next := *c.creds
	next.Seq++
	if err := saveCreds(c.DataDir, &next); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("watchtower: persist sequence: %w", err)
	}
	c.creds = &next
	creds := next
	c.mu.Unlock()

	wire := make([]monitorEventWire, len(events))
	for i, e := range events {
		wire[i] = toMonitorEventWire(e)
	}
	payload := monitorEventsPayload{Kind: "monitor_events", Events: wire}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	timestamp := c.now().UTC().Format(time.RFC3339)
	payloadHash := PayloadHash(payloadBytes)
	signingString := SigningString(creds.AgentID, creds.ServerID, creds.Seq, timestamp, nonce, payloadHash)
	sig, err := Sign(creds.Secret, signingString)
	if err != nil {
		return err
	}
	env := envelope{
		AgentID:        creds.AgentID,
		ServerID:       creds.ServerID,
		SequenceNumber: creds.Seq,
		Timestamp:      timestamp,
		Nonce:          nonce,
		PayloadHash:    payloadHash,
		Payload:        json.RawMessage(payloadBytes),
		Signature:      sig,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, creds.RelayURL+"/v1/monitor-events/batch", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("watchtower: monitor-events: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("watchtower: monitor-events: relay returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// QueueFileName is the offline monitor-event queue's basename inside the
// agent's data dir.
const QueueFileName = "watchtower.queue"

// QueuePath returns the full path to the offline monitor-event queue file
// for dataDir.
func QueuePath(dataDir string) string {
	return dataDir + string(os.PathSeparator) + QueueFileName
}

func loadMonitorQueue(dataDir string) ([]MonitorEvent, error) {
	path := QueuePath(dataDir)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	var wire []monitorEventWire
	if err := json.Unmarshal(b, &wire); err != nil {
		return nil, fmt.Errorf("watchtower: parse %s: %w", path, err)
	}
	out := make([]MonitorEvent, len(wire))
	for i, w := range wire {
		ev, err := fromMonitorEventWire(w)
		if err != nil {
			return nil, err
		}
		out[i] = ev
	}
	return out, nil
}

// saveMonitorQueue writes events to QueuePath(dataDir) as 0600, exactly
// mirroring saveCreds's belt-and-suspenders chmod. A nil/empty slice writes
// an empty JSON array, clearing the queue without deleting the file.
func saveMonitorQueue(dataDir string, events []MonitorEvent) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	if events == nil {
		events = []MonitorEvent{}
	}
	wire := make([]monitorEventWire, len(events))
	for i, e := range events {
		wire[i] = toMonitorEventWire(e)
	}
	b, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	path := QueuePath(dataDir)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// EnqueueMonitorEvent durably persists ev to the offline queue file ahead of
// any send attempt, so a crash between enqueue and flush never loses the
// event: the next FlushQueue call (this process or a restarted one) picks it
// up from disk.
func (c *Client) EnqueueMonitorEvent(ev MonitorEvent) error {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()
	events, err := loadMonitorQueue(c.DataDir)
	if err != nil {
		return err
	}
	events = append(events, ev)
	if _, err := ensureMonitorEventIDs(events); err != nil {
		return err
	}
	return saveMonitorQueue(c.DataDir, events)
}

func ensureMonitorEventIDs(events []MonitorEvent) (bool, error) {
	changed := false
	for i := range events {
		if events[i].EventID != "" {
			continue
		}
		id, err := NewMonitorEventID()
		if err != nil {
			return false, err
		}
		events[i].EventID = id
		changed = true
	}
	return changed, nil
}

func monitorEventKey(e MonitorEvent) string { return e.MonitorKind + ":" + e.Target }

// condenseMonitorEvents keeps at most the latest firing/resolved pair for
// each monitor. A single pending->resolved net event is not sufficient: the
// relay would see no firing transition and therefore never create the
// incident. Keeping the pair reconstructs the incident while bounding a
// long offline flap history to two events per monitor. Original cross-monitor
// ordering and the episode's earliest firstFailureAt are preserved.
func condenseMonitorEvents(events []MonitorEvent) []MonitorEvent {
	type history struct {
		firingIndex   int
		resolvedIndex int
		earliest      time.Time
	}
	histories := make(map[string]history)
	for i, event := range events {
		key := monitorEventKey(event)
		h, ok := histories[key]
		if !ok {
			h.firingIndex = -1
			h.resolvedIndex = -1
		}
		switch event.ToState {
		case "firing":
			// A later firing starts a new episode; older offline flaps are
			// intentionally discarded.
			h.firingIndex = i
			h.resolvedIndex = -1
			h.earliest = event.FirstFailureAt
		case "resolved":
			h.resolvedIndex = i
			if h.earliest.IsZero() || (!event.FirstFailureAt.IsZero() && event.FirstFailureAt.Before(h.earliest)) {
				h.earliest = event.FirstFailureAt
			}
		default:
			if h.earliest.IsZero() || (!event.FirstFailureAt.IsZero() && event.FirstFailureAt.Before(h.earliest)) {
				h.earliest = event.FirstFailureAt
			}
		}
		histories[key] = h
	}

	selected := make(map[int]MonitorEvent, len(histories)*2)
	for _, h := range histories {
		if h.firingIndex >= 0 {
			event := events[h.firingIndex]
			event.FirstFailureAt = h.earliest
			selected[h.firingIndex] = event
		}
		if h.resolvedIndex >= 0 {
			event := events[h.resolvedIndex]
			event.FirstFailureAt = h.earliest
			selected[h.resolvedIndex] = event
		}
	}
	out := make([]MonitorEvent, 0, len(selected))
	for i := range events {
		if event, ok := selected[i]; ok {
			out = append(out, event)
		}
	}
	return out
}

// FlushQueue condenses the queued monitor events and sends them as one
// batch. On success, exactly the events present at the start of the flush
// are cleared -- any event enqueued concurrently while the send was in
// flight survives for the next flush. On failure the queue is left
// untouched so nothing is lost.
func (c *Client) FlushQueue(ctx context.Context) error {
	c.queueMu.Lock()
	events, err := loadMonitorQueue(c.DataDir)
	if err != nil {
		c.queueMu.Unlock()
		return err
	}
	n := len(events)
	if n == 0 {
		c.queueMu.Unlock()
		return nil
	}
	if changed, err := ensureMonitorEventIDs(events); err != nil {
		c.queueMu.Unlock()
		return err
	} else if changed {
		// Persist migration before sending. A lost response must retry with
		// the same IDs rather than recreate incidents.
		if err := saveMonitorQueue(c.DataDir, events); err != nil {
			c.queueMu.Unlock()
			return err
		}
	}
	condensed := condenseMonitorEvents(events)
	c.queueMu.Unlock()

	if err := c.SendMonitorEvents(ctx, condensed); err != nil {
		return err
	}

	c.queueMu.Lock()
	defer c.queueMu.Unlock()
	remaining, err := loadMonitorQueue(c.DataDir)
	if err != nil {
		return err
	}
	if len(remaining) <= n {
		remaining = nil
	} else {
		remaining = remaining[n:]
	}
	return saveMonitorQueue(c.DataDir, remaining)
}

// MonitorDef is the agent-facing view of one relay-configured monitor,
// decoded from the monitor DTO returned by SyncMonitors.
type MonitorDef struct {
	ID                 string
	ServerID           string
	Kind               string
	Target             string
	Enabled            bool
	Severity           string
	EvaluationLocation string
	FailureThreshold   int
	RecoveryThreshold  int
	CooldownSeconds    int
	FiringThreshold    float64
	RecoveryValue      float64
	Params             map[string]string
}

type monitorSyncPayload struct {
	Kind string `json:"kind"`
}

type monitorDefWire struct {
	ID                 string            `json:"id"`
	ServerID           string            `json:"serverId"`
	Kind               string            `json:"kind"`
	Target             string            `json:"target"`
	Enabled            bool              `json:"enabled"`
	Severity           string            `json:"severity"`
	EvaluationLocation string            `json:"evaluationLocation"`
	FailureThreshold   int               `json:"failureThreshold"`
	RecoveryThreshold  int               `json:"recoveryThreshold"`
	CooldownSeconds    int               `json:"cooldownSeconds"`
	FiringThreshold    float64           `json:"firingThreshold"`
	RecoveryValue      float64           `json:"recoveryValue"`
	Params             map[string]string `json:"params,omitempty"`
}

type monitorSyncResponse struct {
	Monitors []monitorDefWire `json:"monitors"`
}

// SyncMonitors POSTs a signed {kind:"monitor_sync"} envelope to
// relayURL/v1/agents/monitors/sync and returns the server's monitors as
// agent-facing DTOs. Like Heartbeat and SendMonitorEvents, the sequence
// number is incremented and persisted before the request is sent. Returns
// ErrNotEnrolled if Enroll has not succeeded yet.
func (c *Client) SyncMonitors(ctx context.Context) ([]MonitorDef, error) {
	c.mu.Lock()
	if c.creds == nil {
		c.mu.Unlock()
		return nil, ErrNotEnrolled
	}
	next := *c.creds
	next.Seq++
	if err := saveCreds(c.DataDir, &next); err != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("watchtower: persist sequence: %w", err)
	}
	c.creds = &next
	creds := next
	c.mu.Unlock()

	payloadBytes, err := json.Marshal(monitorSyncPayload{Kind: "monitor_sync"})
	if err != nil {
		return nil, err
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	timestamp := c.now().UTC().Format(time.RFC3339)
	payloadHash := PayloadHash(payloadBytes)
	signingString := SigningString(creds.AgentID, creds.ServerID, creds.Seq, timestamp, nonce, payloadHash)
	sig, err := Sign(creds.Secret, signingString)
	if err != nil {
		return nil, err
	}
	env := envelope{
		AgentID:        creds.AgentID,
		ServerID:       creds.ServerID,
		SequenceNumber: creds.Seq,
		Timestamp:      timestamp,
		Nonce:          nonce,
		PayloadHash:    payloadHash,
		Payload:        json.RawMessage(payloadBytes),
		Signature:      sig,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, creds.RelayURL+"/v1/agents/monitors/sync", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("watchtower: monitors/sync: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("watchtower: monitors/sync: relay returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out monitorSyncResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("watchtower: monitors/sync: decode response: %w", err)
	}
	defs := make([]MonitorDef, len(out.Monitors))
	for i, w := range out.Monitors {
		defs[i] = MonitorDef{
			ID:                 w.ID,
			ServerID:           w.ServerID,
			Kind:               w.Kind,
			Target:             w.Target,
			Enabled:            w.Enabled,
			Severity:           w.Severity,
			EvaluationLocation: w.EvaluationLocation,
			FailureThreshold:   w.FailureThreshold,
			RecoveryThreshold:  w.RecoveryThreshold,
			CooldownSeconds:    w.CooldownSeconds,
			FiringThreshold:    w.FiringThreshold,
			RecoveryValue:      w.RecoveryValue,
			Params:             w.Params,
		}
	}
	return defs, nil
}
