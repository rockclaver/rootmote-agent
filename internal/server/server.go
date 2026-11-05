// Package server implements the rootmote-agent control-plane WebSocket server.
//
// The server binds only to a loopback address. A startup self-check refuses
// non-loopback bind addresses outright — the only legitimate transport into
// the agent is an SSH-forwarded localhost connection from the mobile app.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/inventory"
	"github.com/rockclaver/rootmote-agent/internal/notifications"
	"github.com/rockclaver/rootmote-agent/internal/playbook"
	"github.com/rockclaver/rootmote-agent/internal/remediation"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/steps"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/version"
	"github.com/rockclaver/rootmote-agent/internal/watchtower"
	"github.com/rockclaver/rootmote-agent/internal/webserver"
)

// Frame is the JSON envelope used on the wire.
type Frame struct {
	ID      string          `json:"id"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// HealthPayload is the payload returned for server.health requests.
type HealthPayload struct {
	Version string `json:"version"`
	UptimeS int64  `json:"uptime_s"`
}

// Config configures the agent server.
type Config struct {
	// Addr is the bind address. Must be a loopback address.
	Addr string
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
	// Review, when non-nil, enables confirmation-token and audit kinds.
	Review *review.Manager
	// Docker, when non-nil, enables docker.* kinds.
	Docker *docker.Manager
	// Infra, when non-nil, enables infra.* host metrics kinds.
	Infra *infra.Manager
	// Systemd, when non-nil, enables infra.service.* kinds.
	Systemd *systemd.Manager
	// Webservers, when non-nil, enables infra.webserver.* host proxy kinds.
	Webservers *webserver.Manager
	// Monitor, when non-nil, enables monitor.silence and monitor.ack.
	Monitor MonitorControl
	// Notifications fans background task.notification events to connected clients.
	Notifications *notifications.Hub
	// Remediation, when non-nil, enables the incident.runbook.*,
	// incident.execution.subscribe, incident.verify, and incident.rollback
	// kinds -- the durable approve/execute/verify lifecycle for one
	// specific approved runbook (issue #74 Task 3).
	Remediation *remediation.Manager
	// Store holds incident bindings and remediation executions. With
	// Remediation it enables playbook building (incident.playbook.generate and
	// the automatic playbook when an incident opens).
	Store *store.Store
	// URLs is the list of addresses check.http may request; playbooks pick
	// their web address from it.
	URLs *URLAllowlist
	// Steps validates playbook steps against the live host before a playbook
	// is proposed.
	Steps *steps.Runner
	// Priv runs privilege-helper actions. Inventory discovery uses it for
	// the read-only pm2-list, certs-list and supervisor-status actions; nil
	// turns those parts into warnings.
	Priv steps.PrivCaller
	// Watchtower, when non-nil, enables watchtower.enable / watchtower.status
	// (Watchtower Phase 1 cloud spine tracer: enroll this agent against a
	// relay and report enrollment state). The client already exists
	// (constructed in cmd/rootmote-agent from the persisted cred file, if
	// any) whether or not the agent is enrolled yet -- enrollment happens
	// here, driven by the mobile app.
	Watchtower *watchtower.Client
	// DiagnoseRedactor, when non-nil, enables incident.diagnose /
	// incident.evidence (Watchtower Phase 5: bounded, redacted local
	// diagnosis, issue #73). A diagnose.Collector is built per request from
	// whichever of Docker/Systemd/Infra/Webservers below are configured --
	// any subset (including none) is nil-safe, exactly like
	// discoverHostInventory.
	DiagnoseRedactor *redact.Redactor
	// DiagnoseConfidenceThreshold overrides diagnose.DefaultConfidenceThreshold
	// when > 0.
	DiagnoseConfidenceThreshold float64
	// OnWatchtowerEnabled starts Phase 2 monitor evaluation/sync after a
	// successful first-time enrollment. It must be idempotent because both
	// boot-time resume and repeated enable calls may invoke it.
	OnWatchtowerEnabled func()
	// ControlPlaneKey is the pairing secret the mobile app must present as an
	// Authorization: Bearer header on the WebSocket upgrade. Generated and
	// persisted by the agent; fetched by the app over the operator-
	// authenticated SSH channel. Empty authorizes nothing when RequirePairing.
	ControlPlaneKey string
	// RequirePairing enforces the ControlPlaneKey check on every WebSocket
	// upgrade. Defaults on for production; disable only for local development.
	RequirePairing bool
}

// Server is the agent's control-plane server.
type Server struct {
	cfg     Config
	startAt time.Time
	// seen tracks request ids that have already been dispatched. It is shared
	// across WebSocket connections so a frame replayed on a fresh tunnel
	// (after the previous one dropped) still short-circuits instead of
	// re-executing the side-effect. Entries expire after replayWindow.
	seen *idSet

	// diagnoseMu guards diagnoseBundles: the last collected Bundle per
	// incident id in this process, so incident.evidence after
	// incident.diagnose returns the exact bundle the assessment was built
	// from instead of re-collecting (and potentially observing different
	// host state).
	diagnoseMu      sync.Mutex
	diagnoseBundles map[string]diagnose.Bundle

	// discovery caches one host discovery pass for a few seconds.
	discovery discoveryCache

	// playbooks builds and proposes a playbook per incident. Nil when the
	// agent has no remediation manager or store.
	playbooks *playbook.Service

	// lifeCtx is the outer context passed to Serve -- the agent process's
	// own lifecycle, cancelled on shutdown. incident.runbook.execute /
	// incident.rollback run their StepExecutor pass on this context (via
	// runRemediationExecute), never on the per-request context (which dies
	// the instant the requesting WebSocket disconnects) and never on
	// context.Background() (which would never observe shutdown).
	lifeCtx context.Context
}

// replayWindow bounds how long a request id remains in the dedupe cache.
// Long enough to cover a flaky tunnel + backoff retries, short enough that
// a real session id reuse (extremely unlikely) doesn't permanently block.
const replayWindow = 5 * time.Minute

// New constructs a Server. It does not bind any sockets.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{
		cfg:             cfg,
		startAt:         cfg.Now(),
		seen:            newIDSet(1024, replayWindow, cfg.Now),
		diagnoseBundles: make(map[string]diagnose.Bundle),
	}
	s.playbooks = s.newPlaybookService()
	return s
}

// ErrNonLoopbackBind is returned when the configured address is not loopback.
var ErrNonLoopbackBind = errors.New("agent refuses to bind to a non-loopback address")

// assertLoopback returns nil iff host resolves only to loopback addresses.
// Hostnames are rejected — only literal IPs are allowed.
func assertLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid addr %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: %q is not a literal IP", ErrNonLoopbackBind, host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%w: %q", ErrNonLoopbackBind, host)
	}
	return nil
}

// Listen binds the configured loopback address and returns the listener.
// It is separate from Serve so tests can inspect the resolved address.
func (s *Server) Listen() (net.Listener, error) {
	if err := assertLoopback(s.cfg.Addr); err != nil {
		return nil, err
	}
	return net.Listen("tcp", s.cfg.Addr)
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.lifeCtx = ctx
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)

	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	err := httpSrv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	// The control plane binds to loopback, but loopback is shared by every
	// local process on the host. Require the pairing key (fetched by the app
	// over the operator-authenticated SSH channel) before upgrading, so a
	// co-tenant, compromised co-hosted app, or AI session running as another
	// user cannot drive the agent just by opening a socket.
	if s.cfg.RequirePairing && !s.pairingAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Loopback only; no browser will reach this. Skip origin checks.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusInternalError, "internal")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	writeMu := newConnWriter(cancel)
	var unsubscribeNotifications func()
	if s.cfg.Notifications != nil {
		unsubscribeNotifications = s.cfg.Notifications.Subscribe(func(n notifications.Notification) {
			s.writeOK(ctx, c, writeMu, "", "task.notification", n)
		})
		defer unsubscribeNotifications()
	}
	go s.writerLoop(ctx, c, writeMu)
	// Request-id dedupe spans reconnects (the cache lives on Server, not this
	// connection). When the mobile transport replays a frame after a tunnel
	// drop on a new WebSocket, this branch still fires so side-effecting
	// kinds like incident.runbook.execute and incident.rollback don't execute twice.
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		var f Frame
		if err := json.Unmarshal(data, &f); err != nil {
			s.writeError(ctx, c, writeMu, "", "bad_frame", err.Error())
			continue
		}
		if f.ID != "" && s.seen.add(f.ID) {
			s.writeOK(ctx, c, writeMu, f.ID, f.Kind, map[string]any{"replay": true})
			continue
		}
		s.dispatch(ctx, c, writeMu, f)
	}
}

// pairingAuthorized reports whether the request carries the control-plane
// pairing key as a bearer token. The comparison is constant-time; an empty
// configured key never authorizes.
func (s *Server) pairingAuthorized(r *http.Request) bool {
	if s.cfg.ControlPlaneKey == "" {
		return false
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.ControlPlaneKey)) == 1
}

// connWriter serializes every outbound frame for one connection onto a single
// writer goroutine. The read loop and all streaming goroutines enqueue here
// instead of writing inline, so a slow client can never block the read loop —
// the condition that previously deadlocked the connection (read loop waiting on
// the write lock while the streamer waited on a client that had stopped
// reading). Delivery is in-order and lossless until the queue overflows, at
// which point the client is too far behind to be alive and we drop the
// connection; the mobile transport reconnects and replays from its last seq.
type connWriter struct {
	send   chan []byte
	cancel context.CancelFunc
	once   sync.Once
	done   chan struct{}
}

func newConnWriter(cancel context.CancelFunc) *connWriter {
	return &connWriter{
		send:   make(chan []byte, 1024),
		cancel: cancel,
		done:   make(chan struct{}),
	}
}

func (w *connWriter) enqueue(b []byte) {
	select {
	case w.send <- b:
	case <-w.done:
	default:
		w.shutdown()
	}
}

func (w *connWriter) shutdown() {
	w.once.Do(func() {
		close(w.done)
		w.cancel()
	})
}

func (s *Server) writerLoop(ctx context.Context, c *websocket.Conn, w *connWriter) {
	for {
		select {
		case b := <-w.send:
			if err := c.Write(ctx, websocket.MessageText, b); err != nil {
				w.shutdown()
				return
			}
		case <-w.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

// idSet tracks request ids that have already been dispatched. Entries expire
// after the configured TTL so the map cannot grow unbounded over an agent's
// lifetime; cap triggers oldest-first eviction if a burst of writes blows
// past the TTL before sweep.
type idSet struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	cap    int
	ttl    time.Duration
	now    func() time.Time
	lastGC time.Time
}

func newIDSet(cap int, ttl time.Duration, now func() time.Time) *idSet {
	if now == nil {
		now = time.Now
	}
	return &idSet{
		seen: make(map[string]time.Time, cap),
		cap:  cap,
		ttl:  ttl,
		now:  now,
	}
}

// add returns true iff id is already in the cache (within TTL). The id is
// inserted on the first call and refreshed on subsequent calls so an
// actively-retried request keeps its dedupe entry alive.
func (s *idSet) add(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.seen) >= s.cap || now.Sub(s.lastGC) > s.ttl {
		for k, t := range s.seen {
			if now.Sub(t) > s.ttl {
				delete(s.seen, k)
			}
		}
		s.lastGC = now
	}
	if t, ok := s.seen[id]; ok && now.Sub(t) <= s.ttl {
		s.seen[id] = now
		return true
	}
	if len(s.seen) >= s.cap {
		var oldestK string
		var oldestT time.Time
		for k, t := range s.seen {
			if oldestK == "" || t.Before(oldestT) {
				oldestK, oldestT = k, t
			}
		}
		delete(s.seen, oldestK)
	}
	s.seen[id] = now
	return false
}

func (s *Server) dispatch(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	switch f.Kind {
	case "server.health":
		uptime := int64(s.cfg.Now().Sub(s.startAt).Seconds())
		s.writeOK(ctx, c, writeMu, f.ID, "server.health", HealthPayload{
			Version: version.Version,
			UptimeS: uptime,
		})
	case "auth.confirm",
		"audit.list":
		s.dispatchReview(ctx, c, writeMu, f)
	case "infra.metrics.sample":
		s.dispatchInfra(ctx, c, writeMu, f)
	case "monitor.silence", "monitor.ack":
		s.dispatchMonitor(ctx, c, writeMu, f)
	case "inventory.discover":
		s.dispatchInventory(ctx, c, writeMu, f)
	case "watchtower.enable", "watchtower.status":
		s.dispatchWatchtower(ctx, c, writeMu, f)
	case "incident.diagnose", "incident.evidence":
		s.dispatchDiagnose(ctx, c, writeMu, f)
	case "incident.runbook.get", "incident.runbook.decline", "incident.runbook.execute",
		"incident.execution.subscribe", "incident.verify", "incident.rollback",
		"incident.playbook.generate":
		s.dispatchRemediation(ctx, c, writeMu, f)
	default:
		s.writeError(ctx, c, writeMu, f.ID, "unknown_kind", f.Kind)
	}
}

// AuditDTO is the wire shape of one audit row.
type AuditDTO struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	ProjectID string `json:"project_id"`
	SessionID string `json:"session_id,omitempty"`
	Actor     string `json:"actor"`
	Summary   string `json:"summary"`
	Data      string `json:"data,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Server) dispatchReview(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Review == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "review subsystem not configured")
		return
	}
	switch f.Kind {
	case "auth.confirm":
		var in struct {
			Action    string   `json:"action"`
			ProjectID string   `json:"project_id"`
			Files     []string `json:"files"`
			Comment   string   `json:"comment"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Action == "" || in.ProjectID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "action and project_id required")
			return
		}
		tok, err := s.cfg.Review.MintConfirmationToken(in.Action, in.ProjectID, in.Files, in.Comment)
		if err != nil {
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "auth.confirm", map[string]any{"confirmation_token": tok.Token, "action_hash": tok.ActionHash, "expires_at": tok.ExpiresAt.Unix()})
	case "audit.list":
		var in struct {
			Type      string `json:"type"`
			ProjectID string `json:"project_id"`
			Limit     int    `json:"limit"`
		}
		_ = json.Unmarshal(f.Payload, &in)
		entries, err := s.cfg.Review.ListAudit(in.Type, in.ProjectID, in.Limit)
		if err != nil {
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		out := make([]AuditDTO, 0, len(entries))
		for _, e := range entries {
			out = append(out, AuditDTO{ID: e.ID, Type: e.Type, ProjectID: e.ProjectID, SessionID: e.SessionID, Actor: e.Actor, Summary: e.Summary, Data: e.Data, CreatedAt: e.CreatedAt.Unix()})
		}
		s.writeOK(ctx, c, writeMu, f.ID, "audit.list", map[string]any{"entries": out})
	}
}

func (s *Server) writeReviewErr(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id string, err error) {
	switch {
	case errors.Is(err, review.ErrTokenInvalid):
		s.writeError(ctx, c, writeMu, id, "token_invalid", err.Error())
	case errors.Is(err, review.ErrTokenUsed):
		s.writeError(ctx, c, writeMu, id, "token_used", err.Error())
	case errors.Is(err, review.ErrTokenExpired):
		s.writeError(ctx, c, writeMu, id, "token_expired", err.Error())
	case errors.Is(err, review.ErrTokenMismatch):
		s.writeError(ctx, c, writeMu, id, "token_mismatch", err.Error())
	case errors.Is(err, store.ErrNotFound):
		s.writeError(ctx, c, writeMu, id, "not_found", err.Error())
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
}

// DockerStatusDTO mirrors docker.Status on the wire.
type DockerStatusDTO struct {
	Available          bool   `json:"available"`
	Version            string `json:"version,omitempty"`
	APIVersion         string `json:"api_version,omitempty"`
	UnavailableReason  string `json:"unavailable_reason,omitempty"`
	UnavailableMessage string `json:"unavailable_message,omitempty"`
}

func toDockerDTO(st docker.Status) DockerStatusDTO {
	return DockerStatusDTO{
		Available:          st.Available,
		Version:            st.Version,
		APIVersion:         st.APIVersion,
		UnavailableReason:  st.UnavailableReason,
		UnavailableMessage: st.UnavailableMessage,
	}
}

func isAllowedDockerContainerAction(action docker.ContainerAction) bool {
	switch action {
	case docker.ActionStart, docker.ActionStop, docker.ActionRestart, docker.ActionPause, docker.ActionUnpause:
		return true
	default:
		return false
	}
}

func dockerLifecycleTokenBinding(id string, action docker.ContainerAction) (string, string, []string) {
	return "docker.container.action." + string(action), "docker", []string{id}
}

func (s *Server) dispatchInfra(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Infra == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "infra subsystem not configured")
		return
	}
	s.writeOK(ctx, c, writeMu, f.ID, "infra.metrics.sample", map[string]any{"sample": s.cfg.Infra.Sample(ctx)})
}

// MonitorControl is the part of the monitor engine the control plane drives.
type MonitorControl interface {
	Silence(rule, target string, d time.Duration) (time.Time, error)
	Ack(key string, firedAt time.Time) error
}

func (s *Server) dispatchMonitor(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Monitor == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "monitoring is not enabled")
		return
	}
	switch f.Kind {
	case "monitor.silence":
		var in struct {
			Rule       string `json:"rule"`
			Target     string `json:"target"`
			DurationMS int64  `json:"duration_ms"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Rule == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "rule required")
			return
		}
		until, err := s.cfg.Monitor.Silence(in.Rule, in.Target, time.Duration(in.DurationMS)*time.Millisecond)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "alerts_error", err.Error())
			return
		}
		out := map[string]any{"silenced": true}
		if !until.IsZero() {
			out["until"] = until.Unix()
		} else {
			out["silenced"] = false
		}
		s.writeOK(ctx, c, writeMu, f.ID, "monitor.silence", out)
	case "monitor.ack":
		var in struct {
			Key     string `json:"key"`
			FiredAt int64  `json:"fired_at"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Key == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "key required")
			return
		}
		if err := s.cfg.Monitor.Ack(in.Key, time.Unix(in.FiredAt, 0)); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "alerts_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "monitor.ack", map[string]any{"acked": true})
	}
}

func (s *Server) writeOK(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id, kind string, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		s.writeError(ctx, c, writeMu, id, "marshal_error", err.Error())
		return
	}
	out, _ := json.Marshal(Frame{ID: id, Kind: kind, Payload: raw})
	writeMu.enqueue(out)
}

func (s *Server) writeError(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id, kind, msg string) {
	raw, _ := json.Marshal(map[string]string{"error": msg})
	out, _ := json.Marshal(Frame{ID: id, Kind: "error." + kind, Payload: raw})
	writeMu.enqueue(out)
}

func (s *Server) dispatchInventory(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	switch f.Kind {
	case "inventory.discover":
		report := s.discoverHostInventory(ctx)
		s.writeOK(ctx, c, writeMu, f.ID, "inventory.discover", report)
	}
}

// discoverHostInventory wires the real infra/docker/systemd/webserver
// managers into an inventory.Discoverer, nil-safe for any subsystem the
// agent was not configured with.
func (s *Server) discoverHostInventory(ctx context.Context) inventory.DiscoveryReport {
	cfg := inventory.DiscoveryConfig{Now: s.cfg.Now}
	if s.cfg.Infra != nil {
		cfg.Infra = s.cfg.Infra
	}
	if s.cfg.Docker != nil {
		cfg.Docker = s.cfg.Docker
	}
	if s.cfg.Systemd != nil {
		cfg.Systemd = s.cfg.Systemd
	}
	if s.cfg.Webservers != nil {
		cfg.Webserver = s.cfg.Webservers
	}
	if s.cfg.Priv != nil {
		cfg.Priv = func(ctx context.Context, action string, args ...string) ([]byte, error) {
			return s.cfg.Priv.Call(ctx, action, args...)
		}
	}
	return inventory.NewDiscoverer(cfg).Discover(ctx)
}

// dispatchWatchtower owns the Watchtower Phase 1 cloud spine tracer:
// enrolling this agent against a relay (mobile-driven, using the
// enrollmentCode minted when the user added the server) and reporting
// enrollment state back to the app. No confirmation-token gate: enabling
// Watchtower only starts an outbound heartbeat loop.
func (s *Server) dispatchWatchtower(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Watchtower == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "watchtower not configured")
		return
	}
	switch f.Kind {
	case "watchtower.enable":
		var in struct {
			RelayURL       string `json:"relayUrl"`
			EnrollmentCode string `json:"enrollmentCode"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.RelayURL == "" || in.EnrollmentCode == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "relayUrl and enrollmentCode required")
			return
		}
		creds, err := s.cfg.Watchtower.Enroll(ctx, in.RelayURL, in.EnrollmentCode)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "watchtower_error", err.Error())
			return
		}
		// EnsureRunning starts the heartbeat loop against context.Background()
		// on first call, independent of this WebSocket connection's lifetime --
		// heartbeats must keep flowing after the mobile app disconnects.
		s.cfg.Watchtower.EnsureRunning(0)
		if s.cfg.OnWatchtowerEnabled != nil {
			s.cfg.OnWatchtowerEnabled()
		}
		s.writeOK(ctx, c, writeMu, f.ID, "watchtower.enable", map[string]any{
			"serverId": creds.ServerID, "agentId": creds.AgentID, "status": "protected",
		})
	case "watchtower.status":
		creds := s.cfg.Watchtower.Creds()
		if creds == nil {
			s.writeOK(ctx, c, writeMu, f.ID, "watchtower.status", map[string]any{"enrolled": false})
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "watchtower.status", map[string]any{
			"enrolled": true,
			"relayUrl": creds.RelayURL,
			"serverId": creds.ServerID,
			"agentId":  creds.AgentID,
			"status":   "protected",
		})
	}
}

// systemdDiagnoseSource adapts *systemd.Manager to diagnose.SystemdSource:
// Get and List already match the manager's real signatures, so embedding it
// satisfies both directly. The manager has no unit-log-reading method at
// all, so Logs shells out to journalctl for a bounded, per-unit tail.
type systemdDiagnoseSource struct {
	*systemd.Manager
}

func (s systemdDiagnoseSource) Logs(ctx context.Context, unit string, tail int) (string, error) {
	if tail <= 0 {
		tail = diagnose.DefaultMaxLogLines
	}
	out, err := exec.CommandContext(ctx, "journalctl", "-u", unit, "-n", strconv.Itoa(tail), "--no-pager").CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("journalctl -u %s: %w", unit, err)
	}
	return string(out), nil
}

// buildDiagnosePipeline wires a diagnose.Pipeline from whichever of
// Docker/Systemd/Infra/Webservers are configured, nil-safe for any subset
// (including none) exactly like discoverHostInventory: a missing source
// just means that section of the evidence bundle stays empty with a
// Warning, per diagnose.Collector.Collect's documented behavior. The
// stack, disk and proxy sources read the host directly.
func (s *Server) buildDiagnosePipeline() *diagnose.Pipeline {
	cfg := diagnose.CollectorConfig{
		Redactor: s.cfg.DiagnoseRedactor,
		Now:      s.cfg.Now,
	}
	if s.cfg.Docker != nil {
		cfg.Docker = s.cfg.Docker
	}
	if s.cfg.Systemd != nil {
		cfg.Systemd = systemdDiagnoseSource{s.cfg.Systemd}
	}
	if s.cfg.Infra != nil {
		cfg.Infra = s.cfg.Infra
	}
	if s.cfg.Webservers != nil {
		cfg.Webserver = s.cfg.Webservers
	}
	cfg.Stack = stackSource{s}
	cfg.Disk = diskSource{}
	cfg.Proxy = proxySource{s: s}
	return diagnose.NewPipeline(diagnose.PipelineConfig{
		Collector:           diagnose.NewCollector(cfg),
		ConfidenceThreshold: s.cfg.DiagnoseConfidenceThreshold,
	})
}

func (s *Server) setDiagnoseBundle(incidentID string, b diagnose.Bundle) {
	s.diagnoseMu.Lock()
	s.diagnoseBundles[incidentID] = b
	s.diagnoseMu.Unlock()
}

func (s *Server) getDiagnoseBundle(incidentID string) (diagnose.Bundle, bool) {
	s.diagnoseMu.Lock()
	defer s.diagnoseMu.Unlock()
	b, ok := s.diagnoseBundles[incidentID]
	return b, ok
}

// dispatchDiagnose owns incident.diagnose and incident.evidence: running the
// bounded, redacted local diagnostic pipeline and serving its evidence
// bundle. Raw evidence never leaves this handler's response; the playbook
// request to the relay is built separately from the redacted bundle.
func (s *Server) dispatchDiagnose(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.DiagnoseRedactor == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "diagnose subsystem not configured")
		return
	}
	var in struct {
		IncidentID  string `json:"incidentId"`
		MonitorKind string `json:"monitorKind"`
		Target      string `json:"target"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.IncidentID == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "incidentId required")
		return
	}
	target := diagnose.Target{IncidentID: in.IncidentID, MonitorKind: in.MonitorKind, Target: in.Target}
	if s.cfg.Store != nil {
		if b, err := s.cfg.Store.GetIncidentBinding(in.IncidentID); err == nil {
			target.Summary = b.Summary
		}
	}
	switch f.Kind {
	case "incident.diagnose":
		assessment, bundle := s.buildDiagnosePipeline().Run(ctx, target)
		s.setDiagnoseBundle(in.IncidentID, bundle)
		s.writeOK(ctx, c, writeMu, f.ID, "incident.diagnose", assessment)
	case "incident.evidence":
		bundle, ok := s.getDiagnoseBundle(in.IncidentID)
		if !ok {
			bundle = s.buildDiagnosePipeline().Collect(ctx, target)
			s.setDiagnoseBundle(in.IncidentID, bundle)
		}
		s.writeOK(ctx, c, writeMu, f.ID, "incident.evidence", bundle)
	}
}
