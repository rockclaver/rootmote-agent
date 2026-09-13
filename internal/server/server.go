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

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/alerts"
	"github.com/rockclaver/rootmote-agent/internal/cliauth"
	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/firewall"
	"github.com/rockclaver/rootmote-agent/internal/infra"
	"github.com/rockclaver/rootmote-agent/internal/inventory"
	"github.com/rockclaver/rootmote-agent/internal/notifications"
	agentprocess "github.com/rockclaver/rootmote-agent/internal/process"
	"github.com/rockclaver/rootmote-agent/internal/push"
	"github.com/rockclaver/rootmote-agent/internal/remediation"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/security"
	"github.com/rockclaver/rootmote-agent/internal/storage"
	"github.com/rockclaver/rootmote-agent/internal/store"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
	"github.com/rockclaver/rootmote-agent/internal/tooling"
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
	// Tooling, when non-nil, enables tooling.* kinds.
	Tooling *tooling.Manager
	// Auth, when non-nil, enables auth.* kinds (CLI login flows).
	Auth *cliauth.Manager
	// Docker, when non-nil, enables docker.* kinds.
	Docker *docker.Manager
	// Infra, when non-nil, enables infra.* host metrics kinds.
	Infra *infra.Manager
	// Systemd, when non-nil, enables infra.service.* kinds.
	Systemd *systemd.Manager
	// Processes, when non-nil, enables infra.process.* kinds.
	Processes *agentprocess.Manager
	// Firewall, when non-nil, enables infra.firewall.* kinds.
	Firewall *firewall.Manager
	// Storage, when non-nil, enables storage.* kinds (Storage Analyzer: scan
	// culprits, guarded category cleanup, browse, and guarded delete).
	Storage *storage.Manager
	// Security, when non-nil, enables security.* kinds (defensive host audit
	// and narrow guarded fixes such as firewall-blocking risky ports).
	Security *security.Manager
	// Webservers, when non-nil, enables infra.webserver.* host proxy kinds.
	Webservers *webserver.Manager
	// Alerts, when non-nil, enables infra.alerts.* kinds.
	Alerts *alerts.Manager
	// AIProposals, when non-nil, enables infra.proposal.* kinds (Phase 6:
	// AI-assisted infrastructure).
	AIProposals *aiproposal.Manager
	// Notifications fans background task.notification events to connected clients.
	Notifications *notifications.Hub
	// Runbook, when non-nil, enables infra.runbook.* kinds and surfaces
	// the AI-proposed remediation queue (Stickiness #4).
	Runbook *runbook.Manager
	// Remediation, when non-nil, enables the incident.runbook.*,
	// incident.execution.subscribe, incident.verify, and incident.rollback
	// kinds -- the durable approve/execute/verify lifecycle for one
	// specific approved runbook (issue #74 Task 3).
	Remediation *remediation.Manager
	// Inventory, when non-nil, enables inventory.* kinds (AI Action Plane:
	// fleet capability snapshots for target resolution).
	Inventory *inventory.Manager
	// PushDevices, when non-nil, enables push.register / push.unregister
	// for FCM device-token management.
	PushDevices *store.Store
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
	// DiagnoseProposer, when non-nil, enables the AI diagnosis step on top
	// of the deterministic signatures. Nil means deterministic-only
	// diagnosis (AC6) without disabling incident.diagnose/incident.evidence.
	DiagnoseProposer diagnose.Proposer
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
	return &Server{
		cfg:             cfg,
		startAt:         cfg.Now(),
		seen:            newIDSet(1024, replayWindow, cfg.Now),
		diagnoseBundles: make(map[string]diagnose.Bundle),
	}
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
	// kinds like incident.runbook.execute / infra.proposal.approve don't execute twice.
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
	case "tooling.check",
		"tooling.install":
		s.dispatchTooling(ctx, c, writeMu, f)
	case "auth.status",
		"auth.login_start",
		"auth.input",
		"auth.login_cancel",
		"auth.set_token",
		"auth.logout",
		"auth.relay_callback":
		s.dispatchAuth(ctx, c, writeMu, f)
	case "infra.metrics.sample":
		s.dispatchInfra(ctx, c, writeMu, f)
	case "infra.alerts.config",
		"infra.alerts.config_set",
		"infra.alerts.silence",
		"infra.alerts.unsilence",
		"infra.alerts.ack":
		s.dispatchAlerts(ctx, c, writeMu, f)
	case "infra.proposal.approve",
		"infra.proposal.decline":
		s.dispatchProposal(ctx, c, writeMu, f)
	case "infra.runbook.list",
		"infra.runbook.get":
		s.dispatchRunbook(ctx, c, writeMu, f)
	case "inventory.capabilities", "inventory.discover":
		s.dispatchInventory(ctx, c, writeMu, f)
	case "push.register", "push.unregister", "push.list",
		"notifications.prefs.list", "notifications.prefs.set":
		s.dispatchPush(ctx, c, writeMu, f)
	case "watchtower.enable", "watchtower.status":
		s.dispatchWatchtower(ctx, c, writeMu, f)
	case "incident.diagnose", "incident.evidence":
		s.dispatchDiagnose(ctx, c, writeMu, f)
	case "incident.runbook.get", "incident.runbook.decline", "incident.runbook.execute",
		"incident.execution.subscribe", "incident.verify", "incident.rollback":
		s.dispatchRemediation(ctx, c, writeMu, f)
	default:
		s.writeError(ctx, c, writeMu, f.ID, "unknown_kind", f.Kind)
	}
}

// ChangedFileDTO is retained only for source compatibility with historical
// audit payloads; the diff API itself is no longer exposed.
type ChangedFileDTO struct {
	Path     string `json:"path"`
	OldPath  string `json:"old_path,omitempty"`
	Group    string `json:"group"`
	Binary   bool   `json:"binary"`
	Revision string `json:"revision"`
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

func (s *Server) dispatchAlerts(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Alerts == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "alerts subsystem not configured")
		return
	}
	switch f.Kind {
	case "infra.alerts.config":
		var in struct {
			ServerID string `json:"server_id"`
		}
		if len(f.Payload) > 0 {
			if err := json.Unmarshal(f.Payload, &in); err != nil {
				s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "invalid alerts config payload")
				return
			}
		}
		rules, err := s.cfg.Alerts.Config(ctx, in.ServerID)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "alerts_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.alerts.config", map[string]any{"rules": rules})
	case "infra.alerts.config_set":
		var in struct {
			ServerID  string  `json:"server_id"`
			Kind      string  `json:"kind"`
			Enabled   bool    `json:"enabled"`
			Threshold float64 `json:"threshold"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Kind == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "kind required")
			return
		}
		rule, err := s.cfg.Alerts.SetConfig(ctx, store.InfraAlertRule{
			ServerID:  in.ServerID,
			Kind:      in.Kind,
			Enabled:   in.Enabled,
			Threshold: in.Threshold,
			UpdatedAt: s.cfg.Now(),
		})
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "alerts_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.alerts.config_set", map[string]any{"rule": rule})
	case "infra.alerts.silence":
		var in struct {
			Rule       string `json:"rule"`
			Target     string `json:"target"`
			DurationMS int64  `json:"duration_ms"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Rule == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "rule required")
			return
		}
		until, err := s.cfg.Alerts.Silence(in.Rule, in.Target, time.Duration(in.DurationMS)*time.Millisecond)
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
		s.writeOK(ctx, c, writeMu, f.ID, "infra.alerts.silence", out)
	case "infra.alerts.unsilence":
		var in struct {
			Rule   string `json:"rule"`
			Target string `json:"target"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Rule == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "rule required")
			return
		}
		if err := s.cfg.Alerts.Unsilence(in.Rule, in.Target); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "alerts_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.alerts.unsilence", map[string]any{"silenced": false})
	case "infra.alerts.ack":
		var in struct {
			Key     string `json:"key"`
			FiredAt int64  `json:"fired_at"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Key == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "key required")
			return
		}
		if err := s.cfg.Alerts.Ack(in.Key, time.Unix(in.FiredAt, 0)); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "alerts_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.alerts.ack", map[string]any{"acked": true})
	}
}

// ToolingStatusDTO mirrors tooling.Status on the wire.
type ToolingStatusDTO struct {
	Kind      string `json:"kind"`
	Installed bool   `json:"installed"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
}

func toToolingDTO(st tooling.Status) ToolingStatusDTO {
	return ToolingStatusDTO{
		Kind: string(st.Kind), Installed: st.Installed,
		Path: st.Path, Version: st.Version,
	}
}

func (s *Server) dispatchTooling(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Tooling == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "tooling subsystem not configured")
		return
	}
	mgr := s.cfg.Tooling
	switch f.Kind {
	case "tooling.check":
		var in struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Kind == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "kind required")
			return
		}
		st, err := mgr.Check(ctx, tooling.Kind(in.Kind))
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "tooling.check", toToolingDTO(st))
	case "tooling.install":
		var in struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Kind == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "kind required")
			return
		}
		kind := tooling.Kind(in.Kind)
		// Ack the install request immediately so the client can start
		// rendering the log view; progress lines correlate via the
		// install_id we hand back.
		installID := f.ID
		s.writeOK(ctx, c, writeMu, f.ID, "tooling.install", map[string]any{
			"install_id": installID,
			"kind":       in.Kind,
			"state":      "started",
		})
		go func() {
			onLine := func(l tooling.Line) {
				s.writeOK(ctx, c, writeMu, "", "tooling.progress", map[string]any{
					"install_id": installID,
					"kind":       in.Kind,
					"stream":     string(l.Stream),
					"line":       l.Text,
				})
			}
			st, err := mgr.Install(ctx, kind, onLine)
			if err != nil {
				if errors.Is(err, tooling.ErrAlreadyRunning) {
					s.writeOK(ctx, c, writeMu, "", "tooling.done", map[string]any{
						"install_id": installID,
						"kind":       in.Kind,
						"ok":         false,
						"error":      "already_running",
					})
					return
				}
				s.writeOK(ctx, c, writeMu, "", "tooling.done", map[string]any{
					"install_id": installID,
					"kind":       in.Kind,
					"ok":         false,
					"error":      err.Error(),
					"status":     toToolingDTO(st),
				})
				return
			}
			s.writeOK(ctx, c, writeMu, "", "tooling.done", map[string]any{
				"install_id": installID,
				"kind":       in.Kind,
				"ok":         true,
				"status":     toToolingDTO(st),
			})
		}()
	}
}

// CliAuthStatusDTO mirrors cliauth.Status.
type CliAuthStatusDTO struct {
	Kind     string `json:"kind"`
	LoggedIn bool   `json:"logged_in"`
	Method   string `json:"method"`
	Account  string `json:"account,omitempty"`
	Version  string `json:"version,omitempty"`
}

func toAuthDTO(st cliauth.Status) CliAuthStatusDTO {
	return CliAuthStatusDTO{
		Kind: st.Kind, LoggedIn: st.LoggedIn,
		Method: st.Method, Account: st.Account, Version: st.Version,
	}
}

func (s *Server) dispatchAuth(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Auth == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "auth subsystem not configured")
		return
	}
	mgr := s.cfg.Auth
	switch f.Kind {
	case "auth.status":
		var in struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Kind == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "kind required")
			return
		}
		st, err := mgr.Status(ctx, in.Kind)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "auth.status", toAuthDTO(st))
	case "auth.login_start":
		var in struct {
			Kind string `json:"kind"`
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Kind == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "kind required")
			return
		}
		if in.Mode == "" {
			in.Mode = cliauth.ModeInteractive
		}
		login, err := mgr.StartLogin(ctx, in.Kind, in.Mode)
		if err != nil {
			code := "internal"
			if errors.Is(err, cliauth.ErrAlreadyRunning) {
				code = "cli_pending"
			} else if errors.Is(err, cliauth.ErrBadKind) || errors.Is(err, cliauth.ErrBadMode) {
				code = "bad_payload"
			}
			s.writeError(ctx, c, writeMu, f.ID, code, err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "auth.login_start", map[string]any{
			"login_id": login.ID, "kind": login.Kind, "mode": in.Mode,
		})
		go func() {
			for ev := range login.Events {
				switch ev.Type {
				case cliauth.EvtProgress:
					s.writeOK(ctx, c, writeMu, "", "auth.progress", map[string]any{
						"login_id": login.ID, "kind": login.Kind,
						"stream": ev.Stream, "line": ev.Line,
					})
				case cliauth.EvtURL:
					s.writeOK(ctx, c, writeMu, "", "auth.url", map[string]any{
						"login_id": login.ID, "kind": login.Kind,
						"url": ev.URL, "user_code": ev.UserCode,
					})
				case cliauth.EvtCallbackTarget:
					s.writeOK(ctx, c, writeMu, "", "auth.callback_target", map[string]any{
						"login_id": login.ID, "kind": login.Kind,
						"host": ev.CallbackHost, "port": ev.CallbackPort, "path": ev.CallbackPath,
					})
				case cliauth.EvtPromptPaste:
					s.writeOK(ctx, c, writeMu, "", "auth.prompt_paste", map[string]any{
						"login_id": login.ID, "kind": login.Kind,
					})
				case cliauth.EvtDone:
					s.writeOK(ctx, c, writeMu, "", "auth.done", map[string]any{
						"login_id": login.ID, "kind": login.Kind,
						"ok": ev.OK, "error": ev.Error, "status": toAuthDTO(ev.Status),
					})
				}
			}
		}()
	case "auth.input":
		var in struct {
			LoginID string `json:"login_id"`
			Text    string `json:"text"`
			Enter   bool   `json:"enter"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.LoginID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "login_id required")
			return
		}
		if err := mgr.Send(ctx, in.LoginID, in.Text, in.Enter); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "auth.input", map[string]any{"login_id": in.LoginID})
	case "auth.login_cancel":
		var in struct {
			LoginID string `json:"login_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.LoginID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "login_id required")
			return
		}
		if err := mgr.Cancel(in.LoginID); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "auth.login_cancel", map[string]any{"login_id": in.LoginID, "cancelled": true})
	case "auth.set_token":
		var in struct {
			Kind  string `json:"kind"`
			Mode  string `json:"mode"`
			Value string `json:"value"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Kind == "" || in.Value == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "kind and value required")
			return
		}
		st, err := mgr.SetToken(ctx, in.Kind, in.Mode, in.Value)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "auth.set_token", toAuthDTO(st))
	case "auth.relay_callback":
		var in struct {
			LoginID string `json:"login_id"`
			Query   string `json:"query"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.LoginID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "login_id required")
			return
		}
		if err := mgr.Relay(ctx, in.LoginID, in.Query); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "auth.relay_callback", map[string]any{"login_id": in.LoginID, "ok": true})
	case "auth.logout":
		var in struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Kind == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "kind required")
			return
		}
		if err := mgr.Logout(ctx, in.Kind); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "auth.logout", map[string]any{"kind": in.Kind, "ok": true})
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

// dispatchInfraSnapshot aggregates the four infra read sources (metrics,
// services, processes, firewall) into a single payload so an AI session can
// ground answers about host health on real data with one round-trip. Missing
// subsystems are reported as null fields rather than failing the call.
func (s *Server) auditAIProposed(auditType, summary string, data map[string]any) store.AuditEntry {
	if s.cfg.Review == nil {
		return store.AuditEntry{}
	}
	body, _ := json.Marshal(data)
	entry, _ := s.cfg.Review.LogAudit(store.AuditEntry{
		Type:      auditType,
		ProjectID: "infra",
		Actor:     "ai-proposed",
		Summary:   summary,
		Data:      string(body),
		CreatedAt: s.cfg.Now(),
	})
	return entry
}

func (s *Server) dispatchProposal(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.AIProposals == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "AI proposal subsystem not configured")
		return
	}
	switch f.Kind {
	case "infra.proposal.decline":
		var in struct {
			ID      string `json:"id"`
			Comment string `json:"comment"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		// Decline never mutates the host, so it does not require a
		// confirmation token; just record the decision.
		audit := s.auditAIProposed("infra.proposal.decline", "ai-proposed declined: "+in.ID, map[string]any{
			"proposal_id": in.ID,
			"comment":     in.Comment,
		})
		p, err := s.cfg.AIProposals.Resolve(in.ID, aiproposal.StatusDeclined, in.Comment, audit.ID)
		if err != nil {
			if errors.Is(err, aiproposal.ErrNotFound) {
				s.writeError(ctx, c, writeMu, f.ID, "not_found", err.Error())
				return
			}
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.proposal.decline", map[string]any{"proposal": p})
	case "infra.proposal.approve":
		s.handleProposalApprove(ctx, c, writeMu, f)
	}
}

// handleProposalApprove implements the propose -> approve -> execute path.
// Critical invariants:
//
//   - The guard checks (protected unit, protected PID) run BEFORE the
//     confirmation token is consumed so a rejected proposal does not burn a
//     token the operator may want to reuse.
//   - The confirmation token is consumed BEFORE the underlying mutation is
//     attempted, so a failure in the executor cannot be retried by replaying
//     the same token.
//   - Every terminal outcome (rejected / failed / executed) writes an audit
//     row attributed to "ai-proposed" and resolves the proposal so a second
//     approval attempt returns ErrAlreadyResolved.
func (s *Server) handleProposalApprove(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	var in struct {
		ID                string `json:"id"`
		ConfirmationToken string `json:"confirmation_token"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
		return
	}
	if s.cfg.Review == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "confirmation subsystem not configured")
		return
	}
	p, err := s.cfg.AIProposals.Get(in.ID)
	if err != nil {
		s.writeError(ctx, c, writeMu, f.ID, "not_found", err.Error())
		return
	}
	if p.Status != aiproposal.StatusPending {
		s.writeError(ctx, c, writeMu, f.ID, "already_resolved", "proposal is not pending")
		return
	}

	auditType := "infra.proposal." + string(p.Kind)
	// Pre-emptively claim the proposal so a second concurrent approve cannot
	// also consume a (different) confirmation token and double-execute the
	// underlying action. The claim is released on any recoverable failure
	// path (token rejected) so the operator can retry; terminal outcomes
	// transition straight from StatusExecuting to a resolved status.
	claimed, claimErr := s.cfg.AIProposals.Claim(p.ID)
	if claimErr != nil {
		s.writeError(ctx, c, writeMu, f.ID, "already_resolved", claimErr.Error())
		return
	}
	p = claimed
	released := false
	releaseOnce := func() {
		if !released {
			s.cfg.AIProposals.Release(p.ID)
			released = true
		}
	}
	defer releaseOnce()

	// Guard checks BEFORE consuming the token.
	switch p.Kind {
	case aiproposal.KindServiceAction:
		if s.cfg.Systemd == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "systemd subsystem not configured")
			return
		}
		name, _ := p.Params["name"].(string)
		actStr, _ := p.Params["action"].(string)
		act := systemd.Action(actStr)
		if s.cfg.Systemd.IsProtected(name) && (act == systemd.ActionStop || act == systemd.ActionDisable) {
			audit := s.auditAIProposed(auditType, fmt.Sprintf("ai-proposed %s rejected: protected unit %s", actStr, name), map[string]any{
				"proposal_id": p.ID, "kind": p.Kind, "params": p.Params, "reason": "protected_unit",
			})
			_, _ = s.cfg.AIProposals.Resolve(p.ID, aiproposal.StatusRejected, "protected_unit", audit.ID)
			s.writeError(ctx, c, writeMu, f.ID, "protected_unit", fmt.Sprintf("refused %s on protected unit %s", actStr, name))
			return
		}
	case aiproposal.KindProcessKill:
		if s.cfg.Processes == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "process subsystem not configured")
			return
		}
		pid := intFromParams(p.Params["pid"])
		if reason, ok := s.cfg.Processes.IsProtected(ctx, pid); ok {
			audit := s.auditAIProposed(auditType, fmt.Sprintf("ai-proposed kill rejected: protected pid %d", pid), map[string]any{
				"proposal_id": p.ID, "kind": p.Kind, "params": p.Params, "reason": "protected_pid", "detail": reason,
			})
			_, _ = s.cfg.AIProposals.Resolve(p.ID, aiproposal.StatusRejected, "protected_pid", audit.ID)
			s.writeError(ctx, c, writeMu, f.ID, "protected_pid", fmt.Sprintf("refused kill on protected pid %d: %s", pid, reason))
			return
		}
	case aiproposal.KindFirewallAdd, aiproposal.KindFirewallRemove:
		if s.cfg.Firewall == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "firewall subsystem not configured")
			return
		}
		// anti-lockout is enforced inside Firewall.RuleRemove (post-token)
	case aiproposal.KindSecurityFix:
		if s.cfg.Security == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "security subsystem not configured")
			return
		}
	}

	// Consume the confirmation token. A token failure here is recoverable:
	// the operator can retry the approval with a freshly-minted token, so we
	// leave the proposal in StatusPending rather than resolving it.
	if err := s.cfg.Review.ConsumeToken(in.ConfirmationToken, p.TokenAction, p.TokenProjectID, p.TokenFiles, ""); err != nil {
		s.auditAIProposed(auditType, "ai-proposed token rejected: "+err.Error(), map[string]any{
			"proposal_id": p.ID, "kind": p.Kind, "params": p.Params, "reason": "token_invalid",
		})
		s.writeReviewErr(ctx, c, writeMu, f.ID, err)
		return
	}

	// Execute via the same managers human-initiated calls use.
	execErr := s.executeProposal(ctx, p)
	if execErr != nil {
		audit := s.auditAIProposed(auditType, "ai-proposed execution failed: "+execErr.Error(), map[string]any{
			"proposal_id": p.ID, "kind": p.Kind, "params": p.Params, "ok": false, "error": execErr.Error(),
		})
		_, _ = s.cfg.AIProposals.Resolve(p.ID, aiproposal.StatusFailed, execErr.Error(), audit.ID)
		// Map known error classes to the same wire kinds the human path uses.
		var pue *systemd.ProtectedUnitError
		var ppe *agentprocess.ProtectedPIDError
		var ale *firewall.AntiLockoutError
		switch {
		case errors.As(execErr, &pue):
			s.writeError(ctx, c, writeMu, f.ID, "protected_unit", execErr.Error())
		case errors.As(execErr, &ppe):
			s.writeError(ctx, c, writeMu, f.ID, "protected_pid", execErr.Error())
		case errors.As(execErr, &ale):
			s.writeError(ctx, c, writeMu, f.ID, "anti_lockout", execErr.Error())
		case errors.Is(execErr, agentprocess.ErrIdentityMismatch):
			s.writeError(ctx, c, writeMu, f.ID, "process_identity_mismatch", execErr.Error())
		case errors.Is(execErr, agentprocess.ErrTerminationFailed):
			s.writeError(ctx, c, writeMu, f.ID, "process_termination_failed", execErr.Error())
		case errors.Is(execErr, agentprocess.ErrKernelThread):
			s.writeError(ctx, c, writeMu, f.ID, "process_kernel_thread", execErr.Error())
		case errors.Is(execErr, firewall.ErrReadOnly):
			s.writeError(ctx, c, writeMu, f.ID, "firewall_read_only", execErr.Error())
		default:
			s.writeError(ctx, c, writeMu, f.ID, "exec_error", execErr.Error())
		}
		return
	}
	audit := s.auditAIProposed(auditType, "ai-proposed executed: "+p.ID, map[string]any{
		"proposal_id": p.ID, "kind": p.Kind, "params": p.Params, "ok": true,
	})
	resolved, _ := s.cfg.AIProposals.Resolve(p.ID, aiproposal.StatusExecuted, "ok", audit.ID)
	s.writeOK(ctx, c, writeMu, f.ID, "infra.proposal.approve", map[string]any{
		"proposal": resolved,
		"audit_id": audit.ID,
	})
}

func (s *Server) executeProposal(ctx context.Context, p aiproposal.Proposal) error {
	switch p.Kind {
	case aiproposal.KindServiceAction:
		name, _ := p.Params["name"].(string)
		actStr, _ := p.Params["action"].(string)
		return s.cfg.Systemd.Action(ctx, name, systemd.Action(actStr))
	case aiproposal.KindProcessKill:
		pid := intFromParams(p.Params["pid"])
		startTicks := uint64FromParams(p.Params["start_time_ticks"])
		signal, _ := p.Params["signal"].(string)
		return s.cfg.Processes.Kill(ctx, pid, startTicks, signal)
	case aiproposal.KindFirewallAdd:
		rule, err := ruleFromParams(p.Params)
		if err != nil {
			return err
		}
		return s.cfg.Firewall.RuleAdd(ctx, rule)
	case aiproposal.KindFirewallRemove:
		rule, err := ruleFromParams(p.Params)
		if err != nil {
			return err
		}
		return s.cfg.Firewall.RuleRemove(ctx, rule)
	case aiproposal.KindSecurityFix:
		req, err := securityFixRequestFromParams(p.Params)
		if err != nil {
			return err
		}
		_, err = s.cfg.Security.Fix(ctx, req)
		return err
	}
	return fmt.Errorf("unknown proposal kind %q", p.Kind)
}

// dispatchRunbook surfaces the runbook.Manager's queue. Mutations are NOT
// exposed: a runbook is created server-side from an alert, and its steps are
// approved via the existing infra.proposal.approve path (which already routes
// through biometric + confirmation token).
func (s *Server) dispatchRunbook(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Runbook == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "runbook subsystem not configured")
		return
	}
	switch f.Kind {
	case "infra.runbook.list":
		s.writeOK(ctx, c, writeMu, f.ID, "infra.runbook.list", map[string]any{
			"runbooks": s.cfg.Runbook.List(),
		})
	case "infra.runbook.get":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		rb, ok := s.cfg.Runbook.Get(in.ID)
		if !ok {
			s.writeError(ctx, c, writeMu, f.ID, "not_found", "runbook "+in.ID)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.runbook.get", map[string]any{
			"runbook": rb,
		})
	}
}

func (s *Server) dispatchInventory(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Inventory == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "inventory subsystem not configured")
		return
	}
	switch f.Kind {
	case "inventory.capabilities":
		snap := s.cfg.Inventory.SnapshotCapabilities(ctx)
		s.writeOK(ctx, c, writeMu, f.ID, "inventory.capabilities", map[string]any{"snapshot": snap})
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
	return inventory.NewDiscoverer(cfg).Discover(ctx)
}

// dispatchPush owns FCM device-token registration. Tokens are stored on the
// host so the agent can fan push messages to every device that has connected
// to this server — no external device-registry service is required.
func (s *Server) dispatchPush(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.PushDevices == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "push subsystem not configured")
		return
	}
	switch f.Kind {
	case "push.register":
		var in struct {
			Token     string `json:"token"`
			APNsToken string `json:"apns_token"`
			Platform  string `json:"platform"`
			// ServerID is Rootmote's own client-side identifier for the
			// server this device is registering against (minted when the
			// user added the server; the agent has no other way to learn
			// it). Persisted per-device so push.Hub can stamp the right
			// value into deep_link/staged-action payloads instead of the
			// agent's internal rule-bucket id, which the client can never
			// match against its own server list.
			ServerID string `json:"server_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Token == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "token required")
			return
		}
		err := s.cfg.PushDevices.PutPushDevice(store.PushDevice{
			Token: in.Token, APNsToken: in.APNsToken, Platform: in.Platform,
			ClientServerID: in.ServerID, LastSeenAt: s.cfg.Now(),
		})
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "push.register", map[string]any{"ok": true})
	case "push.unregister":
		var in struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Token == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "token required")
			return
		}
		if err := s.cfg.PushDevices.DeletePushDevice(in.Token); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "push.unregister", map[string]any{"ok": true})
	case "push.list":
		devices, err := s.cfg.PushDevices.ListPushDevices()
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "push.list", map[string]any{"devices": devices})
	case "notifications.prefs.list":
		overrides, err := s.cfg.PushDevices.ListNotificationPrefs()
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		ov := make(map[string]bool, len(overrides))
		for _, p := range overrides {
			ov[p.Type] = p.PushEnabled
		}
		kinds := push.KnownKinds()
		out := make([]NotificationPrefDTO, 0, len(kinds))
		for _, k := range kinds {
			enabled, overridden := k.DefaultPush, false
			if v, ok := ov[k.Key]; ok {
				enabled, overridden = v, true
			}
			out = append(out, NotificationPrefDTO{
				Type: k.Key, Label: k.Label, DefaultPush: k.DefaultPush,
				PushEnabled: enabled, Overridden: overridden,
			})
		}
		s.writeOK(ctx, c, writeMu, f.ID, "notifications.prefs.list", map[string]any{"prefs": out})
	case "notifications.prefs.set":
		var in struct {
			Type        string `json:"type"`
			PushEnabled bool   `json:"push_enabled"`
			// Reset, when true, deletes any override and reverts Type to
			// its built-in default; PushEnabled is ignored.
			Reset bool `json:"reset"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Type == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "type required")
			return
		}
		if in.Reset {
			if err := s.cfg.PushDevices.DeleteNotificationPref(in.Type); err != nil {
				s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
				return
			}
		} else if err := s.cfg.PushDevices.PutNotificationPref(store.NotificationPref{
			Type: in.Type, PushEnabled: in.PushEnabled, UpdatedAt: s.cfg.Now(),
		}); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "notifications.prefs.set", map[string]any{"ok": true})
	}
}

// dispatchWatchtower owns the Watchtower Phase 1 cloud spine tracer:
// enrolling this agent against a relay (mobile-driven, using the
// enrollmentCode minted when the user added the server) and reporting
// enrollment state back to the app. No confirmation-token gate: enabling
// Watchtower only starts an outbound heartbeat loop, mirroring the
// ungated push.register write it sits next to.
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
// Warning, per diagnose.Collector.Collect's documented behavior.
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
	return diagnose.NewPipeline(diagnose.PipelineConfig{
		Collector:           diagnose.NewCollector(cfg),
		Proposer:            s.cfg.DiagnoseProposer,
		ConfidenceThreshold: s.cfg.DiagnoseConfidenceThreshold,
		Now:                 s.cfg.Now,
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

// dispatchDiagnose owns incident.diagnose and incident.evidence (Watchtower
// Phase 5, issue #73): running the bounded, redacted local diagnostic
// pipeline and serving its evidence bundle. Raw evidence never leaves this
// handler's response -- the relay only ever receives Assessment.Summary()
// via watchtower.Client.SendDiagnosticSummary, posted elsewhere.
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

// NotificationPrefDTO is one row of the push notification settings list: a
// known kind, its built-in default, and the effective push_enabled after
// applying any persisted override.
type NotificationPrefDTO struct {
	Type        string `json:"type"`
	Label       string `json:"label"`
	DefaultPush bool   `json:"default_push"`
	PushEnabled bool   `json:"push_enabled"`
	Overridden  bool   `json:"overridden"`
}
