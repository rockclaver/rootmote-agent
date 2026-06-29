// Package server implements the claver-agent control-plane WebSocket server.
//
// The server binds only to a loopback address. A startup self-check refuses
// non-loopback bind addresses outright — the only legitimate transport into
// the agent is an SSH-forwarded localhost connection from the mobile app.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/claver-agent/internal/actions"
	"github.com/rockclaver/claver-agent/internal/aiproposal"
	"github.com/rockclaver/claver-agent/internal/alerts"
	"github.com/rockclaver/claver-agent/internal/billing"
	"github.com/rockclaver/claver-agent/internal/cliauth"
	"github.com/rockclaver/claver-agent/internal/cost"
	"github.com/rockclaver/claver-agent/internal/docker"
	"github.com/rockclaver/claver-agent/internal/firewall"
	gh "github.com/rockclaver/claver-agent/internal/github"
	"github.com/rockclaver/claver-agent/internal/inbox"
	"github.com/rockclaver/claver-agent/internal/infra"
	"github.com/rockclaver/claver-agent/internal/inventory"
	"github.com/rockclaver/claver-agent/internal/memory"
	"github.com/rockclaver/claver-agent/internal/notifications"
	"github.com/rockclaver/claver-agent/internal/previews"
	agentprocess "github.com/rockclaver/claver-agent/internal/process"
	"github.com/rockclaver/claver-agent/internal/projects"
	"github.com/rockclaver/claver-agent/internal/review"
	"github.com/rockclaver/claver-agent/internal/runbook"
	"github.com/rockclaver/claver-agent/internal/sessions"
	"github.com/rockclaver/claver-agent/internal/skills"
	"github.com/rockclaver/claver-agent/internal/store"
	"github.com/rockclaver/claver-agent/internal/systemd"
	"github.com/rockclaver/claver-agent/internal/tooling"
	"github.com/rockclaver/claver-agent/internal/version"
	"github.com/rockclaver/claver-agent/internal/webserver"
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
	// Projects, when non-nil, enables the project.* kinds.
	Projects *projects.Manager
	// Sessions, when non-nil, enables the session.* kinds.
	Sessions *sessions.Manager
	// Skills, when non-nil, enables the skills.list kind (prompt-composer
	// autocomplete for installed skills + built-in commands).
	Skills *skills.Manager
	// Review, when non-nil, enables the diff.*, review.*, auth.confirm,
	// and audit.list kinds.
	Review *review.Manager
	// GitHub, when non-nil, enables github.* kinds.
	GitHub *gh.Manager
	// Previews, when non-nil, enables preview.* kinds.
	Previews *previews.Manager
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
	// Webservers, when non-nil, enables infra.webserver.* host proxy kinds.
	Webservers *webserver.Manager
	// Alerts, when non-nil, enables infra.alerts.* kinds.
	Alerts *alerts.Manager
	// AIProposals, when non-nil, enables infra.proposal.* kinds (Phase 6:
	// AI-assisted infrastructure).
	AIProposals *aiproposal.Manager
	// Notifications fans background task.notification events to connected clients.
	Notifications *notifications.Hub
	// Inbox, when non-nil, enables inbox.* kinds (unified triage feed).
	Inbox *inbox.Manager
	// Runbook, when non-nil, enables infra.runbook.* kinds and surfaces
	// the AI-proposed remediation queue (Stickiness #4).
	Runbook *runbook.Manager
	// Actions, when non-nil, enables action.* kinds (AI Action Plane:
	// top-level command jobs). Phase 1 is read-only — no mutation.
	Actions *actions.Manager
	// Inventory, when non-nil, enables inventory.* kinds (AI Action Plane:
	// fleet capability snapshots for target resolution).
	Inventory *inventory.Manager
	// PushDevices, when non-nil, enables push.register / push.unregister
	// for FCM device-token management.
	PushDevices *store.Store
	// Memory, when non-nil, enables memory.* and journal.* kinds (Stickiness
	// #5: per-project agent memory + project journal).
	Memory *memory.Manager
	// Cost, when non-nil, enables cost.* kinds (Stickiness #8: cross-fleet
	// cost & usage rollup).
	Cost *cost.Calculator
	// Billing, when non-nil, enables provider.* kinds (encrypted VPS billing
	// credentials + on-demand refresh of the daily cost fetch).
	Billing *billing.Manager
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

	dockerLogMu      sync.Mutex
	dockerLogNextGen int64
	dockerLogCancels map[string]dockerLogCancel

	dockerStatsMu      sync.Mutex
	dockerStatsNextGen int64
	dockerStatsCancels map[string]dockerLogCancel

	infraMetricsMu      sync.Mutex
	infraMetricsNextGen int64
	infraMetricsCancels map[string]dockerLogCancel
}

type dockerLogCancel struct {
	gen    int64
	cancel context.CancelFunc
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
		cfg:                 cfg,
		startAt:             cfg.Now(),
		seen:                newIDSet(1024, replayWindow, cfg.Now),
		dockerLogCancels:    make(map[string]dockerLogCancel),
		dockerStatsCancels:  make(map[string]dockerLogCancel),
		infraMetricsCancels: make(map[string]dockerLogCancel),
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
	// kinds like project.create / session.prompt don't execute twice.
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
	case "project.create",
		"project.import",
		"project.list",
		"project.status",
		"project.history",
		"project.branch_create",
		"project.branch_switch",
		"project.delete":
		s.dispatchProject(ctx, c, writeMu, f)
	case "session.start",
		"session.prompt",
		"session.input",
		"session.question_decision",
		"session.interrupt",
		"session.resize",
		"session.stop",
		"session.delete",
		"session.list",
		"session.subscribe",
		"session.approval",
		"session.set_mode",
		"session.download":
		s.dispatchSession(ctx, c, writeMu, f)
	case "skills.list":
		s.dispatchSkills(ctx, c, writeMu, f)
	case "diff.status",
		"diff.file",
		"diff.summarize",
		"review.approve",
		"review.reject",
		"review.revise",
		"auth.confirm",
		"audit.list":
		s.dispatchReview(ctx, c, writeMu, f)
	case "preview.setup_domain",
		"preview.get_domain",
		"preview.dns_validate",
		"preview.start",
		"preview.stop",
		"preview.restart",
		"preview.list",
		"preview.get",
		"preview.active":
		s.dispatchPreview(ctx, c, writeMu, f)
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
	case "docker.status",
		"docker.container.list",
		"docker.container.get",
		"docker.container.action",
		"docker.container.logs",
		"docker.container.logs_subscribe",
		"docker.container.logs_unsubscribe",
		"docker.container.stats",
		"docker.container.stats_subscribe",
		"docker.container.stats_unsubscribe",
		"docker.image.list",
		"docker.image.get",
		"docker.volume.list",
		"docker.network.list",
		"docker.info":
		s.dispatchDocker(ctx, c, writeMu, f)
	case "infra.metrics.sample",
		"infra.metrics.subscribe",
		"infra.metrics.unsubscribe":
		s.dispatchInfra(ctx, c, writeMu, f)
	case "infra.service.list",
		"infra.service.get",
		"infra.service.action",
		"infra.system.reboot":
		s.dispatchSystemd(ctx, c, writeMu, f)
	case "infra.webserver.list",
		"infra.webserver.validate",
		"infra.webserver.action":
		s.dispatchWebserver(ctx, c, writeMu, f)
	case "infra.process.list",
		"infra.process.kill":
		s.dispatchProcess(ctx, c, writeMu, f)
	case "infra.firewall.status",
		"infra.firewall.rule_add",
		"infra.firewall.rule_remove":
		s.dispatchFirewall(ctx, c, writeMu, f)
	case "infra.alerts.config",
		"infra.alerts.config_set",
		"infra.alerts.silence",
		"infra.alerts.unsilence",
		"infra.alerts.ack":
		s.dispatchAlerts(ctx, c, writeMu, f)
	case "infra.snapshot":
		s.dispatchInfraSnapshot(ctx, c, writeMu, f)
	case "infra.proposal.create",
		"infra.proposal.list",
		"infra.proposal.get",
		"infra.proposal.approve",
		"infra.proposal.decline":
		s.dispatchProposal(ctx, c, writeMu, f)
	case "github.repo_list",
		"github.repo_import",
		"github.commit",
		"github.push",
		"github.pr_draft",
		"github.pr_create",
		"github.pr_list",
		"github.revoke":
		s.dispatchGitHub(ctx, c, writeMu, f)
	case "inbox.list", "inbox.stream", "inbox.mark_read", "inbox.resolve":
		s.dispatchInbox(ctx, c, writeMu, f)
	case "infra.runbook.list",
		"infra.runbook.get":
		s.dispatchRunbook(ctx, c, writeMu, f)
	case "action.submit",
		"action.list",
		"action.get",
		"action.cancel":
		s.dispatchAction(ctx, c, writeMu, f)
	case "inventory.capabilities":
		s.dispatchInventory(ctx, c, writeMu, f)
	case "push.register", "push.unregister", "push.list":
		s.dispatchPush(ctx, c, writeMu, f)
	case "memory.list",
		"memory.create",
		"memory.update",
		"memory.delete",
		"memory.proposals",
		"memory.confirm",
		"memory.reject",
		"journal.list",
		"journal.export":
		s.dispatchMemory(ctx, c, writeMu, f)
	case "cost.rollup",
		"cost.export",
		"provider.list",
		"provider.set",
		"provider.delete",
		"provider.refresh":
		s.dispatchCost(ctx, c, writeMu, f)
	default:
		s.writeError(ctx, c, writeMu, f.ID, "unknown_kind", f.Kind)
	}
}

// ProjectDTO is the wire shape of a project row.
type ProjectDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	RemoteURL string `json:"remote_url,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

func toDTO(p store.Project) ProjectDTO {
	return ProjectDTO{ID: p.ID, Name: p.Name, RemoteURL: p.RemoteURL, CreatedAt: p.CreatedAt.Unix()}
}

type SessionDTO struct {
	ID           string `json:"id"`
	ProjectID    string `json:"project_id"`
	Agent        string `json:"agent"`
	Transport    string `json:"transport"`
	StartedAt    int64  `json:"started_at"`
	EndedAt      *int64 `json:"ended_at,omitempty"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
}

type SessionEventDTO struct {
	SessionID string `json:"session_id"`
	Seq       int64  `json:"seq"`
	Type      string `json:"type"`
	Data      string `json:"data"`
	CreatedAt int64  `json:"created_at"`
}

func toSessionDTO(sess store.Session) SessionDTO {
	var ended *int64
	if sess.EndedAt != nil {
		v := sess.EndedAt.Unix()
		ended = &v
	}
	return SessionDTO{
		ID: sess.ID, ProjectID: sess.ProjectID, Agent: sess.Agent, Transport: sess.Transport,
		StartedAt: sess.StartedAt.Unix(), EndedAt: ended,
		InputTokens: sess.InputTokens, OutputTokens: sess.OutputTokens,
	}
}

func toSessionEventDTO(ev store.SessionEvent) SessionEventDTO {
	return SessionEventDTO{SessionID: ev.SessionID, Seq: ev.Seq, Type: ev.Type, Data: ev.Data, CreatedAt: ev.CreatedAt.Unix()}
}

func (s *Server) dispatchProject(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Projects == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "projects subsystem not configured")
		return
	}
	mgr := s.cfg.Projects
	switch f.Kind {
	case "project.create":
		var in struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Name == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "name required")
			return
		}
		p, err := mgr.CreateEmpty(in.Name)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "project.create", toDTO(p))
	case "project.import":
		var in struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Name == "" || in.URL == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "name and url required")
			return
		}
		p, err := mgr.Import(in.Name, in.URL)
		if err != nil {
			s.writeProjectErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "project.import", toDTO(p))
	case "project.list":
		ps, err := mgr.List()
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		out := make([]ProjectDTO, 0, len(ps))
		for _, p := range ps {
			out = append(out, toDTO(p))
		}
		s.writeOK(ctx, c, writeMu, f.ID, "project.list", map[string]any{"projects": out})
	case "project.status":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		st, err := mgr.Status(in.ID)
		if err != nil {
			s.writeProjectErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "project.status", st)
	case "project.history":
		var in struct {
			ID     string `json:"id"`
			Limit  int    `json:"limit"`
			Offset int    `json:"offset"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		commits, err := mgr.History(in.ID, in.Limit, in.Offset)
		if err != nil {
			s.writeProjectErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "project.history", map[string]any{"commits": commits})
	case "project.branch_create", "project.branch_switch":
		var in struct {
			ID     string `json:"id"`
			Branch string `json:"branch"`
			Force  bool   `json:"force"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" || in.Branch == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id and branch required")
			return
		}
		var err error
		if f.Kind == "project.branch_create" {
			err = mgr.BranchCreate(in.ID, in.Branch, in.Force)
		} else {
			err = mgr.BranchSwitch(in.ID, in.Branch, in.Force)
		}
		if err != nil {
			s.writeProjectErr(ctx, c, writeMu, f.ID, err)
			return
		}
		st, _ := mgr.Status(in.ID)
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, st)
	case "project.delete":
		var in struct {
			ID   string `json:"id"`
			Wipe bool   `json:"wipe"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		if err := mgr.Delete(in.ID, in.Wipe); err != nil {
			s.writeProjectErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "project.delete", map[string]any{"id": in.ID, "wiped": in.Wipe})
	}
}

func (s *Server) dispatchSession(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Sessions == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "sessions subsystem not configured")
		return
	}
	mgr := s.cfg.Sessions
	switch f.Kind {
	case "session.start":
		var in struct {
			ProjectID string `json:"project_id"`
			Agent     string `json:"agent"`
			RunMode   string `json:"run_mode"`
			Transport string `json:"transport"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" || in.Agent == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id and agent required")
			return
		}
		sess, err := mgr.Start(ctx, in.ProjectID, in.Agent, in.RunMode, in.Transport)
		if err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.start", toSessionDTO(sess))
	case "session.prompt":
		var in struct {
			SessionID string `json:"session_id"`
			Prompt    string `json:"prompt"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" || in.Prompt == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "session_id and prompt required")
			return
		}
		if err := mgr.SendPrompt(ctx, in.SessionID, in.Prompt); err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.prompt", map[string]any{"session_id": in.SessionID})
	case "session.input":
		var in struct {
			SessionID string `json:"session_id"`
			Data      string `json:"data"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "session_id required")
			return
		}
		if err := mgr.SendInput(ctx, in.SessionID, in.Data); err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.input", map[string]any{"session_id": in.SessionID})
	case "session.question_decision":
		var in struct {
			SessionID       string `json:"session_id"`
			GroupIndex      int    `json:"group_index"`
			SelectedIndices []int  `json:"selected_indices"`
			FreeText        string `json:"free_text"`
			Action          string `json:"action"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "invalid_payload", "session_id required")
			return
		}
		if err := mgr.SendQuestionDecision(ctx, in.SessionID, in.GroupIndex, in.SelectedIndices, in.FreeText, in.Action); err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.question_decision", map[string]any{"session_id": in.SessionID})
	case "session.approval":
		var in struct {
			SessionID string `json:"session_id"`
			RequestID string `json:"request_id"`
			Decision  string `json:"decision"`
			Note      string `json:"note"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "session_id required")
			return
		}
		if err := mgr.SendApproval(ctx, in.SessionID, in.RequestID, in.Decision, in.Note); err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.approval", map[string]any{"session_id": in.SessionID})
	case "session.set_mode":
		var in struct {
			SessionID string `json:"session_id"`
			Mode      string `json:"mode"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "session_id required")
			return
		}
		if err := mgr.SetMode(ctx, in.SessionID, in.Mode); err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.set_mode", map[string]any{"session_id": in.SessionID})
	case "session.interrupt":
		var in struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "session_id required")
			return
		}
		if err := mgr.Interrupt(ctx, in.SessionID); err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.interrupt", map[string]any{"session_id": in.SessionID})
	case "session.resize":
		var in struct {
			SessionID string `json:"session_id"`
			Cols      int    `json:"cols"`
			Rows      int    `json:"rows"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "session_id required")
			return
		}
		if err := mgr.Resize(ctx, in.SessionID, in.Cols, in.Rows); err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.resize", map[string]any{"session_id": in.SessionID})
	case "session.stop":
		var in struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "session_id required")
			return
		}
		if err := mgr.Stop(ctx, in.SessionID); err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.stop", map[string]any{"session_id": in.SessionID})
	case "session.delete":
		var in struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "session_id required")
			return
		}
		if err := mgr.Delete(ctx, in.SessionID); err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.delete", map[string]any{"session_id": in.SessionID})
	case "session.list":
		var in struct {
			ProjectID string `json:"project_id"`
		}
		_ = json.Unmarshal(f.Payload, &in)
		sessions, err := mgr.List(in.ProjectID)
		if err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		out := make([]SessionDTO, 0, len(sessions))
		for _, sess := range sessions {
			out = append(out, toSessionDTO(sess))
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.list", map[string]any{"sessions": out})
	case "session.download":
		var in struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "session_id required")
			return
		}
		log, err := mgr.Log(in.SessionID)
		if err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.download", map[string]any{"session_id": in.SessionID, "log": log})
	case "session.subscribe":
		var in struct {
			SessionID string `json:"session_id"`
			AfterSeq  int64  `json:"after_seq"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SessionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "session_id required")
			return
		}
		ch, cleanup, err := mgr.Subscribe(ctx, in.SessionID, in.AfterSeq)
		if err != nil {
			s.writeSessionErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "session.subscribe", map[string]any{"session_id": in.SessionID})
		go func() {
			defer cleanup()
			for {
				select {
				case ev, ok := <-ch:
					if !ok {
						return
					}
					s.writeOK(ctx, c, writeMu, "", "session.event", toSessionEventDTO(ev))
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

// SkillItemDTO is the wire shape of one pickable skill or command.
type SkillItemDTO struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) dispatchSkills(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Skills == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "skills subsystem not configured")
		return
	}
	var in struct {
		Agent string `json:"agent"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.Agent == "" {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "agent required")
		return
	}
	cat, err := s.cfg.Skills.List(in.Agent)
	if err != nil {
		s.writeError(ctx, c, writeMu, f.ID, "bad_agent", err.Error())
		return
	}
	s.writeOK(ctx, c, writeMu, f.ID, "skills.list", map[string]any{
		"agent":    cat.Agent,
		"skills":   toSkillItemDTOs(cat.Skills),
		"commands": toSkillItemDTOs(cat.Commands),
	})
}

func toSkillItemDTOs(items []skills.Item) []SkillItemDTO {
	out := make([]SkillItemDTO, 0, len(items))
	for _, it := range items {
		out = append(out, SkillItemDTO{Name: it.Name, Description: it.Description})
	}
	return out
}

// ChangedFileDTO is the wire shape of one row in diff.status.
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
	mgr := s.cfg.Review
	switch f.Kind {
	case "diff.status":
		var in struct {
			ProjectID string `json:"project_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id required")
			return
		}
		files, err := mgr.Status(in.ProjectID)
		if err != nil {
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		out := make([]ChangedFileDTO, 0, len(files))
		for _, fl := range files {
			out = append(out, ChangedFileDTO{
				Path: fl.Path, OldPath: fl.OldPath, Group: string(fl.Group),
				Binary: fl.Binary, Revision: fl.Revision,
			})
		}
		s.writeOK(ctx, c, writeMu, f.ID, "diff.status", map[string]any{"files": out})
	case "diff.file":
		var in struct {
			ProjectID string `json:"project_id"`
			Path      string `json:"path"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" || in.Path == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id and path required")
			return
		}
		fp, err := mgr.File(in.ProjectID, in.Path)
		if err != nil {
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "diff.file", fp)
	case "diff.summarize":
		var in struct {
			ProjectID string `json:"project_id"`
			Path      string `json:"path"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" || in.Path == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id and path required")
			return
		}
		row, err := mgr.Summarize(in.ProjectID, in.Path)
		if err != nil {
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "diff.summarize", map[string]any{
			"path":       row.Path,
			"revision":   row.Revision,
			"summary":    row.Summary,
			"created_at": row.CreatedAt.Unix(),
		})
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
		tok, err := mgr.MintConfirmationToken(in.Action, in.ProjectID, in.Files, in.Comment)
		if err != nil {
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "auth.confirm", map[string]any{
			"confirmation_token": tok.Token,
			"action_hash":        tok.ActionHash,
			"expires_at":         tok.ExpiresAt.Unix(),
		})
	case "review.approve":
		s.dispatchReviewDecision(ctx, c, writeMu, f, mgr, "review.approve", true)
	case "review.reject":
		s.dispatchReviewDecision(ctx, c, writeMu, f, mgr, "review.reject", false)
	case "review.revise":
		s.dispatchReviewDecision(ctx, c, writeMu, f, mgr, "review.revise", false)
	case "audit.list":
		var in struct {
			Type      string `json:"type"`
			ProjectID string `json:"project_id"`
			Limit     int    `json:"limit"`
		}
		_ = json.Unmarshal(f.Payload, &in)
		entries, err := mgr.ListAudit(in.Type, in.ProjectID, in.Limit)
		if err != nil {
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		out := make([]AuditDTO, 0, len(entries))
		for _, e := range entries {
			out = append(out, AuditDTO{
				ID: e.ID, Type: e.Type, ProjectID: e.ProjectID, SessionID: e.SessionID,
				Actor: e.Actor, Summary: e.Summary, Data: e.Data, CreatedAt: e.CreatedAt.Unix(),
			})
		}
		s.writeOK(ctx, c, writeMu, f.ID, "audit.list", map[string]any{"entries": out})
	}
}

func (s *Server) dispatchReviewDecision(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame, mgr *review.Manager, action string, requireToken bool) {
	var in struct {
		ProjectID         string   `json:"project_id"`
		SessionID         string   `json:"session_id"`
		Files             []string `json:"files"`
		Comment           string   `json:"comment"`
		ConfirmationToken string   `json:"confirmation_token"`
	}
	if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" || len(in.Files) == 0 {
		s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id and files required")
		return
	}
	if requireToken {
		if err := mgr.ConsumeToken(in.ConfirmationToken, action, in.ProjectID, in.Files, in.Comment); err != nil {
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
	}
	var (
		ev    store.SessionEvent
		audit store.AuditEntry
		err   error
	)
	switch action {
	case "review.approve":
		ev, audit, err = mgr.Approve(in.ProjectID, in.SessionID, in.Files, in.Comment)
	case "review.reject":
		ev, audit, err = mgr.Reject(in.ProjectID, in.SessionID, in.Files, in.Comment)
	case "review.revise":
		ev, audit, err = mgr.Revise(in.ProjectID, in.SessionID, in.Files, in.Comment)
	}
	if err != nil {
		s.writeReviewErr(ctx, c, writeMu, f.ID, err)
		return
	}
	// Surface the new session event to live subscribers so the UI sees the
	// review decision immediately.
	if s.cfg.Sessions != nil && in.SessionID != "" && ev.Seq > 0 {
		s.cfg.Sessions.PublishExisting(ev)
	}
	s.writeOK(ctx, c, writeMu, f.ID, action, map[string]any{
		"audit_id":   audit.ID,
		"session_id": in.SessionID,
		"seq":        ev.Seq,
	})
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
	case errors.Is(err, review.ErrSessionMismatch):
		s.writeError(ctx, c, writeMu, id, "session_mismatch", err.Error())
	case errors.Is(err, review.ErrNotFound), errors.Is(err, projects.ErrNotFound), errors.Is(err, store.ErrNotFound):
		s.writeError(ctx, c, writeMu, id, "not_found", err.Error())
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
}

func (s *Server) dispatchGitHub(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.GitHub == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "github subsystem not configured")
		return
	}
	mgr := s.cfg.GitHub
	switch f.Kind {
	case "github.repo_list":
		var in struct {
			Account    string `json:"account"`
			Page       int    `json:"page"`
			PerPage    int    `json:"per_page"`
			Query      string `json:"query"`
			Visibility string `json:"visibility"`
			Owner      string `json:"owner"`
			OwnerType  string `json:"owner_type"`
		}
		_ = json.Unmarshal(f.Payload, &in)
		result, err := mgr.ListRepos(ctx, in.Account, gh.RepoListOptions{
			Page:       in.Page,
			PerPage:    in.PerPage,
			Query:      in.Query,
			Visibility: in.Visibility,
			Owner:      in.Owner,
			OwnerType:  in.OwnerType,
		})
		if err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, result)
	case "github.repo_import":
		var in struct {
			Account  string `json:"account"`
			FullName string `json:"full_name"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.FullName == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "full_name required")
			return
		}
		p, err := mgr.ImportRepo(ctx, in.Account, in.FullName)
		if err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, toDTO(p))
	case "github.commit":
		var in struct {
			ProjectID string   `json:"project_id"`
			Message   string   `json:"message"`
			Files     []string `json:"files"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" || in.Message == "" || len(in.Files) == 0 {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id, message and files required")
			return
		}
		sha, err := mgr.Commit(in.ProjectID, in.Message, in.Files)
		if err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, map[string]string{"sha": sha})
	case "github.push":
		var in struct {
			ProjectID         string   `json:"project_id"`
			Account           string   `json:"account"`
			ConfirmationToken string   `json:"confirmation_token"`
			Files             []string `json:"files"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id required")
			return
		}
		if err := mgr.Push(in.ProjectID, in.Account, in.ConfirmationToken, in.Files); err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, map[string]string{"project_id": in.ProjectID})
	case "github.pr_draft":
		var in struct {
			ProjectID string `json:"project_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id required")
			return
		}
		title, body, err := mgr.DraftPR(in.ProjectID)
		if err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, map[string]string{"title": title, "body": body})
	case "github.pr_create":
		var in struct {
			Account   string `json:"account"`
			ProjectID string `json:"project_id"`
			Repo      string `json:"repo"`
			Head      string `json:"head"`
			Base      string `json:"base"`
			Title     string `json:"title"`
			Body      string `json:"body"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Repo == "" || in.Head == "" || in.Base == "" || in.Title == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "repo, head, base and title required")
			return
		}
		pr, err := mgr.CreatePR(ctx, in.Account, in.Repo, in.Head, in.Base, in.Title, in.Body)
		if err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		if s.cfg.Memory != nil && in.ProjectID != "" {
			_, _ = s.cfg.Memory.AppendJournal(
				in.ProjectID,
				memory.JournalPR,
				fmt.Sprintf("Opened PR #%d: %s", pr.Number, pr.Title),
				pr.URL,
				s.cfg.Now(),
			)
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, pr)
	case "github.pr_list":
		var in struct {
			Account string `json:"account"`
			Repo    string `json:"repo"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Repo == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "repo required")
			return
		}
		prs, err := mgr.ListPRs(ctx, in.Account, in.Repo)
		if err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, map[string]any{"pull_requests": prs})
	case "github.revoke":
		var in struct {
			Account string `json:"account"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Account == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "account required")
			return
		}
		if err := mgr.Revoke(ctx, in.Account); err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, map[string]string{"account": in.Account})
	}
}

func (s *Server) writeGitHubErr(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id string, err error) {
	switch {
	case errors.Is(err, gh.ErrTokenMissing):
		s.writeError(ctx, c, writeMu, id, "github_reauth_required", err.Error())
	case errors.Is(err, gh.ErrUnapprovedChanges):
		s.writeError(ctx, c, writeMu, id, "unapproved_changes", err.Error())
	case errors.Is(err, gh.ErrConfirmationNeeded), errors.Is(err, review.ErrTokenInvalid):
		s.writeError(ctx, c, writeMu, id, "token_invalid", err.Error())
	case errors.Is(err, review.ErrTokenUsed):
		s.writeError(ctx, c, writeMu, id, "token_used", err.Error())
	case errors.Is(err, review.ErrTokenExpired):
		s.writeError(ctx, c, writeMu, id, "token_expired", err.Error())
	case errors.Is(err, review.ErrTokenMismatch):
		s.writeError(ctx, c, writeMu, id, "token_mismatch", err.Error())
	case errors.Is(err, projects.ErrNotFound), errors.Is(err, store.ErrNotFound):
		s.writeError(ctx, c, writeMu, id, "not_found", err.Error())
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
}

func (s *Server) writeSessionErr(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id string, err error) {
	switch {
	case errors.Is(err, sessions.ErrBadAgent):
		s.writeError(ctx, c, writeMu, id, "bad_agent", err.Error())
	case errors.Is(err, sessions.ErrBadMode):
		s.writeError(ctx, c, writeMu, id, "bad_mode", err.Error())
	case errors.Is(err, sessions.ErrAuthRequired):
		s.writeError(ctx, c, writeMu, id, "auth_required", err.Error())
	case errors.Is(err, sessions.ErrNotFound), errors.Is(err, projects.ErrNotFound):
		s.writeError(ctx, c, writeMu, id, "not_found", err.Error())
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
}

func (s *Server) writeProjectErr(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id string, err error) {
	switch {
	case errors.Is(err, projects.ErrDirtyTree):
		s.writeError(ctx, c, writeMu, id, "dirty_tree", err.Error())
	case errors.Is(err, projects.ErrNotFound):
		s.writeError(ctx, c, writeMu, id, "not_found", err.Error())
	case errors.Is(err, projects.ErrAuthRequired):
		s.writeError(ctx, c, writeMu, id, "auth_required", err.Error())
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
}

// PreviewDTO is the wire shape of one preview row.
type PreviewDTO struct {
	ID         string `json:"id"`
	ProjectID  string `json:"project_id"`
	Subdomain  string `json:"subdomain"`
	BaseDomain string `json:"base_domain"`
	URL        string `json:"url"`
	Command    string `json:"command"`
	Port       int    `json:"port"`
	Status     string `json:"status"`
	LastError  string `json:"last_error,omitempty"`
	StartedAt  int64  `json:"started_at"`
	EndedAt    *int64 `json:"ended_at,omitempty"`
}

func toPreviewDTO(p store.Preview) PreviewDTO {
	var ended *int64
	if p.EndedAt != nil {
		v := p.EndedAt.Unix()
		ended = &v
	}
	return PreviewDTO{
		ID: p.ID, ProjectID: p.ProjectID,
		Subdomain: p.Subdomain, BaseDomain: p.BaseDomain,
		URL: p.URL, Command: p.Command, Port: p.Port,
		Status: p.Status, LastError: p.LastError,
		StartedAt: p.StartedAt.Unix(), EndedAt: ended,
	}
}

func (s *Server) dispatchPreview(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Previews == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "previews subsystem not configured")
		return
	}
	mgr := s.cfg.Previews
	switch f.Kind {
	case "preview.get_domain":
		base, err := mgr.BaseDomain()
		if err != nil {
			s.writePreviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, map[string]any{
			"base_domain":  base,
			"cert_warmup":  int64(mgr.CertWarmup().Seconds()),
			"is_setup":     base != "",
			"sample_host":  sampleHost(base),
			"wildcard_dns": wildcardDNSHint(base),
		})
	case "preview.setup_domain":
		var in struct {
			BaseDomain string `json:"base_domain"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.BaseDomain == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "base_domain required")
			return
		}
		base, err := mgr.SetupDomain(in.BaseDomain)
		if err != nil {
			s.writePreviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, map[string]any{
			"base_domain":  base,
			"wildcard_dns": wildcardDNSHint(base),
		})
	case "preview.dns_validate":
		res, err := mgr.ValidateDNS(ctx)
		if err != nil {
			s.writePreviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, res)
	case "preview.start":
		var in struct {
			ProjectID string `json:"project_id"`
			Command   string `json:"command"`
			Port      int    `json:"port"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id required")
			return
		}
		row, err := mgr.Start(ctx, previews.StartRequest{
			ProjectID: in.ProjectID, Command: in.Command, Port: in.Port,
		})
		if err != nil {
			s.writePreviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, toPreviewDTO(row))
	case "preview.stop":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		if err := mgr.Stop(ctx, in.ID); err != nil {
			s.writePreviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		row, _ := mgr.Get(in.ID)
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, toPreviewDTO(row))
	case "preview.restart":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		row, err := mgr.Restart(ctx, in.ID)
		if err != nil {
			s.writePreviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, toPreviewDTO(row))
	case "preview.list":
		var in struct {
			ProjectID string `json:"project_id"`
		}
		_ = json.Unmarshal(f.Payload, &in)
		rows, err := mgr.List(in.ProjectID)
		if err != nil {
			s.writePreviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		out := make([]PreviewDTO, 0, len(rows))
		for _, r := range rows {
			out = append(out, toPreviewDTO(r))
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, map[string]any{"previews": out})
	case "preview.get":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		row, err := mgr.Get(in.ID)
		if err != nil {
			s.writePreviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, toPreviewDTO(row))
	case "preview.active":
		var in struct {
			ProjectID string `json:"project_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id required")
			return
		}
		row, err := mgr.Active(in.ProjectID)
		if err != nil {
			s.writePreviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, toPreviewDTO(row))
	}
}

func (s *Server) writePreviewErr(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id string, err error) {
	switch {
	case errors.Is(err, previews.ErrBaseDomainUnset):
		s.writeError(ctx, c, writeMu, id, "preview_no_domain", err.Error())
	case errors.Is(err, previews.ErrDNSValidationFailed):
		s.writeError(ctx, c, writeMu, id, "preview_dns_failed", err.Error())
	case errors.Is(err, previews.ErrAlreadyRunning):
		s.writeError(ctx, c, writeMu, id, "preview_already_running", err.Error())
	case errors.Is(err, previews.ErrPortUnknown):
		s.writeError(ctx, c, writeMu, id, "preview_port_unknown", err.Error())
	case errors.Is(err, projects.ErrNotFound), errors.Is(err, store.ErrNotFound):
		s.writeError(ctx, c, writeMu, id, "not_found", err.Error())
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
}

func sampleHost(base string) string {
	if base == "" {
		return ""
	}
	return "preview-abc123." + base
}

func wildcardDNSHint(base string) string {
	if base == "" {
		return ""
	}
	return "*." + base
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

func (s *Server) auditDockerLifecycle(id, action string, ok bool, summary string) store.AuditEntry {
	if s.cfg.Review == nil {
		return store.AuditEntry{}
	}
	status := "failed"
	if ok {
		status = "succeeded"
	}
	body, _ := json.Marshal(map[string]any{
		"container_id": id,
		"action":       action,
		"ok":           ok,
		"summary":      summary,
	})
	entry, _ := s.cfg.Review.LogAudit(store.AuditEntry{
		Type:      "docker.container.action",
		ProjectID: "docker",
		Actor:     "mobile",
		Summary:   fmt.Sprintf("docker %s %s for %s: %s", action, status, id, summary),
		Data:      string(body),
		CreatedAt: s.cfg.Now(),
	})
	return entry
}

func (s *Server) dispatchDocker(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Docker == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "docker subsystem not configured")
		return
	}
	switch f.Kind {
	case "docker.status":
		st := s.cfg.Docker.Status(ctx)
		s.writeOK(ctx, c, writeMu, f.ID, "docker.status", toDockerDTO(st))
	case "docker.container.list":
		containers, err := s.cfg.Docker.Containers(ctx)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "docker_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "docker.container.list", map[string]any{"containers": containers})
	case "docker.container.get":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		container, err := s.cfg.Docker.Container(ctx, in.ID)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "docker_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "docker.container.get", map[string]any{"container": container})
	case "docker.container.action":
		var in struct {
			ID                string `json:"id"`
			Action            string `json:"action"`
			ConfirmationToken string `json:"confirmation_token"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" || in.Action == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id and action required")
			return
		}
		action := docker.ContainerAction(in.Action)
		if !isAllowedDockerContainerAction(action) {
			s.auditDockerLifecycle(in.ID, in.Action, false, "unsupported action")
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "unsupported docker container action")
			return
		}
		if s.cfg.Review == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "confirmation subsystem not configured")
			return
		}
		tokenAction, projectID, files := dockerLifecycleTokenBinding(in.ID, action)
		if err := s.cfg.Review.ConsumeToken(in.ConfirmationToken, tokenAction, projectID, files, ""); err != nil {
			s.auditDockerLifecycle(in.ID, in.Action, false, err.Error())
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		if err := s.cfg.Docker.ContainerAction(ctx, in.ID, action); err != nil {
			s.auditDockerLifecycle(in.ID, in.Action, false, err.Error())
			s.writeError(ctx, c, writeMu, f.ID, "docker_error", err.Error())
			return
		}
		audit := s.auditDockerLifecycle(in.ID, in.Action, true, "ok")
		s.writeOK(ctx, c, writeMu, f.ID, "docker.container.action", map[string]any{
			"id":       in.ID,
			"action":   in.Action,
			"audit_id": audit.ID,
		})
	case "docker.container.logs":
		var in struct {
			ID   string `json:"id"`
			Tail int    `json:"tail"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		logs, err := s.cfg.Docker.Logs(ctx, in.ID, in.Tail)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "docker_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "docker.container.logs", map[string]any{"logs": logs})
	case "docker.container.logs_subscribe":
		var in struct {
			ID             string `json:"id"`
			SubscriptionID string `json:"subscription_id"`
			SinceTime      string `json:"since_time"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" || in.SubscriptionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id and subscription_id required")
			return
		}
		var since time.Time
		if in.SinceTime != "" {
			parsed, err := time.Parse(time.RFC3339Nano, in.SinceTime)
			if err != nil {
				s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "since_time must be RFC3339Nano")
				return
			}
			since = parsed
		}
		streamCtx, cancel := context.WithCancel(ctx)
		s.dockerLogMu.Lock()
		if previous := s.dockerLogCancels[in.SubscriptionID]; previous.cancel != nil {
			previous.cancel()
		}
		s.dockerLogNextGen++
		gen := s.dockerLogNextGen
		s.dockerLogCancels[in.SubscriptionID] = dockerLogCancel{gen: gen, cancel: cancel}
		s.dockerLogMu.Unlock()
		s.writeOK(ctx, c, writeMu, f.ID, "docker.container.logs_subscribe", map[string]any{
			"container_id":    in.ID,
			"subscription_id": in.SubscriptionID,
		})
		go func() {
			defer func() {
				s.dockerLogMu.Lock()
				if current := s.dockerLogCancels[in.SubscriptionID]; current.gen == gen {
					delete(s.dockerLogCancels, in.SubscriptionID)
				}
				s.dockerLogMu.Unlock()
				cancel()
			}()
			err := s.cfg.Docker.SubscribeLogs(streamCtx, in.ID, since, func(entry docker.LogEntry) {
				s.writeOK(ctx, c, writeMu, "", "docker.container.log_event", map[string]any{
					"subscription_id": in.SubscriptionID,
					"container_id":    entry.ContainerID,
					"stream":          entry.Stream,
					"timestamp":       entry.Timestamp,
					"line":            entry.Line,
				})
			})
			if err != nil {
				s.writeOK(ctx, c, writeMu, "", "docker.container.log_done", map[string]any{
					"subscription_id": in.SubscriptionID,
					"container_id":    in.ID,
					"ok":              false,
					"error":           err.Error(),
				})
				return
			}
			s.writeOK(ctx, c, writeMu, "", "docker.container.log_done", map[string]any{
				"subscription_id": in.SubscriptionID,
				"container_id":    in.ID,
				"ok":              true,
			})
		}()
	case "docker.container.logs_unsubscribe":
		var in struct {
			SubscriptionID string `json:"subscription_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SubscriptionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "subscription_id required")
			return
		}
		s.dockerLogMu.Lock()
		cancelEntry := s.dockerLogCancels[in.SubscriptionID]
		if cancelEntry.cancel != nil {
			cancelEntry.cancel()
			delete(s.dockerLogCancels, in.SubscriptionID)
		}
		s.dockerLogMu.Unlock()
		s.writeOK(ctx, c, writeMu, f.ID, "docker.container.logs_unsubscribe", map[string]any{
			"subscription_id": in.SubscriptionID,
			"cancelled":       cancelEntry.cancel != nil,
		})
	case "docker.container.stats":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		snap, err := s.cfg.Docker.Stats(ctx, in.ID)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "docker_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "docker.container.stats", map[string]any{"sample": snap})
	case "docker.container.stats_subscribe":
		var in struct {
			ID             string `json:"id"`
			SubscriptionID string `json:"subscription_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" || in.SubscriptionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id and subscription_id required")
			return
		}
		streamCtx, cancel := context.WithCancel(ctx)
		s.dockerStatsMu.Lock()
		if previous := s.dockerStatsCancels[in.SubscriptionID]; previous.cancel != nil {
			previous.cancel()
		}
		s.dockerStatsNextGen++
		gen := s.dockerStatsNextGen
		s.dockerStatsCancels[in.SubscriptionID] = dockerLogCancel{gen: gen, cancel: cancel}
		s.dockerStatsMu.Unlock()
		s.writeOK(ctx, c, writeMu, f.ID, "docker.container.stats_subscribe", map[string]any{
			"container_id":    in.ID,
			"subscription_id": in.SubscriptionID,
		})
		go func() {
			defer func() {
				s.dockerStatsMu.Lock()
				if current := s.dockerStatsCancels[in.SubscriptionID]; current.gen == gen {
					delete(s.dockerStatsCancels, in.SubscriptionID)
				}
				s.dockerStatsMu.Unlock()
				cancel()
			}()
			err := s.cfg.Docker.SubscribeStats(streamCtx, in.ID, func(snap docker.StatsSnapshot) {
				s.writeOK(ctx, c, writeMu, "", "docker.container.stats_event", map[string]any{
					"subscription_id": in.SubscriptionID,
					"sample":          snap,
				})
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				s.writeOK(ctx, c, writeMu, "", "docker.container.stats_done", map[string]any{
					"subscription_id": in.SubscriptionID,
					"container_id":    in.ID,
					"ok":              false,
					"error":           err.Error(),
				})
				return
			}
			s.writeOK(ctx, c, writeMu, "", "docker.container.stats_done", map[string]any{
				"subscription_id": in.SubscriptionID,
				"container_id":    in.ID,
				"ok":              true,
			})
		}()
	case "docker.container.stats_unsubscribe":
		var in struct {
			SubscriptionID string `json:"subscription_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SubscriptionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "subscription_id required")
			return
		}
		s.dockerStatsMu.Lock()
		cancelEntry := s.dockerStatsCancels[in.SubscriptionID]
		if cancelEntry.cancel != nil {
			cancelEntry.cancel()
			delete(s.dockerStatsCancels, in.SubscriptionID)
		}
		s.dockerStatsMu.Unlock()
		s.writeOK(ctx, c, writeMu, f.ID, "docker.container.stats_unsubscribe", map[string]any{
			"subscription_id": in.SubscriptionID,
			"cancelled":       cancelEntry.cancel != nil,
		})
	case "docker.image.list":
		images, err := s.cfg.Docker.Images(ctx)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "docker_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "docker.image.list", map[string]any{"images": images})
	case "docker.image.get":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		image, err := s.cfg.Docker.Image(ctx, in.ID)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "docker_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "docker.image.get", map[string]any{"image": image})
	case "docker.volume.list":
		volumes, err := s.cfg.Docker.Volumes(ctx)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "docker_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "docker.volume.list", map[string]any{"volumes": volumes})
	case "docker.network.list":
		networks, err := s.cfg.Docker.Networks(ctx)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "docker_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "docker.network.list", map[string]any{"networks": networks})
	case "docker.info":
		info, err := s.cfg.Docker.Info(ctx)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "docker_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "docker.info", map[string]any{"info": info})
	}
}

func (s *Server) dispatchInfra(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Infra == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "infra subsystem not configured")
		return
	}
	switch f.Kind {
	case "infra.metrics.sample":
		s.writeOK(ctx, c, writeMu, f.ID, "infra.metrics.sample", map[string]any{
			"sample": s.cfg.Infra.Sample(ctx),
		})
	case "infra.metrics.subscribe":
		var in struct {
			SubscriptionID string `json:"subscription_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SubscriptionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "subscription_id required")
			return
		}
		streamCtx, cancel := context.WithCancel(ctx)
		s.infraMetricsMu.Lock()
		if previous := s.infraMetricsCancels[in.SubscriptionID]; previous.cancel != nil {
			previous.cancel()
		}
		s.infraMetricsNextGen++
		gen := s.infraMetricsNextGen
		s.infraMetricsCancels[in.SubscriptionID] = dockerLogCancel{gen: gen, cancel: cancel}
		s.infraMetricsMu.Unlock()
		s.writeOK(ctx, c, writeMu, f.ID, "infra.metrics.subscribe", map[string]any{
			"subscription_id": in.SubscriptionID,
		})
		go func() {
			defer func() {
				s.infraMetricsMu.Lock()
				if current := s.infraMetricsCancels[in.SubscriptionID]; current.gen == gen {
					delete(s.infraMetricsCancels, in.SubscriptionID)
				}
				s.infraMetricsMu.Unlock()
				cancel()
			}()
			err := s.cfg.Infra.Subscribe(streamCtx, func(sample infra.HostMetrics) {
				s.writeOK(ctx, c, writeMu, "", "infra.metrics.event", map[string]any{
					"subscription_id": in.SubscriptionID,
					"sample":          sample,
				})
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				s.writeOK(ctx, c, writeMu, "", "infra.metrics.done", map[string]any{
					"subscription_id": in.SubscriptionID,
					"ok":              false,
					"error":           err.Error(),
				})
				return
			}
			s.writeOK(ctx, c, writeMu, "", "infra.metrics.done", map[string]any{
				"subscription_id": in.SubscriptionID,
				"ok":              true,
			})
		}()
	case "infra.metrics.unsubscribe":
		var in struct {
			SubscriptionID string `json:"subscription_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.SubscriptionID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "subscription_id required")
			return
		}
		s.infraMetricsMu.Lock()
		cancelEntry := s.infraMetricsCancels[in.SubscriptionID]
		if cancelEntry.cancel != nil {
			cancelEntry.cancel()
			delete(s.infraMetricsCancels, in.SubscriptionID)
		}
		s.infraMetricsMu.Unlock()
		s.writeOK(ctx, c, writeMu, f.ID, "infra.metrics.unsubscribe", map[string]any{
			"subscription_id": in.SubscriptionID,
			"cancelled":       cancelEntry.cancel != nil,
		})
	}
}

func serviceLifecycleTokenBinding(unit string, action systemd.Action) (string, string, []string) {
	return "infra.service.action." + string(action), "infra", []string{unit}
}

func systemRebootTokenBinding() (string, string, []string) {
	return "infra.system.reboot", "infra", nil
}

func (s *Server) auditSystemReboot(ok bool, summary string) store.AuditEntry {
	if s.cfg.Review == nil {
		return store.AuditEntry{}
	}
	status := "failed"
	if ok {
		status = "succeeded"
	}
	body, _ := json.Marshal(map[string]any{
		"ok":      ok,
		"summary": summary,
	})
	entry, _ := s.cfg.Review.LogAudit(store.AuditEntry{
		Type:      "infra.system.reboot",
		ProjectID: "infra",
		Actor:     "mobile",
		Summary:   fmt.Sprintf("host reboot %s: %s", status, summary),
		Data:      string(body),
		CreatedAt: s.cfg.Now(),
	})
	return entry
}

func (s *Server) auditServiceLifecycle(unit, action string, ok bool, summary string) store.AuditEntry {
	if s.cfg.Review == nil {
		return store.AuditEntry{}
	}
	status := "failed"
	if ok {
		status = "succeeded"
	}
	body, _ := json.Marshal(map[string]any{
		"unit":    unit,
		"action":  action,
		"ok":      ok,
		"summary": summary,
	})
	entry, _ := s.cfg.Review.LogAudit(store.AuditEntry{
		Type:      "infra.service.action",
		ProjectID: "infra",
		Actor:     "mobile",
		Summary:   fmt.Sprintf("systemd %s %s for %s: %s", action, status, unit, summary),
		Data:      string(body),
		CreatedAt: s.cfg.Now(),
	})
	return entry
}

func (s *Server) dispatchSystemd(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Systemd == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "systemd subsystem not configured")
		return
	}
	switch f.Kind {
	case "infra.service.list":
		st := s.cfg.Systemd.Status(ctx)
		if !st.Available {
			s.writeOK(ctx, c, writeMu, f.ID, "infra.service.list", map[string]any{
				"available":           false,
				"unavailable_reason":  st.UnavailableReason,
				"unavailable_message": st.UnavailableMessage,
				"units":               []systemd.Unit{},
			})
			return
		}
		units, err := s.cfg.Systemd.List(ctx)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "systemd_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.service.list", map[string]any{
			"available": true,
			"units":     units,
		})
	case "infra.service.get":
		var in struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Name == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "name required")
			return
		}
		st := s.cfg.Systemd.Status(ctx)
		if !st.Available {
			s.writeOK(ctx, c, writeMu, f.ID, "infra.service.get", map[string]any{
				"available":           false,
				"unavailable_reason":  st.UnavailableReason,
				"unavailable_message": st.UnavailableMessage,
			})
			return
		}
		detail, err := s.cfg.Systemd.Get(ctx, in.Name)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "systemd_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.service.get", map[string]any{
			"available": true,
			"unit":      detail,
		})
	case "infra.service.action":
		var in struct {
			Name              string `json:"name"`
			Action            string `json:"action"`
			ConfirmationToken string `json:"confirmation_token"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Name == "" || in.Action == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "name and action required")
			return
		}
		action := systemd.Action(in.Action)
		// Run the protected-unit guard BEFORE consuming the token so the
		// caller can't burn a token attempting to stop sshd.
		if s.cfg.Systemd.IsProtected(in.Name) && (action == systemd.ActionStop || action == systemd.ActionDisable) {
			audit := s.auditServiceLifecycle(in.Name, in.Action, false, "protected unit")
			s.writeError(ctx, c, writeMu, f.ID, "protected_unit", fmt.Sprintf("refused %s on protected unit %s", action, in.Name))
			_ = audit
			return
		}
		if s.cfg.Review == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "confirmation subsystem not configured")
			return
		}
		tokenAction, projectID, files := serviceLifecycleTokenBinding(in.Name, action)
		if err := s.cfg.Review.ConsumeToken(in.ConfirmationToken, tokenAction, projectID, files, ""); err != nil {
			s.auditServiceLifecycle(in.Name, in.Action, false, err.Error())
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		if err := s.cfg.Systemd.Action(ctx, in.Name, action); err != nil {
			s.auditServiceLifecycle(in.Name, in.Action, false, err.Error())
			var pe *systemd.ProtectedUnitError
			if errors.As(err, &pe) {
				s.writeError(ctx, c, writeMu, f.ID, "protected_unit", err.Error())
				return
			}
			if errors.Is(err, systemd.ErrUnsupportedAction) {
				s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
				return
			}
			s.writeError(ctx, c, writeMu, f.ID, "systemd_error", err.Error())
			return
		}
		audit := s.auditServiceLifecycle(in.Name, in.Action, true, "ok")
		s.writeOK(ctx, c, writeMu, f.ID, "infra.service.action", map[string]any{
			"name":     in.Name,
			"action":   in.Action,
			"audit_id": audit.ID,
		})
	case "infra.system.reboot":
		var in struct {
			ConfirmationToken string `json:"confirmation_token"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "invalid payload")
			return
		}
		if s.cfg.Review == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "confirmation subsystem not configured")
			return
		}
		tokenAction, projectID, files := systemRebootTokenBinding()
		if err := s.cfg.Review.ConsumeToken(in.ConfirmationToken, tokenAction, projectID, files, ""); err != nil {
			s.auditSystemReboot(false, err.Error())
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		if err := s.cfg.Systemd.Reboot(ctx); err != nil {
			s.auditSystemReboot(false, err.Error())
			s.writeError(ctx, c, writeMu, f.ID, "systemd_error", err.Error())
			return
		}
		audit := s.auditSystemReboot(true, "ok")
		// The OK frame may never reach the app since the host is going down;
		// the client treats a transport drop after sending as success.
		s.writeOK(ctx, c, writeMu, f.ID, "infra.system.reboot", map[string]any{
			"audit_id": audit.ID,
		})
	}
}

func webserverActionTokenBinding(id, action string) (string, string, []string) {
	return "infra.webserver.action." + action, "infra", []string{id}
}

func webserverKindFromID(id string) string {
	if i := strings.IndexByte(id, ':'); i > 0 {
		return id[:i]
	}
	return ""
}

func (s *Server) auditWebserverAction(id string, kind webserver.Kind, unit, action string, ok bool, summary string) store.AuditEntry {
	if s.cfg.Review == nil {
		return store.AuditEntry{}
	}
	status := "failed"
	if ok {
		status = "succeeded"
	}
	body, _ := json.Marshal(map[string]any{
		"id":      id,
		"kind":    kind,
		"unit":    unit,
		"action":  action,
		"ok":      ok,
		"summary": summary,
	})
	entry, _ := s.cfg.Review.LogAudit(store.AuditEntry{
		Type:      "infra.webserver.action",
		ProjectID: "infra",
		Actor:     "mobile",
		Summary:   fmt.Sprintf("webserver %s %s for %s (%s): %s", action, status, id, unit, summary),
		Data:      string(body),
		CreatedAt: s.cfg.Now(),
	})
	return entry
}

func (s *Server) dispatchWebserver(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Webservers == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "webserver subsystem not configured")
		return
	}
	switch f.Kind {
	case "infra.webserver.list":
		snap := s.cfg.Webservers.List(ctx)
		s.writeOK(ctx, c, writeMu, f.ID, "infra.webserver.list", map[string]any{
			"available":  snap.Available,
			"webservers": snap.Webservers,
			"warnings":   snap.Warnings,
		})
	case "infra.webserver.validate":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		res, err := s.cfg.Webservers.Validate(ctx, in.ID)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.webserver.validate", res)
	case "infra.webserver.action":
		var in struct {
			ID                string `json:"id"`
			Action            string `json:"action"`
			ConfirmationToken string `json:"confirmation_token"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" || in.Action == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id and action required")
			return
		}
		if in.Action != "reload" && in.Action != "restart" {
			s.auditWebserverAction(in.ID, webserver.Kind(webserverKindFromID(in.ID)), "", in.Action, false, "unsupported action")
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "unsupported webserver action")
			return
		}
		if s.cfg.Review == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "confirmation subsystem not configured")
			return
		}
		tokenAction, projectID, files := webserverActionTokenBinding(in.ID, in.Action)
		if err := s.cfg.Review.ConsumeToken(in.ConfirmationToken, tokenAction, projectID, files, ""); err != nil {
			s.auditWebserverAction(in.ID, webserver.Kind(webserverKindFromID(in.ID)), "", in.Action, false, err.Error())
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		inst, err := s.cfg.Webservers.Action(ctx, in.ID, in.Action)
		if err != nil {
			s.auditWebserverAction(in.ID, webserver.Kind(webserverKindFromID(in.ID)), inst.Unit, in.Action, false, err.Error())
			s.writeError(ctx, c, writeMu, f.ID, "webserver_error", err.Error())
			return
		}
		audit := s.auditWebserverAction(in.ID, inst.Kind, inst.Unit, in.Action, true, "ok")
		s.writeOK(ctx, c, writeMu, f.ID, "infra.webserver.action", map[string]any{
			"id":       in.ID,
			"action":   in.Action,
			"audit_id": audit.ID,
		})
	}
}

func processKillTokenBinding(pid int, startTimeTicks uint64, signal string) (string, string, []string) {
	if signal == "" {
		signal = agentprocess.SignalTerm
	}
	return "infra.process.kill." + signal, "infra", []string{fmt.Sprintf("pid:%d:start:%d", pid, startTimeTicks)}
}

func (s *Server) auditProcessKill(pid int, signal string, ok bool, summary string) store.AuditEntry {
	if s.cfg.Review == nil {
		return store.AuditEntry{}
	}
	if signal == "" {
		signal = agentprocess.SignalTerm
	}
	status := "failed"
	if ok {
		status = "succeeded"
	}
	body, _ := json.Marshal(map[string]any{
		"pid":     pid,
		"signal":  signal,
		"ok":      ok,
		"summary": summary,
	})
	entry, _ := s.cfg.Review.LogAudit(store.AuditEntry{
		Type:      "infra.process.kill",
		ProjectID: "infra",
		Actor:     "mobile",
		Summary:   fmt.Sprintf("process %s %s for pid %d: %s", signal, status, pid, summary),
		Data:      string(body),
		CreatedAt: s.cfg.Now(),
	})
	return entry
}

func (s *Server) dispatchProcess(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Processes == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "process subsystem not configured")
		return
	}
	switch f.Kind {
	case "infra.process.list":
		var in struct {
			Sort  string `json:"sort"`
			Limit int    `json:"limit"`
		}
		if len(f.Payload) > 0 {
			if err := json.Unmarshal(f.Payload, &in); err != nil {
				s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "invalid process list payload")
				return
			}
		}
		processes, err := s.cfg.Processes.List(ctx, in.Sort, in.Limit)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "process_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.process.list", map[string]any{"processes": processes})
	case "infra.process.kill":
		var in struct {
			PID               int    `json:"pid"`
			StartTimeTicks    uint64 `json:"start_time_ticks"`
			Signal            string `json:"signal"`
			ConfirmationToken string `json:"confirmation_token"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.PID <= 0 || in.StartTimeTicks == 0 {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "pid and start_time_ticks required")
			return
		}
		if in.Signal == "" {
			in.Signal = agentprocess.SignalTerm
		}
		// The protected-PID guard runs before token consumption or signalling.
		if reason, ok := s.cfg.Processes.IsProtected(ctx, in.PID); ok {
			s.auditProcessKill(in.PID, in.Signal, false, "protected pid")
			s.writeError(ctx, c, writeMu, f.ID, "protected_pid", fmt.Sprintf("refused %s on protected pid %d: %s", in.Signal, in.PID, reason))
			return
		}
		if s.cfg.Review == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "confirmation subsystem not configured")
			return
		}
		tokenAction, projectID, files := processKillTokenBinding(in.PID, in.StartTimeTicks, in.Signal)
		if err := s.cfg.Review.ConsumeToken(in.ConfirmationToken, tokenAction, projectID, files, ""); err != nil {
			s.auditProcessKill(in.PID, in.Signal, false, err.Error())
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		if err := s.cfg.Processes.Kill(ctx, in.PID, in.StartTimeTicks, in.Signal); err != nil {
			s.auditProcessKill(in.PID, in.Signal, false, err.Error())
			var pe *agentprocess.ProtectedPIDError
			if errors.As(err, &pe) {
				s.writeError(ctx, c, writeMu, f.ID, "protected_pid", err.Error())
				return
			}
			if errors.Is(err, agentprocess.ErrUnsupportedSignal) {
				s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
				return
			}
			if errors.Is(err, agentprocess.ErrIdentityMismatch) {
				s.writeError(ctx, c, writeMu, f.ID, "process_identity_mismatch", err.Error())
				return
			}
			s.writeError(ctx, c, writeMu, f.ID, "process_error", err.Error())
			return
		}
		audit := s.auditProcessKill(in.PID, in.Signal, true, "ok")
		s.writeOK(ctx, c, writeMu, f.ID, "infra.process.kill", map[string]any{
			"pid":      in.PID,
			"signal":   in.Signal,
			"audit_id": audit.ID,
		})
	}
}

func firewallRuleTokenBinding(verb string, rule firewall.Rule) (string, string, []string) {
	return "infra.firewall." + verb, "infra", []string{fmt.Sprintf("%s/%s/%d", rule.Action, rule.Protocol, rule.Port)}
}

func (s *Server) auditFirewallRule(verb string, rule firewall.Rule, ok bool, summary string) store.AuditEntry {
	if s.cfg.Review == nil {
		return store.AuditEntry{}
	}
	status := "failed"
	if ok {
		status = "succeeded"
	}
	body, _ := json.Marshal(map[string]any{
		"verb":    verb,
		"rule":    rule,
		"ok":      ok,
		"summary": summary,
	})
	entry, _ := s.cfg.Review.LogAudit(store.AuditEntry{
		Type:      "infra.firewall." + verb,
		ProjectID: "infra",
		Actor:     "mobile",
		Summary:   fmt.Sprintf("firewall %s %s for %s/%s/%d: %s", verb, status, rule.Action, rule.Protocol, rule.Port, summary),
		Data:      string(body),
		CreatedAt: s.cfg.Now(),
	})
	return entry
}

func (s *Server) dispatchFirewall(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Firewall == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "firewall subsystem not configured")
		return
	}
	switch f.Kind {
	case "infra.firewall.status":
		st, err := s.cfg.Firewall.Status(ctx)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "firewall_error", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.firewall.status", map[string]any{
			"backend":             string(st.Backend),
			"available":           st.Available,
			"unavailable_reason":  st.UnavailableReason,
			"unavailable_message": st.UnavailableMessage,
			"rules":               st.Rules,
			"sockets":             st.Sockets,
			"ssh_ports":           st.SSHPorts,
		})
	case "infra.firewall.rule_add", "infra.firewall.rule_remove":
		var in struct {
			Action            string `json:"action"`
			Protocol          string `json:"protocol"`
			Port              int    `json:"port"`
			Source            string `json:"source"`
			Comment           string `json:"comment"`
			ConfirmationToken string `json:"confirmation_token"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Port <= 0 {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "action, protocol, and port required")
			return
		}
		if in.Protocol == "" {
			in.Protocol = string(firewall.ProtoTCP)
		}
		rule := firewall.Rule{
			Action:   firewall.Action(in.Action),
			Protocol: firewall.Protocol(in.Protocol),
			Port:     in.Port,
			Source:   in.Source,
			Comment:  in.Comment,
		}
		verb := "rule_add"
		if f.Kind == "infra.firewall.rule_remove" {
			verb = "rule_remove"
		}
		if s.cfg.Review == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "confirmation subsystem not configured")
			return
		}
		tokenAction, projectID, files := firewallRuleTokenBinding(verb, rule)
		if err := s.cfg.Review.ConsumeToken(in.ConfirmationToken, tokenAction, projectID, files, ""); err != nil {
			s.auditFirewallRule(verb, rule, false, err.Error())
			s.writeReviewErr(ctx, c, writeMu, f.ID, err)
			return
		}
		var opErr error
		if verb == "rule_add" {
			opErr = s.cfg.Firewall.RuleAdd(ctx, rule)
		} else {
			opErr = s.cfg.Firewall.RuleRemove(ctx, rule)
		}
		if opErr != nil {
			s.auditFirewallRule(verb, rule, false, opErr.Error())
			var ale *firewall.AntiLockoutError
			if errors.As(opErr, &ale) {
				s.writeError(ctx, c, writeMu, f.ID, "anti_lockout", opErr.Error())
				return
			}
			if errors.Is(opErr, firewall.ErrReadOnly) {
				s.writeError(ctx, c, writeMu, f.ID, "firewall_read_only", opErr.Error())
				return
			}
			if errors.Is(opErr, firewall.ErrUnsupportedAction) {
				s.writeError(ctx, c, writeMu, f.ID, "bad_payload", opErr.Error())
				return
			}
			s.writeError(ctx, c, writeMu, f.ID, "firewall_error", opErr.Error())
			return
		}
		audit := s.auditFirewallRule(verb, rule, true, "ok")
		s.writeOK(ctx, c, writeMu, f.ID, "infra.firewall."+verb, map[string]any{
			"rule":     rule,
			"audit_id": audit.ID,
		})
	}
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
func (s *Server) dispatchInfraSnapshot(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	out := map[string]any{}
	if s.cfg.Infra != nil {
		out["metrics"] = s.cfg.Infra.Sample(ctx)
	} else {
		out["metrics"] = nil
	}
	if s.cfg.Systemd != nil {
		st := s.cfg.Systemd.Status(ctx)
		if st.Available {
			units, err := s.cfg.Systemd.List(ctx)
			if err == nil {
				out["services"] = map[string]any{"available": true, "units": units}
			} else {
				out["services"] = map[string]any{"available": true, "error": err.Error()}
			}
		} else {
			out["services"] = map[string]any{"available": false, "unavailable_reason": st.UnavailableReason}
		}
	} else {
		out["services"] = nil
	}
	if s.cfg.Processes != nil {
		procs, err := s.cfg.Processes.List(ctx, "cpu", 50)
		if err == nil {
			out["processes"] = procs
		} else {
			out["processes"] = map[string]any{"error": err.Error()}
		}
	} else {
		out["processes"] = nil
	}
	if s.cfg.Firewall != nil {
		st, err := s.cfg.Firewall.Status(ctx)
		if err == nil {
			out["firewall"] = st
		} else {
			out["firewall"] = map[string]any{"error": err.Error()}
		}
	} else {
		out["firewall"] = nil
	}
	s.writeOK(ctx, c, writeMu, f.ID, "infra.snapshot", out)
}

// proposalTokenBinding computes the (action, project_id, files) tuple a
// confirmation token must be bound to for the proposal to be approvable. It
// delegates to the same binding helpers the human-initiated flows use, so the
// AI-proposed path inherits the identical action_hash semantics — no token
// minted for a human action can be re-used for an AI proposal and vice versa.
func proposalTokenBinding(kind aiproposal.Kind, params map[string]any) (action, projectID string, files []string, err error) {
	switch kind {
	case aiproposal.KindServiceAction:
		name, _ := params["name"].(string)
		actStr, _ := params["action"].(string)
		if name == "" || actStr == "" {
			return "", "", nil, fmt.Errorf("name and action required")
		}
		a, p, f := serviceLifecycleTokenBinding(name, systemd.Action(actStr))
		return a, p, f, nil
	case aiproposal.KindProcessKill:
		pid := intFromParams(params["pid"])
		startTicks := uint64FromParams(params["start_time_ticks"])
		signal, _ := params["signal"].(string)
		if pid <= 0 || startTicks == 0 {
			return "", "", nil, fmt.Errorf("pid and start_time_ticks required")
		}
		a, p, f := processKillTokenBinding(pid, startTicks, signal)
		return a, p, f, nil
	case aiproposal.KindFirewallAdd, aiproposal.KindFirewallRemove:
		rule, rerr := ruleFromParams(params)
		if rerr != nil {
			return "", "", nil, rerr
		}
		verb := "rule_add"
		if kind == aiproposal.KindFirewallRemove {
			verb = "rule_remove"
		}
		a, p, f := firewallRuleTokenBinding(verb, rule)
		return a, p, f, nil
	}
	return "", "", nil, fmt.Errorf("unknown kind")
}

func intFromParams(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

func uint64FromParams(v any) uint64 {
	switch n := v.(type) {
	case float64:
		return uint64(n)
	case int:
		return uint64(n)
	case int64:
		return uint64(n)
	case uint64:
		return n
	}
	return 0
}

func ruleFromParams(params map[string]any) (firewall.Rule, error) {
	action, _ := params["action"].(string)
	proto, _ := params["protocol"].(string)
	port := intFromParams(params["port"])
	source, _ := params["source"].(string)
	comment, _ := params["comment"].(string)
	if port <= 0 {
		return firewall.Rule{}, fmt.Errorf("port required")
	}
	if proto == "" {
		proto = string(firewall.ProtoTCP)
	}
	return firewall.Rule{
		Action:   firewall.Action(action),
		Protocol: firewall.Protocol(proto),
		Port:     port,
		Source:   source,
		Comment:  comment,
	}, nil
}

// auditAIProposed appends an audit row for an AI-proposed action. The Actor
// field is fixed to "ai-proposed" so the audit log distinguishes machine-
// suggested side effects from human-initiated ones even when the underlying
// audit Type matches what a human action would produce.
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
	case "infra.proposal.create":
		var in struct {
			Kind      string         `json:"kind"`
			Params    map[string]any `json:"params"`
			Rationale string         `json:"rationale"`
			SessionID string         `json:"session_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Kind == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "kind required")
			return
		}
		action, projectID, files, err := proposalTokenBinding(aiproposal.Kind(in.Kind), in.Params)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		p, err := s.cfg.AIProposals.Create(aiproposal.Proposal{
			Kind:           aiproposal.Kind(in.Kind),
			Params:         in.Params,
			Rationale:      in.Rationale,
			SessionID:      in.SessionID,
			TokenAction:    action,
			TokenProjectID: projectID,
			TokenFiles:     files,
		})
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.proposal.create", map[string]any{"proposal": p})
	case "infra.proposal.list":
		s.writeOK(ctx, c, writeMu, f.ID, "infra.proposal.list", map[string]any{"proposals": s.cfg.AIProposals.List()})
	case "infra.proposal.get":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		p, err := s.cfg.AIProposals.Get(in.ID)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "not_found", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "infra.proposal.get", map[string]any{"proposal": p})
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

// dispatchAction surfaces the AI Action Plane orchestrator (Phase 1). It
// exposes the job ledger: submit a command, list jobs, get one job with its
// event trail, and cancel a running job. Phase 1 is read-only — submit kicks
// off a read-only planner and never mutates host state.
func (s *Server) dispatchAction(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Actions == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "actions subsystem not configured")
		return
	}
	switch f.Kind {
	case "action.submit":
		var in struct {
			Text   string `json:"text"`
			Worker string `json:"worker"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || strings.TrimSpace(in.Text) == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "text required")
			return
		}
		job, err := s.cfg.Actions.Submit(ctx, in.Text, actions.Worker(in.Worker))
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "action.submit", map[string]any{"job": job})
	case "action.list":
		jobs, err := s.cfg.Actions.List()
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "action.list", map[string]any{"jobs": jobs})
	case "action.get":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		job, err := s.cfg.Actions.Get(in.ID)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "not_found", "action job "+in.ID)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "action.get", map[string]any{"job": job})
	case "action.cancel":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		job, err := s.cfg.Actions.Cancel(in.ID)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "not_found", "action job "+in.ID)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "action.cancel", map[string]any{"job": job})
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
	}
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
			Token    string `json:"token"`
			Platform string `json:"platform"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Token == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "token required")
			return
		}
		err := s.cfg.PushDevices.PutPushDevice(store.PushDevice{
			Token: in.Token, Platform: in.Platform, LastSeenAt: s.cfg.Now(),
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
	}
}

// MemoryDTO is the wire shape of a project_memory row.
type MemoryDTO struct {
	ID              string `json:"id"`
	ProjectID       string `json:"project_id"`
	Kind            string `json:"kind"`
	Title           string `json:"title"`
	Body            string `json:"body"`
	CreatedAt       int64  `json:"created_at"`
	UpdatedAt       int64  `json:"updated_at"`
	SourceSessionID string `json:"source_session_id,omitempty"`
}

func toMemoryDTO(m store.ProjectMemory) MemoryDTO {
	return MemoryDTO{
		ID: m.ID, ProjectID: m.ProjectID, Kind: m.Kind, Title: m.Title, Body: m.Body,
		CreatedAt: m.CreatedAt.Unix(), UpdatedAt: m.UpdatedAt.Unix(), SourceSessionID: m.SourceSessionID,
	}
}

// MemoryProposalDTO is the wire shape of a pending AI-proposed memory entry.
type MemoryProposalDTO struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	SessionID string `json:"session_id,omitempty"`
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	CreatedAt int64  `json:"created_at"`
}

func toProposalDTO(p memory.Proposal) MemoryProposalDTO {
	return MemoryProposalDTO{
		ID: p.ID, ProjectID: p.ProjectID, SessionID: p.SessionID,
		Kind: p.Kind, Title: p.Title, Body: p.Body, CreatedAt: p.CreatedAt.Unix(),
	}
}

// JournalEntryDTO is the wire shape of a project_journal_entry row.
type JournalEntryDTO struct {
	ID         int64  `json:"id"`
	ProjectID  string `json:"project_id"`
	Kind       string `json:"kind"`
	Summary    string `json:"summary"`
	OccurredAt int64  `json:"occurred_at"`
	RefID      string `json:"ref_id,omitempty"`
}

func toJournalDTO(e store.JournalEntry) JournalEntryDTO {
	return JournalEntryDTO{
		ID: e.ID, ProjectID: e.ProjectID, Kind: e.Kind, Summary: e.Summary,
		OccurredAt: e.OccurredAt.Unix(), RefID: e.RefID,
	}
}

func (s *Server) dispatchMemory(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Memory == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "memory subsystem not configured")
		return
	}
	mgr := s.cfg.Memory
	switch f.Kind {
	case "memory.list":
		var in struct {
			ProjectID string `json:"project_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id required")
			return
		}
		rows, err := mgr.ListMemory(in.ProjectID)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		out := make([]MemoryDTO, 0, len(rows))
		for _, r := range rows {
			out = append(out, toMemoryDTO(r))
		}
		s.writeOK(ctx, c, writeMu, f.ID, "memory.list", map[string]any{"memories": out})
	case "memory.create":
		var in struct {
			ProjectID string `json:"project_id"`
			Kind      string `json:"kind"`
			Title     string `json:"title"`
			Body      string `json:"body"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		row, err := mgr.CreateMemory(in.ProjectID, in.Kind, in.Title, in.Body, "")
		if err != nil {
			s.writeMemoryErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "memory.create", toMemoryDTO(row))
	case "memory.update":
		var in struct {
			ID    string `json:"id"`
			Kind  string `json:"kind"`
			Title string `json:"title"`
			Body  string `json:"body"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		row, err := mgr.UpdateMemory(in.ID, in.Kind, in.Title, in.Body)
		if err != nil {
			s.writeMemoryErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "memory.update", toMemoryDTO(row))
	case "memory.delete":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		if err := mgr.DeleteMemory(in.ID); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "memory.delete", map[string]any{"id": in.ID})
	case "memory.proposals":
		var in struct {
			ProjectID string `json:"project_id"`
		}
		_ = json.Unmarshal(f.Payload, &in)
		props := mgr.ListProposals(in.ProjectID)
		out := make([]MemoryProposalDTO, 0, len(props))
		for _, p := range props {
			out = append(out, toProposalDTO(p))
		}
		s.writeOK(ctx, c, writeMu, f.ID, "memory.proposals", map[string]any{"proposals": out})
	case "memory.confirm":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		row, err := mgr.ConfirmProposal(in.ID)
		if err != nil {
			s.writeMemoryErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "memory.confirm", toMemoryDTO(row))
	case "memory.reject":
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id required")
			return
		}
		if err := mgr.RejectProposal(in.ID); err != nil {
			s.writeMemoryErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "memory.reject", map[string]any{"id": in.ID})
	case "journal.list":
		var in struct {
			ProjectID string `json:"project_id"`
			Kind      string `json:"kind"`
			Cursor    string `json:"cursor"`
			Limit     int    `json:"limit"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id required")
			return
		}
		entries, next, err := mgr.ListJournal(in.ProjectID, in.Kind, in.Cursor, in.Limit)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		out := make([]JournalEntryDTO, 0, len(entries))
		for _, e := range entries {
			out = append(out, toJournalDTO(e))
		}
		s.writeOK(ctx, c, writeMu, f.ID, "journal.list", map[string]any{"entries": out, "next_cursor": next})
	case "journal.export":
		var in struct {
			ProjectID string `json:"project_id"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id required")
			return
		}
		name := ""
		if s.cfg.Projects != nil {
			if p, err := s.cfg.Projects.Get(in.ProjectID); err == nil {
				name = p.Name
			}
		}
		md, err := mgr.ExportJournalMarkdown(in.ProjectID, name)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "journal.export", map[string]any{"markdown": md})
	}
}

func (s *Server) writeMemoryErr(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id string, err error) {
	switch {
	case errors.Is(err, memory.ErrNotFound), errors.Is(err, memory.ErrNoProposal):
		s.writeError(ctx, c, writeMu, id, "not_found", err.Error())
	case errors.Is(err, memory.ErrBadKind), errors.Is(err, memory.ErrEmptyTitle),
		errors.Is(err, memory.ErrNoProject), errors.Is(err, memory.ErrBadJournal):
		s.writeError(ctx, c, writeMu, id, "bad_payload", err.Error())
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
}

// ProviderCredentialDTO is the non-secret wire shape of a stored billing
// credential. The sealed API key is never serialized.
type ProviderCredentialDTO struct {
	Provider  string `json:"provider"`
	UpdatedAt int64  `json:"updated_at"`
}

// dispatchCost serves the cross-fleet cost rollup (cost.*) and the encrypted
// VPS billing credential surface (provider.*). cost.* needs only the Cost
// calculator; provider.* additionally needs the Billing manager.
func (s *Server) dispatchCost(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	switch f.Kind {
	case "cost.rollup":
		if s.cfg.Cost == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "cost subsystem not configured")
			return
		}
		var in struct {
			Month string `json:"month"`
		}
		_ = json.Unmarshal(f.Payload, &in)
		r, err := s.cfg.Cost.Rollup(in.Month)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "cost.rollup", r)
	case "cost.export":
		if s.cfg.Cost == nil {
			s.writeError(ctx, c, writeMu, f.ID, "unavailable", "cost subsystem not configured")
			return
		}
		var in struct {
			Month string `json:"month"`
		}
		_ = json.Unmarshal(f.Payload, &in)
		csv, err := s.cfg.Cost.ExportCSV(in.Month)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "cost.export", map[string]any{"csv": csv, "month": in.Month})
	case "provider.list", "provider.set", "provider.delete", "provider.refresh":
		s.dispatchProvider(ctx, c, writeMu, f)
	}
}

func (s *Server) dispatchProvider(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Billing == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "billing subsystem not configured")
		return
	}
	mgr := s.cfg.Billing
	switch f.Kind {
	case "provider.list":
		infos, err := mgr.ListCredentials()
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		out := make([]ProviderCredentialDTO, 0, len(infos))
		for _, ci := range infos {
			out = append(out, ProviderCredentialDTO{Provider: ci.Provider, UpdatedAt: ci.UpdatedAt.Unix()})
		}
		s.writeOK(ctx, c, writeMu, f.ID, "provider.list", map[string]any{
			"credentials": out,
			"supported":   billing.ProviderNames(),
		})
	case "provider.set":
		var in struct {
			Provider string `json:"provider"`
			APIKey   string `json:"api_key"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		if err := mgr.SetCredential(in.Provider, in.APIKey); err != nil {
			s.writeBillingErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "provider.set", map[string]any{"provider": in.Provider})
	case "provider.delete":
		var in struct {
			Provider string `json:"provider"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.Provider == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "provider required")
			return
		}
		if err := mgr.DeleteCredential(in.Provider); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "provider.delete", map[string]any{"provider": in.Provider})
	case "provider.refresh":
		rows, err := mgr.FetchAll(ctx)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		out := make([]ProviderCostDTO, 0, len(rows))
		for _, r := range rows {
			out = append(out, toProviderCostDTO(r))
		}
		s.writeOK(ctx, c, writeMu, f.ID, "provider.refresh", map[string]any{"infra": out})
	}
}

// ProviderCostDTO mirrors one normalized infra-cost row for the refresh reply.
type ProviderCostDTO struct {
	Provider    string `json:"provider"`
	Month       string `json:"month"`
	AmountCents int64  `json:"amount_cents"`
	Currency    string `json:"currency"`
	Status      string `json:"status"`
	Detail      string `json:"detail,omitempty"`
	FetchedAt   int64  `json:"fetched_at"`
}

func toProviderCostDTO(r store.InfraCost) ProviderCostDTO {
	return ProviderCostDTO{
		Provider: r.Provider, Month: r.Month, AmountCents: r.AmountCents,
		Currency: r.Currency, Status: r.Status, Detail: r.Detail, FetchedAt: r.FetchedAt.Unix(),
	}
}

func (s *Server) writeBillingErr(ctx context.Context, c *websocket.Conn, writeMu *connWriter, id string, err error) {
	switch {
	case errors.Is(err, billing.ErrBadProvider), errors.Is(err, billing.ErrNoKey):
		s.writeError(ctx, c, writeMu, id, "bad_payload", err.Error())
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
}

func (s *Server) dispatchInbox(ctx context.Context, c *websocket.Conn, writeMu *connWriter, f Frame) {
	if s.cfg.Inbox == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "inbox subsystem not configured")
		return
	}
	mgr := s.cfg.Inbox
	switch f.Kind {
	case "inbox.list":
		var in struct {
			Cursor string `json:"cursor"`
			Limit  int    `json:"limit"`
		}
		if len(f.Payload) > 0 {
			if err := json.Unmarshal(f.Payload, &in); err != nil {
				s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
				return
			}
		}
		res, err := mgr.List(ctx, in.Cursor, in.Limit)
		if err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "inbox.list", res)
	case "inbox.mark_read":
		var in struct {
			IDs []string `json:"ids"`
		}
		if len(f.Payload) > 0 {
			if err := json.Unmarshal(f.Payload, &in); err != nil {
				s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
				return
			}
		}
		if err := mgr.MarkRead(in.IDs); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "inbox.mark_read", map[string]any{"ok": true})
	case "inbox.resolve":
		var in struct {
			ID     string `json:"id"`
			Action string `json:"action"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", err.Error())
			return
		}
		if in.ID == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "id is required")
			return
		}
		if err := mgr.Resolve(in.ID, in.Action); err != nil {
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, "inbox.resolve", map[string]any{"ok": true})
	case "inbox.stream":
		ch, cleanup := mgr.Subscribe(ctx)
		s.writeOK(ctx, c, writeMu, f.ID, "inbox.stream", map[string]any{"subscribed": true})
		go func() {
			defer cleanup()
			for {
				select {
				case item, ok := <-ch:
					if !ok {
						return
					}
					s.writeOK(ctx, c, writeMu, "", "inbox.event", item)
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}
