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
	"sync"
	"time"

	"nhooyr.io/websocket"

	gh "github.com/rockclaver/claver/agent/internal/github"
	"github.com/rockclaver/claver/agent/internal/previews"
	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/review"
	"github.com/rockclaver/claver/agent/internal/sessions"
	"github.com/rockclaver/claver/agent/internal/store"
	"github.com/rockclaver/claver/agent/internal/version"
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
	// Review, when non-nil, enables the diff.*, review.*, auth.confirm,
	// and audit.list kinds.
	Review *review.Manager
	// GitHub, when non-nil, enables github.* kinds.
	GitHub *gh.Manager
	// Previews, when non-nil, enables preview.* kinds.
	Previews *previews.Manager
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
		cfg:     cfg,
		startAt: cfg.Now(),
		seen:    newIDSet(1024, replayWindow, cfg.Now),
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

	ctx := r.Context()
	var writeMu sync.Mutex
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
			s.writeError(ctx, c, &writeMu, "", "bad_frame", err.Error())
			continue
		}
		if f.ID != "" && s.seen.add(f.ID) {
			s.writeOK(ctx, c, &writeMu, f.ID, f.Kind, map[string]any{"replay": true})
			continue
		}
		s.dispatch(ctx, c, &writeMu, f)
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

func (s *Server) dispatch(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, f Frame) {
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
		"project.branch_create",
		"project.branch_switch",
		"project.delete":
		s.dispatchProject(ctx, c, writeMu, f)
	case "session.start",
		"session.prompt",
		"session.interrupt",
		"session.stop",
		"session.list",
		"session.subscribe",
		"session.download":
		s.dispatchSession(ctx, c, writeMu, f)
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
	case "github.device_start",
		"github.device_poll",
		"github.repo_list",
		"github.repo_import",
		"github.commit",
		"github.push",
		"github.pr_draft",
		"github.pr_create",
		"github.pr_list",
		"github.revoke":
		s.dispatchGitHub(ctx, c, writeMu, f)
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
		ID: sess.ID, ProjectID: sess.ProjectID, Agent: sess.Agent,
		StartedAt: sess.StartedAt.Unix(), EndedAt: ended,
		InputTokens: sess.InputTokens, OutputTokens: sess.OutputTokens,
	}
}

func toSessionEventDTO(ev store.SessionEvent) SessionEventDTO {
	return SessionEventDTO{SessionID: ev.SessionID, Seq: ev.Seq, Type: ev.Type, Data: ev.Data, CreatedAt: ev.CreatedAt.Unix()}
}

func (s *Server) dispatchProject(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, f Frame) {
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

func (s *Server) dispatchSession(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, f Frame) {
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
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.ProjectID == "" || in.Agent == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "project_id and agent required")
			return
		}
		sess, err := mgr.Start(ctx, in.ProjectID, in.Agent)
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

func (s *Server) dispatchReview(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, f Frame) {
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

func (s *Server) dispatchReviewDecision(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, f Frame, mgr *review.Manager, action string, requireToken bool) {
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

func (s *Server) writeReviewErr(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, id string, err error) {
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

func (s *Server) dispatchGitHub(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, f Frame) {
	if s.cfg.GitHub == nil {
		s.writeError(ctx, c, writeMu, f.ID, "unavailable", "github subsystem not configured")
		return
	}
	mgr := s.cfg.GitHub
	switch f.Kind {
	case "github.device_start":
		out, err := mgr.StartDeviceFlow(ctx)
		if err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, out)
	case "github.device_poll":
		var in struct {
			DeviceCode string `json:"device_code"`
		}
		if err := json.Unmarshal(f.Payload, &in); err != nil || in.DeviceCode == "" {
			s.writeError(ctx, c, writeMu, f.ID, "bad_payload", "device_code required")
			return
		}
		out, err := mgr.PollDeviceFlow(ctx, in.DeviceCode)
		if err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, out)
	case "github.repo_list":
		var in struct {
			Account string `json:"account"`
			Page    int    `json:"page"`
			PerPage int    `json:"per_page"`
		}
		_ = json.Unmarshal(f.Payload, &in)
		repos, hasNext, err := mgr.ListRepos(ctx, in.Account, in.Page, in.PerPage)
		if err != nil {
			s.writeGitHubErr(ctx, c, writeMu, f.ID, err)
			return
		}
		s.writeOK(ctx, c, writeMu, f.ID, f.Kind, map[string]any{"repos": repos, "has_next": hasNext})
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
			Account string `json:"account"`
			Repo    string `json:"repo"`
			Head    string `json:"head"`
			Base    string `json:"base"`
			Title   string `json:"title"`
			Body    string `json:"body"`
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

func (s *Server) writeGitHubErr(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, id string, err error) {
	switch {
	case errors.Is(err, gh.ErrAuthPending):
		s.writeError(ctx, c, writeMu, id, "github_pending", err.Error())
	case errors.Is(err, gh.ErrSlowDown):
		s.writeError(ctx, c, writeMu, id, "github_slow_down", err.Error())
	case errors.Is(err, gh.ErrExpiredDeviceCode):
		s.writeError(ctx, c, writeMu, id, "github_device_expired", err.Error())
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

func (s *Server) writeSessionErr(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, id string, err error) {
	switch {
	case errors.Is(err, sessions.ErrBadAgent):
		s.writeError(ctx, c, writeMu, id, "bad_agent", err.Error())
	case errors.Is(err, sessions.ErrNotFound), errors.Is(err, projects.ErrNotFound):
		s.writeError(ctx, c, writeMu, id, "not_found", err.Error())
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
}

func (s *Server) writeProjectErr(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, id string, err error) {
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

func (s *Server) dispatchPreview(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, f Frame) {
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

func (s *Server) writePreviewErr(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, id string, err error) {
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

func (s *Server) writeOK(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, id, kind string, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		s.writeError(ctx, c, writeMu, id, "marshal_error", err.Error())
		return
	}
	out, _ := json.Marshal(Frame{ID: id, Kind: kind, Payload: raw})
	writeMu.Lock()
	defer writeMu.Unlock()
	_ = c.Write(ctx, websocket.MessageText, out)
}

func (s *Server) writeError(ctx context.Context, c *websocket.Conn, writeMu *sync.Mutex, id, kind, msg string) {
	raw, _ := json.Marshal(map[string]string{"error": msg})
	out, _ := json.Marshal(Frame{ID: id, Kind: "error." + kind, Payload: raw})
	writeMu.Lock()
	defer writeMu.Unlock()
	_ = c.Write(ctx, websocket.MessageText, out)
}
