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

	"github.com/rockclaver/claver/agent/internal/projects"
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
}

// Server is the agent's control-plane server.
type Server struct {
	cfg     Config
	startAt time.Time
}

// New constructs a Server. It does not bind any sockets.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{cfg: cfg, startAt: cfg.Now()}
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
		s.dispatch(ctx, c, &writeMu, f)
	}
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
			s.writeError(ctx, c, writeMu, f.ID, "internal", err.Error())
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
	default:
		s.writeError(ctx, c, writeMu, id, "internal", err.Error())
	}
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
