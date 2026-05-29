// Package store is the agent's State Store. Phase 3 introduces the projects
// table; later phases extend the schema for sessions, previews, github tokens,
// audit. Schema changes go through this single module.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Project is the persisted row for a project workspace.
type Project struct {
	ID        string
	Name      string
	RemoteURL string
	CreatedAt time.Time
}

// Session is a persisted AI-agent pane bound to one project workspace.
type Session struct {
	ID           string
	ProjectID    string
	Agent        string
	StartedAt    time.Time
	EndedAt      *time.Time
	InputTokens  int
	OutputTokens int
}

// SessionEvent is an append-only terminal or lifecycle event for a session.
type SessionEvent struct {
	SessionID string
	Seq       int64
	Type      string
	Data      string
	CreatedAt time.Time
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps a SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path and applies migrations.
func Open(path string) (*Store, error) {
	if path != ":memory:" {
		path = filepath.Clean(path)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS projects (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL,
	remote_url  TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	id            TEXT PRIMARY KEY,
	project_id    TEXT NOT NULL,
	agent         TEXT NOT NULL,
	started_at    INTEGER NOT NULL,
	ended_at      INTEGER,
	input_tokens  INTEGER NOT NULL DEFAULT 0,
	output_tokens INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS session_events (
	session_id TEXT NOT NULL,
	seq        INTEGER NOT NULL,
	type       TEXT NOT NULL,
	data       TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY(session_id, seq),
	FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
`)
	return err
}

// CreateProject inserts a new project row. The ID must be unique.
func (s *Store) CreateProject(p Project) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO projects (id, name, remote_url, created_at) VALUES (?, ?, ?, ?)`,
		p.ID, p.Name, p.RemoteURL, p.CreatedAt.Unix(),
	)
	return err
}

// GetProject loads a project by ID.
func (s *Store) GetProject(id string) (Project, error) {
	row := s.db.QueryRow(
		`SELECT id, name, remote_url, created_at FROM projects WHERE id = ?`, id,
	)
	var p Project
	var ts int64
	if err := row.Scan(&p.ID, &p.Name, &p.RemoteURL, &ts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Project{}, fmt.Errorf("project %s: %w", id, ErrNotFound)
		}
		return Project{}, err
	}
	p.CreatedAt = time.Unix(ts, 0)
	return p, nil
}

// ListProjects returns all projects ordered by creation time.
func (s *Store) ListProjects() ([]Project, error) {
	rows, err := s.db.Query(
		`SELECT id, name, remote_url, created_at FROM projects ORDER BY created_at ASC, id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Project, 0)
	for rows.Next() {
		var p Project
		var ts int64
		if err := rows.Scan(&p.ID, &p.Name, &p.RemoteURL, &ts); err != nil {
			return nil, err
		}
		p.CreatedAt = time.Unix(ts, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteProject removes a project row. Missing rows are not an error.
func (s *Store) DeleteProject(id string) error {
	_, err := s.db.Exec(`DELETE FROM projects WHERE id = ?`, id)
	return err
}

// CreateSession inserts a new active session row.
func (s *Store) CreateSession(sess Session) error {
	if sess.StartedAt.IsZero() {
		sess.StartedAt = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO sessions (id, project_id, agent, started_at, ended_at, input_tokens, output_tokens)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.ProjectID, sess.Agent, sess.StartedAt.Unix(), nullableUnix(sess.EndedAt),
		sess.InputTokens, sess.OutputTokens,
	)
	return err
}

// GetSession loads a session by ID.
func (s *Store) GetSession(id string) (Session, error) {
	row := s.db.QueryRow(
		`SELECT id, project_id, agent, started_at, ended_at, input_tokens, output_tokens
		 FROM sessions WHERE id = ?`, id,
	)
	var sess Session
	var started int64
	var ended sql.NullInt64
	if err := row.Scan(&sess.ID, &sess.ProjectID, &sess.Agent, &started, &ended, &sess.InputTokens, &sess.OutputTokens); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, fmt.Errorf("session %s: %w", id, ErrNotFound)
		}
		return Session{}, err
	}
	sess.StartedAt = time.Unix(started, 0)
	if ended.Valid {
		t := time.Unix(ended.Int64, 0)
		sess.EndedAt = &t
	}
	return sess, nil
}

// ListSessions returns sessions ordered newest first.
func (s *Store) ListSessions(projectID string) ([]Session, error) {
	rows, err := s.db.Query(
		`SELECT id, project_id, agent, started_at, ended_at, input_tokens, output_tokens
		 FROM sessions
		 WHERE (? = '' OR project_id = ?)
		 ORDER BY started_at DESC, id DESC`, projectID, projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Session, 0)
	for rows.Next() {
		var sess Session
		var started int64
		var ended sql.NullInt64
		if err := rows.Scan(&sess.ID, &sess.ProjectID, &sess.Agent, &started, &ended, &sess.InputTokens, &sess.OutputTokens); err != nil {
			return nil, err
		}
		sess.StartedAt = time.Unix(started, 0)
		if ended.Valid {
			t := time.Unix(ended.Int64, 0)
			sess.EndedAt = &t
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// ActiveSessions returns sessions that have not been stopped.
func (s *Store) ActiveSessions() ([]Session, error) {
	rows, err := s.db.Query(
		`SELECT id, project_id, agent, started_at, ended_at, input_tokens, output_tokens
		 FROM sessions WHERE ended_at IS NULL ORDER BY started_at ASC, id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Session, 0)
	for rows.Next() {
		var sess Session
		var started int64
		var ended sql.NullInt64
		if err := rows.Scan(&sess.ID, &sess.ProjectID, &sess.Agent, &started, &ended, &sess.InputTokens, &sess.OutputTokens); err != nil {
			return nil, err
		}
		sess.StartedAt = time.Unix(started, 0)
		if ended.Valid {
			t := time.Unix(ended.Int64, 0)
			sess.EndedAt = &t
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// EndSession marks a session stopped without deleting its log.
func (s *Store) EndSession(id string, endedAt time.Time) error {
	_, err := s.db.Exec(`UPDATE sessions SET ended_at = ? WHERE id = ?`, endedAt.Unix(), id)
	return err
}

// UpdateSessionUsage stores parsed agent token usage.
func (s *Store) UpdateSessionUsage(id string, inputTokens, outputTokens int) error {
	_, err := s.db.Exec(
		`UPDATE sessions SET input_tokens = ?, output_tokens = ? WHERE id = ?`,
		inputTokens, outputTokens, id,
	)
	return err
}

// AppendSessionEvent appends an event and assigns the next sequence number.
func (s *Store) AppendSessionEvent(event SessionEvent) (SessionEvent, error) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return SessionEvent{}, err
	}
	defer tx.Rollback()
	var next sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(seq) + 1 FROM session_events WHERE session_id = ?`, event.SessionID).Scan(&next); err != nil {
		return SessionEvent{}, err
	}
	if next.Valid {
		event.Seq = next.Int64
	} else {
		event.Seq = 1
	}
	if _, err := tx.Exec(
		`INSERT INTO session_events (session_id, seq, type, data, created_at) VALUES (?, ?, ?, ?, ?)`,
		event.SessionID, event.Seq, event.Type, event.Data, event.CreatedAt.Unix(),
	); err != nil {
		return SessionEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return SessionEvent{}, err
	}
	return event, nil
}

// SessionEventsAfter returns events with seq > afterSeq in ascending order.
func (s *Store) SessionEventsAfter(sessionID string, afterSeq int64) ([]SessionEvent, error) {
	rows, err := s.db.Query(
		`SELECT session_id, seq, type, data, created_at
		 FROM session_events
		 WHERE session_id = ? AND seq > ?
		 ORDER BY seq ASC`, sessionID, afterSeq,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SessionEvent, 0)
	for rows.Next() {
		var ev SessionEvent
		var created int64
		if err := rows.Scan(&ev.SessionID, &ev.Seq, &ev.Type, &ev.Data, &created); err != nil {
			return nil, err
		}
		ev.CreatedAt = time.Unix(created, 0)
		out = append(out, ev)
	}
	return out, rows.Err()
}

func nullableUnix(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Unix()
}
