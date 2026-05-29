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

// AuditEntry is one row in the agent's append-only audit log.
type AuditEntry struct {
	ID        int64
	Type      string
	ProjectID string
	SessionID string
	Actor     string
	Summary   string
	Data      string
	CreatedAt time.Time
}

// ConfirmationToken is a single-use, action-bound credential minted after a
// biometric prompt on the mobile client. The agent verifies that a token has
// not been consumed, has not expired, and that its bound action_hash matches
// the action being attempted before performing any state-changing call that
// requires confirmation (review.approve, push.*, commit.*).
type ConfirmationToken struct {
	Token      string
	ActionHash string
	ProjectID  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UsedAt     *time.Time
}

// DiffSummary caches an AI-generated description of one file's changes at a
// specific revision (typically the working-tree blob hash). Cached so that
// repeated `diff.summarize` calls for the same content do not re-invoke the
// agent.
type DiffSummary struct {
	ProjectID string
	Path      string
	Revision  string
	Summary   string
	CreatedAt time.Time
}

// GitHubToken stores the encrypted OAuth access token material for one agent.
// CiphertextPath points at the on-disk encrypted blob; token plaintext never
// lives in SQLite.
type GitHubToken struct {
	AccountLogin   string
	CiphertextPath string
	CreatedAt      time.Time
	UpdatedAt      time.Time
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

CREATE TABLE IF NOT EXISTS audit (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	type       TEXT NOT NULL,
	project_id TEXT NOT NULL DEFAULT '',
	session_id TEXT NOT NULL DEFAULT '',
	actor      TEXT NOT NULL DEFAULT '',
	summary    TEXT NOT NULL DEFAULT '',
	data       TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_created_idx ON audit(created_at DESC);
CREATE INDEX IF NOT EXISTS audit_type_idx ON audit(type);
CREATE INDEX IF NOT EXISTS audit_project_idx ON audit(project_id);

CREATE TABLE IF NOT EXISTS confirmation_tokens (
	token       TEXT PRIMARY KEY,
	action_hash TEXT NOT NULL,
	project_id  TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	used_at     INTEGER
);

CREATE TABLE IF NOT EXISTS diff_summaries (
	project_id TEXT NOT NULL,
	path       TEXT NOT NULL,
	revision   TEXT NOT NULL,
	summary    TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY(project_id, path, revision)
);

CREATE TABLE IF NOT EXISTS github_tokens (
	account_login   TEXT PRIMARY KEY,
	ciphertext_path TEXT NOT NULL,
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL
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

// AppendAudit inserts an audit row, assigns its rowid, and returns it.
func (s *Store) AppendAudit(e AuditEntry) (AuditEntry, error) {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	res, err := s.db.Exec(
		`INSERT INTO audit (type, project_id, session_id, actor, summary, data, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Type, e.ProjectID, e.SessionID, e.Actor, e.Summary, e.Data, e.CreatedAt.Unix(),
	)
	if err != nil {
		return AuditEntry{}, err
	}
	e.ID, _ = res.LastInsertId()
	return e, nil
}

// ListAudit returns the most recent audit rows matching the filter. An empty
// filter field means "any". Limit is clamped to [1, 500].
func (s *Store) ListAudit(filterType, projectID string, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.Query(
		`SELECT id, type, project_id, session_id, actor, summary, data, created_at
		 FROM audit
		 WHERE (? = '' OR type = ?) AND (? = '' OR project_id = ?)
		 ORDER BY created_at DESC, id DESC
		 LIMIT ?`,
		filterType, filterType, projectID, projectID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditEntry, 0)
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Type, &e.ProjectID, &e.SessionID, &e.Actor, &e.Summary, &e.Data, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CreateConfirmationToken stores a freshly minted token. Returns an error if
// the token already exists.
func (s *Store) CreateConfirmationToken(tok ConfirmationToken) error {
	if tok.CreatedAt.IsZero() {
		tok.CreatedAt = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO confirmation_tokens (token, action_hash, project_id, created_at, expires_at, used_at)
		 VALUES (?, ?, ?, ?, ?, NULL)`,
		tok.Token, tok.ActionHash, tok.ProjectID, tok.CreatedAt.Unix(), tok.ExpiresAt.Unix(),
	)
	return err
}

// GetConfirmationToken loads a token by its opaque ID.
func (s *Store) GetConfirmationToken(token string) (ConfirmationToken, error) {
	row := s.db.QueryRow(
		`SELECT token, action_hash, project_id, created_at, expires_at, used_at
		 FROM confirmation_tokens WHERE token = ?`, token,
	)
	var t ConfirmationToken
	var created, expires int64
	var used sql.NullInt64
	if err := row.Scan(&t.Token, &t.ActionHash, &t.ProjectID, &created, &expires, &used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ConfirmationToken{}, fmt.Errorf("confirmation_token: %w", ErrNotFound)
		}
		return ConfirmationToken{}, err
	}
	t.CreatedAt = time.Unix(created, 0)
	t.ExpiresAt = time.Unix(expires, 0)
	if used.Valid {
		u := time.Unix(used.Int64, 0)
		t.UsedAt = &u
	}
	return t, nil
}

// MarkConfirmationTokenUsed atomically flips the used_at column from NULL to
// `at`. Returns true if the update succeeded (token had not been used yet).
func (s *Store) MarkConfirmationTokenUsed(token string, at time.Time) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE confirmation_tokens SET used_at = ? WHERE token = ? AND used_at IS NULL`,
		at.Unix(), token,
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// GetDiffSummary loads a cached diff summary, if any.
func (s *Store) GetDiffSummary(projectID, path, revision string) (DiffSummary, error) {
	row := s.db.QueryRow(
		`SELECT project_id, path, revision, summary, created_at
		 FROM diff_summaries WHERE project_id = ? AND path = ? AND revision = ?`,
		projectID, path, revision,
	)
	var d DiffSummary
	var ts int64
	if err := row.Scan(&d.ProjectID, &d.Path, &d.Revision, &d.Summary, &ts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DiffSummary{}, fmt.Errorf("diff_summary: %w", ErrNotFound)
		}
		return DiffSummary{}, err
	}
	d.CreatedAt = time.Unix(ts, 0)
	return d, nil
}

// PutDiffSummary upserts a diff summary cache row.
func (s *Store) PutDiffSummary(d DiffSummary) error {
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO diff_summaries (project_id, path, revision, summary, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(project_id, path, revision) DO UPDATE SET summary = excluded.summary`,
		d.ProjectID, d.Path, d.Revision, d.Summary, d.CreatedAt.Unix(),
	)
	return err
}

// PutGitHubToken upserts the encrypted token pointer for the authenticated
// GitHub account.
func (s *Store) PutGitHubToken(t GitHubToken) error {
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	if t.UpdatedAt.IsZero() {
		t.UpdatedAt = now
	}
	_, err := s.db.Exec(
		`INSERT INTO github_tokens (account_login, ciphertext_path, created_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(account_login) DO UPDATE SET
		   ciphertext_path = excluded.ciphertext_path,
		   updated_at = excluded.updated_at`,
		t.AccountLogin, t.CiphertextPath, t.CreatedAt.Unix(), t.UpdatedAt.Unix(),
	)
	return err
}

// GetGitHubToken loads the token pointer for one GitHub account.
func (s *Store) GetGitHubToken(accountLogin string) (GitHubToken, error) {
	row := s.db.QueryRow(
		`SELECT account_login, ciphertext_path, created_at, updated_at
		 FROM github_tokens WHERE account_login = ?`, accountLogin,
	)
	var t GitHubToken
	var created, updated int64
	if err := row.Scan(&t.AccountLogin, &t.CiphertextPath, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GitHubToken{}, fmt.Errorf("github_token: %w", ErrNotFound)
		}
		return GitHubToken{}, err
	}
	t.CreatedAt = time.Unix(created, 0)
	t.UpdatedAt = time.Unix(updated, 0)
	return t, nil
}

// ListGitHubTokens returns all stored token pointers.
func (s *Store) ListGitHubTokens() ([]GitHubToken, error) {
	rows, err := s.db.Query(
		`SELECT account_login, ciphertext_path, created_at, updated_at
		 FROM github_tokens ORDER BY account_login ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GitHubToken
	for rows.Next() {
		var t GitHubToken
		var created, updated int64
		if err := rows.Scan(&t.AccountLogin, &t.CiphertextPath, &created, &updated); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(created, 0)
		t.UpdatedAt = time.Unix(updated, 0)
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteGitHubToken removes one token pointer.
func (s *Store) DeleteGitHubToken(accountLogin string) error {
	_, err := s.db.Exec(`DELETE FROM github_tokens WHERE account_login = ?`, accountLogin)
	return err
}

func nullableUnix(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Unix()
}
