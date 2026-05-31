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

// Preview is the persisted record of a per-project dev-server preview.
// One project may have at most one active preview at a time. Inactive rows
// are retained so the UI can show preview history.
type Preview struct {
	ID         string
	ProjectID  string
	Subdomain  string
	BaseDomain string
	URL        string
	Command    string
	Port       int
	PGID       int
	Status     string // "starting" | "running" | "stopped" | "failed"
	LastError  string
	StartedAt  time.Time
	EndedAt    *time.Time
}

// AgentSetting is one row in the agent's key/value config table. It is used
// for sticky, agent-wide configuration like the user's preview base domain.
type AgentSetting struct {
	Key   string
	Value string
}

// InfraAlertRule stores one per-server alert rule override. Missing rows are
// materialized from defaults by ListInfraAlertRules.
type InfraAlertRule struct {
	ServerID  string    `json:"server_id"`
	Kind      string    `json:"kind"`
	Enabled   bool      `json:"enabled"`
	Threshold float64   `json:"threshold"`
	UpdatedAt time.Time `json:"updated_at"`
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

// PushDevice is one registered mobile device that can receive FCM-delivered
// push notifications from this agent. We keep the registry on-host (rather
// than in a separate cloud service) so the agent has no external dependency
// for the device list — the FCM service-account JSON is the only off-host
// credential it needs.
type PushDevice struct {
	Token        string
	Platform     string // "ios" | "android"
	RegisteredAt time.Time
	LastSeenAt   time.Time
}

// CliToken stores the encrypted credential material for one CLI (claude or
// codex). Method records how the credential was obtained so callers can
// reconstruct the right env vars / on-disk file when launching sessions.
type CliToken struct {
	Kind           string // "claude" | "codex"
	Method         string // "subscription" | "token" | "api_key" | "auth_json"
	Account        string // best-effort identifier (email, login) — may be empty
	CiphertextPath string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ProjectMemory is one long-lived note the agent reuses across sessions for a
// project: a convention, a gotcha, a decision, or a file-level note. Rows are
// user-owned and rendered only by Claver. SourceSessionID, when set, records
// which AI session proposed the entry.
type ProjectMemory struct {
	ID              string
	ProjectID       string
	Kind            string // convention | gotcha | decision | file_note
	Title           string
	Body            string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	SourceSessionID string
}

// JournalEntry is one item in a project's auto-summarized timeline: a finished
// session, a PR, a deploy, a fired alert, or an approval. ID is an
// autoincrement rowid so it doubles as a stable pagination cursor (occurred_at
// alone is not unique). RefID points back at the originating record (e.g. a
// session id) when one exists.
type JournalEntry struct {
	ID         int64
	ProjectID  string
	Kind       string // session | pr | deploy | alert | approval
	Summary    string
	OccurredAt time.Time
	RefID      string
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

CREATE TABLE IF NOT EXISTS previews (
	id          TEXT PRIMARY KEY,
	project_id  TEXT NOT NULL,
	subdomain   TEXT NOT NULL,
	base_domain TEXT NOT NULL,
	url         TEXT NOT NULL,
	command     TEXT NOT NULL DEFAULT '',
	port        INTEGER NOT NULL DEFAULT 0,
	pgid        INTEGER NOT NULL DEFAULT 0,
	status      TEXT NOT NULL,
	last_error  TEXT NOT NULL DEFAULT '',
	started_at  INTEGER NOT NULL,
	ended_at    INTEGER,
	FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS previews_project_idx ON previews(project_id);
CREATE INDEX IF NOT EXISTS previews_status_idx  ON previews(status);

CREATE TABLE IF NOT EXISTS agent_settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS infra_alert_rules (
	server_id  TEXT NOT NULL,
	kind       TEXT NOT NULL,
	enabled    INTEGER NOT NULL,
	threshold  REAL NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY(server_id, kind)
);

CREATE TABLE IF NOT EXISTS cli_tokens (
	kind            TEXT PRIMARY KEY,
	method          TEXT NOT NULL,
	account         TEXT NOT NULL DEFAULT '',
	ciphertext_path TEXT NOT NULL,
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS push_devices (
	token         TEXT PRIMARY KEY,
	platform      TEXT NOT NULL DEFAULT '',
	registered_at INTEGER NOT NULL,
	last_seen_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS project_memory (
	id                TEXT PRIMARY KEY,
	project_id        TEXT NOT NULL,
	kind              TEXT NOT NULL,
	title             TEXT NOT NULL,
	body              TEXT NOT NULL DEFAULT '',
	created_at        INTEGER NOT NULL,
	updated_at        INTEGER NOT NULL,
	source_session_id TEXT NOT NULL DEFAULT '',
	FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS project_memory_project_idx ON project_memory(project_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS project_journal_entry (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	project_id  TEXT NOT NULL,
	kind        TEXT NOT NULL,
	summary     TEXT NOT NULL,
	occurred_at INTEGER NOT NULL,
	ref_id      TEXT NOT NULL DEFAULT '',
	FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS project_journal_occurred_idx ON project_journal_entry(project_id, occurred_at DESC, id DESC);
`)
	return err
}

// DefaultInfraAlertRule returns the shipped enabled defaults for one rule.
func DefaultInfraAlertRule(serverID, kind string) InfraAlertRule {
	r := InfraAlertRule{ServerID: serverID, Kind: kind, Enabled: true}
	switch kind {
	case "disk_usage":
		r.Threshold = 90
	case "load_sustained":
		r.Threshold = 4
	case "unit_failed":
		r.Threshold = 0
	}
	return r
}

// ListInfraAlertRules returns defaults overlaid by persisted per-server rows.
func (s *Store) ListInfraAlertRules(serverID string) ([]InfraAlertRule, error) {
	if serverID == "" {
		serverID = "local"
	}
	rules := []InfraAlertRule{
		DefaultInfraAlertRule(serverID, "disk_usage"),
		DefaultInfraAlertRule(serverID, "load_sustained"),
		DefaultInfraAlertRule(serverID, "unit_failed"),
	}
	byKind := map[string]int{}
	for i, r := range rules {
		byKind[r.Kind] = i
	}
	rows, err := s.db.Query(
		`SELECT kind, enabled, threshold, updated_at FROM infra_alert_rules WHERE server_id = ?`,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r InfraAlertRule
		var enabled int
		var updated int64
		r.ServerID = serverID
		if err := rows.Scan(&r.Kind, &enabled, &r.Threshold, &updated); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		r.UpdatedAt = time.Unix(updated, 0)
		if i, ok := byKind[r.Kind]; ok {
			rules[i] = r
		}
	}
	return rules, rows.Err()
}

// PutInfraAlertRule upserts a per-server alert rule.
func (s *Store) PutInfraAlertRule(r InfraAlertRule) error {
	if r.ServerID == "" {
		r.ServerID = "local"
	}
	if r.UpdatedAt.IsZero() {
		r.UpdatedAt = time.Now()
	}
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO infra_alert_rules (server_id, kind, enabled, threshold, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(server_id, kind) DO UPDATE SET
		   enabled = excluded.enabled,
		   threshold = excluded.threshold,
		   updated_at = excluded.updated_at`,
		r.ServerID, r.Kind, enabled, r.Threshold, r.UpdatedAt.Unix(),
	)
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

// DeleteSession removes the session row; FK cascade drops session_events.
func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
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

// PutCliToken upserts the encrypted credential pointer for a CLI.
func (s *Store) PutCliToken(t CliToken) error {
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	_, err := s.db.Exec(
		`INSERT INTO cli_tokens (kind, method, account, ciphertext_path, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(kind) DO UPDATE SET
		   method = excluded.method,
		   account = excluded.account,
		   ciphertext_path = excluded.ciphertext_path,
		   updated_at = excluded.updated_at`,
		t.Kind, t.Method, t.Account, t.CiphertextPath, t.CreatedAt.Unix(), t.UpdatedAt.Unix(),
	)
	return err
}

// GetCliToken loads the credential pointer for one CLI kind.
func (s *Store) GetCliToken(kind string) (CliToken, error) {
	row := s.db.QueryRow(
		`SELECT kind, method, account, ciphertext_path, created_at, updated_at
		 FROM cli_tokens WHERE kind = ?`, kind,
	)
	var t CliToken
	var created, updated int64
	if err := row.Scan(&t.Kind, &t.Method, &t.Account, &t.CiphertextPath, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CliToken{}, fmt.Errorf("cli_token: %w", ErrNotFound)
		}
		return CliToken{}, err
	}
	t.CreatedAt = time.Unix(created, 0)
	t.UpdatedAt = time.Unix(updated, 0)
	return t, nil
}

// DeleteCliToken removes one CLI credential pointer.
func (s *Store) DeleteCliToken(kind string) error {
	_, err := s.db.Exec(`DELETE FROM cli_tokens WHERE kind = ?`, kind)
	return err
}

// CreatePreview inserts a new preview row.
func (s *Store) CreatePreview(p Preview) error {
	if p.StartedAt.IsZero() {
		p.StartedAt = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO previews (id, project_id, subdomain, base_domain, url, command, port, pgid, status, last_error, started_at, ended_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.ProjectID, p.Subdomain, p.BaseDomain, p.URL, p.Command,
		p.Port, p.PGID, p.Status, p.LastError, p.StartedAt.Unix(), nullableUnix(p.EndedAt),
	)
	return err
}

// UpdatePreview overwrites the mutable columns of a preview row.
func (s *Store) UpdatePreview(p Preview) error {
	_, err := s.db.Exec(
		`UPDATE previews SET port = ?, pgid = ?, status = ?, last_error = ?, ended_at = ? WHERE id = ?`,
		p.Port, p.PGID, p.Status, p.LastError, nullableUnix(p.EndedAt), p.ID,
	)
	return err
}

// GetPreview loads a preview row by ID.
func (s *Store) GetPreview(id string) (Preview, error) {
	row := s.db.QueryRow(
		`SELECT id, project_id, subdomain, base_domain, url, command, port, pgid, status, last_error, started_at, ended_at
		 FROM previews WHERE id = ?`, id,
	)
	return scanPreview(row)
}

// ActivePreviewForProject returns the currently running/starting preview for
// the given project, if any. Returns ErrNotFound when no active row exists.
func (s *Store) ActivePreviewForProject(projectID string) (Preview, error) {
	row := s.db.QueryRow(
		`SELECT id, project_id, subdomain, base_domain, url, command, port, pgid, status, last_error, started_at, ended_at
		 FROM previews
		 WHERE project_id = ? AND ended_at IS NULL
		 ORDER BY started_at DESC LIMIT 1`, projectID,
	)
	return scanPreview(row)
}

// ListPreviews returns previews ordered newest first, optionally filtered by
// project ID. Pass "" to list across all projects.
func (s *Store) ListPreviews(projectID string) ([]Preview, error) {
	rows, err := s.db.Query(
		`SELECT id, project_id, subdomain, base_domain, url, command, port, pgid, status, last_error, started_at, ended_at
		 FROM previews
		 WHERE (? = '' OR project_id = ?)
		 ORDER BY started_at DESC, id DESC`, projectID, projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Preview, 0)
	for rows.Next() {
		p, err := scanPreviewRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ActivePreviews returns every preview that has not yet been marked stopped.
// The agent uses this during rehydration after a restart.
func (s *Store) ActivePreviews() ([]Preview, error) {
	rows, err := s.db.Query(
		`SELECT id, project_id, subdomain, base_domain, url, command, port, pgid, status, last_error, started_at, ended_at
		 FROM previews WHERE ended_at IS NULL ORDER BY started_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Preview, 0)
	for rows.Next() {
		p, err := scanPreviewRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePreview removes a preview row entirely. Used when a preview is torn
// down after a successful stop.
func (s *Store) DeletePreview(id string) error {
	_, err := s.db.Exec(`DELETE FROM previews WHERE id = ?`, id)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanPreview(row rowScanner) (Preview, error) {
	p, err := scanPreviewRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Preview{}, fmt.Errorf("preview: %w", ErrNotFound)
	}
	return p, err
}

func scanPreviewRow(row rowScanner) (Preview, error) {
	var p Preview
	var started int64
	var ended sql.NullInt64
	if err := row.Scan(&p.ID, &p.ProjectID, &p.Subdomain, &p.BaseDomain, &p.URL, &p.Command, &p.Port, &p.PGID, &p.Status, &p.LastError, &started, &ended); err != nil {
		return Preview{}, err
	}
	p.StartedAt = time.Unix(started, 0)
	if ended.Valid {
		t := time.Unix(ended.Int64, 0)
		p.EndedAt = &t
	}
	return p, nil
}

// GetAgentSetting reads one key from the agent_settings table. Returns
// ErrNotFound when the key has never been set.
func (s *Store) GetAgentSetting(key string) (string, error) {
	row := s.db.QueryRow(`SELECT value FROM agent_settings WHERE key = ?`, key)
	var v string
	if err := row.Scan(&v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("agent_setting %s: %w", key, ErrNotFound)
		}
		return "", err
	}
	return v, nil
}

// PutAgentSetting upserts one key.
func (s *Store) PutAgentSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO agent_settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// PutPushDevice upserts a device token. RegisteredAt is preserved on update;
// LastSeenAt is always bumped to now (or to the value supplied by the caller
// if non-zero), so the agent can later prune stale tokens that FCM has
// rejected as unregistered.
func (s *Store) PutPushDevice(d PushDevice) error {
	if d.Token == "" {
		return errors.New("push device token required")
	}
	now := d.LastSeenAt
	if now.IsZero() {
		now = time.Now()
	}
	reg := d.RegisteredAt
	if reg.IsZero() {
		reg = now
	}
	_, err := s.db.Exec(
		`INSERT INTO push_devices (token, platform, registered_at, last_seen_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(token) DO UPDATE SET
		   platform = excluded.platform,
		   last_seen_at = excluded.last_seen_at`,
		d.Token, d.Platform, reg.Unix(), now.Unix(),
	)
	return err
}

// DeletePushDevice removes a device token. No-op if the token was already
// gone, so a client unregister + server-side prune of an unregistered token
// can race without an error.
func (s *Store) DeletePushDevice(token string) error {
	_, err := s.db.Exec(`DELETE FROM push_devices WHERE token = ?`, token)
	return err
}

// ListPushDevices returns every registered device.
func (s *Store) ListPushDevices() ([]PushDevice, error) {
	rows, err := s.db.Query(`SELECT token, platform, registered_at, last_seen_at FROM push_devices ORDER BY registered_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushDevice
	for rows.Next() {
		var d PushDevice
		var reg, seen int64
		if err := rows.Scan(&d.Token, &d.Platform, &reg, &seen); err != nil {
			return nil, err
		}
		d.RegisteredAt = time.Unix(reg, 0)
		d.LastSeenAt = time.Unix(seen, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// CreateMemory inserts a new project memory row. CreatedAt/UpdatedAt default
// to now when zero.
func (s *Store) CreateMemory(m ProjectMemory) error {
	now := time.Now()
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = m.CreatedAt
	}
	_, err := s.db.Exec(
		`INSERT INTO project_memory (id, project_id, kind, title, body, created_at, updated_at, source_session_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.ProjectID, m.Kind, m.Title, m.Body, m.CreatedAt.Unix(), m.UpdatedAt.Unix(), m.SourceSessionID,
	)
	return err
}

// GetMemory loads one memory row by ID.
func (s *Store) GetMemory(id string) (ProjectMemory, error) {
	row := s.db.QueryRow(
		`SELECT id, project_id, kind, title, body, created_at, updated_at, source_session_id
		 FROM project_memory WHERE id = ?`, id,
	)
	var m ProjectMemory
	var created, updated int64
	if err := row.Scan(&m.ID, &m.ProjectID, &m.Kind, &m.Title, &m.Body, &created, &updated, &m.SourceSessionID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProjectMemory{}, fmt.Errorf("memory %s: %w", id, ErrNotFound)
		}
		return ProjectMemory{}, err
	}
	m.CreatedAt = time.Unix(created, 0)
	m.UpdatedAt = time.Unix(updated, 0)
	return m, nil
}

// UpdateMemory overwrites the mutable columns (kind, title, body) and bumps
// updated_at. Returns ErrNotFound if the row does not exist.
func (s *Store) UpdateMemory(id, kind, title, body string, updatedAt time.Time) error {
	if updatedAt.IsZero() {
		updatedAt = time.Now()
	}
	res, err := s.db.Exec(
		`UPDATE project_memory SET kind = ?, title = ?, body = ?, updated_at = ? WHERE id = ?`,
		kind, title, body, updatedAt.Unix(), id,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("memory %s: %w", id, ErrNotFound)
	}
	return nil
}

// DeleteMemory removes one memory row. Missing rows are not an error.
func (s *Store) DeleteMemory(id string) error {
	_, err := s.db.Exec(`DELETE FROM project_memory WHERE id = ?`, id)
	return err
}

// ListMemory returns a project's memory rows ordered most-recently-updated
// first. Pass "" to list across all projects.
func (s *Store) ListMemory(projectID string) ([]ProjectMemory, error) {
	rows, err := s.db.Query(
		`SELECT id, project_id, kind, title, body, created_at, updated_at, source_session_id
		 FROM project_memory
		 WHERE (? = '' OR project_id = ?)
		 ORDER BY updated_at DESC, id DESC`, projectID, projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ProjectMemory, 0)
	for rows.Next() {
		var m ProjectMemory
		var created, updated int64
		if err := rows.Scan(&m.ID, &m.ProjectID, &m.Kind, &m.Title, &m.Body, &created, &updated, &m.SourceSessionID); err != nil {
			return nil, err
		}
		m.CreatedAt = time.Unix(created, 0)
		m.UpdatedAt = time.Unix(updated, 0)
		out = append(out, m)
	}
	return out, rows.Err()
}

// AppendJournalEntry inserts a timeline entry, assigns its rowid, and returns
// the stored row. OccurredAt defaults to now when zero.
func (s *Store) AppendJournalEntry(e JournalEntry) (JournalEntry, error) {
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now()
	}
	res, err := s.db.Exec(
		`INSERT INTO project_journal_entry (project_id, kind, summary, occurred_at, ref_id)
		 VALUES (?, ?, ?, ?, ?)`,
		e.ProjectID, e.Kind, e.Summary, e.OccurredAt.Unix(), e.RefID,
	)
	if err != nil {
		return JournalEntry{}, err
	}
	e.ID, _ = res.LastInsertId()
	return e, nil
}

// ListJournal returns a page of journal entries ordered by occurrence time,
// newest first. An empty kind means "any". limit is clamped to [1, 200].
//
// Pagination is keyset-based on (occurred_at, id) rather than on the insertion
// rowid: a journal entry can be inserted with an explicit, backdated
// occurred_at (the session-end summarizer runs asynchronously, and future
// PR/deploy/alert sources append events after the fact), so a larger id does
// not imply a later event. Ordering by id alone would let a delayed insert
// jump to the top of the timeline. cursor is the opaque token returned as the
// previous page's nextCursor; pass "" to start from the newest entry. The
// returned nextCursor is "" when there are no further rows.
func (s *Store) ListJournal(projectID, kind, cursor string, limit int) ([]JournalEntry, string, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	// An empty cursor means "from the top". A sentinel above any real
	// occurred_at lets the same keyset predicate cover the first page too.
	curOccurred, curID := int64(1)<<62-1, int64(1)<<62-1
	if cursor != "" {
		o, i, ok := decodeJournalCursor(cursor)
		if !ok {
			return nil, "", fmt.Errorf("invalid journal cursor %q", cursor)
		}
		curOccurred, curID = o, i
	}
	rows, err := s.db.Query(
		`SELECT id, project_id, kind, summary, occurred_at, ref_id
		 FROM project_journal_entry
		 WHERE project_id = ? AND (? = '' OR kind = ?)
		   AND (occurred_at < ? OR (occurred_at = ? AND id < ?))
		 ORDER BY occurred_at DESC, id DESC
		 LIMIT ?`,
		projectID, kind, kind, curOccurred, curOccurred, curID, limit+1,
	)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := make([]JournalEntry, 0, limit)
	for rows.Next() {
		var e JournalEntry
		var occurred int64
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.Kind, &e.Summary, &occurred, &e.RefID); err != nil {
			return nil, "", err
		}
		e.OccurredAt = time.Unix(occurred, 0)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	// We fetched limit+1 to detect a further page without a second query.
	var next string
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeJournalCursor(last.OccurredAt.Unix(), last.ID)
	}
	return out, next, nil
}

// encodeJournalCursor packs the keyset (occurred_at unix, id) into the opaque
// "<occurred>:<id>" token the client echoes back to page through history.
func encodeJournalCursor(occurred, id int64) string {
	return fmt.Sprintf("%d:%d", occurred, id)
}

func decodeJournalCursor(s string) (occurred, id int64, ok bool) {
	if _, err := fmt.Sscanf(s, "%d:%d", &occurred, &id); err != nil {
		return 0, 0, false
	}
	return occurred, id, true
}

func nullableUnix(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Unix()
}
