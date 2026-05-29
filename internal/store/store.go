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
