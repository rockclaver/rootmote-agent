package store

import (
	"path/filepath"
	"testing"
	"time"
)

// AC: "Project list survives `systemctl restart claver-agent` with no data loss."
// We simulate a restart by closing and reopening the database file.
func TestStore_ProjectsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "claver.db")

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t0 := time.Unix(1_700_000_000, 0)
	p := Project{ID: "p1", Name: "alpha", RemoteURL: "https://example.com/r.git", CreatedAt: t0}
	if err := s.CreateProject(p); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	got, err := s2.GetProject("p1")
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got.Name != "alpha" || got.RemoteURL != "https://example.com/r.git" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if !got.CreatedAt.Equal(t0) {
		t.Errorf("created_at: got %v want %v", got.CreatedAt, t0)
	}
}

func TestStore_ListOrderedByCreatedAt(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.CreateProject(Project{ID: "b", Name: "b", CreatedAt: time.Unix(200, 0)})
	_ = s.CreateProject(Project{ID: "a", Name: "a", CreatedAt: time.Unix(100, 0)})
	_ = s.CreateProject(Project{ID: "c", Name: "c", CreatedAt: time.Unix(300, 0)})
	ps, err := s.ListProjects()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 3 || ps[0].ID != "a" || ps[1].ID != "b" || ps[2].ID != "c" {
		t.Errorf("order wrong: %+v", ps)
	}
}

func TestStore_DeleteRemovesRow(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.CreateProject(Project{ID: "p1", Name: "x", CreatedAt: time.Unix(1, 0)})
	if err := s.DeleteProject("p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetProject("p1"); err == nil {
		t.Fatal("expected not-found after delete")
	}
}
