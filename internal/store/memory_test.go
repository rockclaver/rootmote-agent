package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.CreateProject(Project{ID: "p1", Name: "demo"}); err != nil {
		t.Fatalf("create project: %v", err)
	}
	return st
}

func TestMemoryCRUD(t *testing.T) {
	st := openTestStore(t)
	m := ProjectMemory{
		ID: "m1", ProjectID: "p1", Kind: "convention", Title: "Use tabs",
		Body: "gofmt", CreatedAt: time.Unix(100, 0), UpdatedAt: time.Unix(100, 0),
	}
	if err := st.CreateMemory(m); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := st.GetMemory("m1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Title != "Use tabs" || got.Kind != "convention" {
		t.Fatalf("unexpected row: %+v", got)
	}
	if err := st.UpdateMemory("m1", "gotcha", "Watch the WAL", "body2", time.Unix(200, 0)); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = st.GetMemory("m1")
	if got.Kind != "gotcha" || got.Title != "Watch the WAL" || got.Body != "body2" {
		t.Fatalf("update not applied: %+v", got)
	}
	if !got.UpdatedAt.Equal(time.Unix(200, 0)) {
		t.Fatalf("updated_at not bumped: %v", got.UpdatedAt)
	}
	if err := st.UpdateMemory("missing", "gotcha", "x", "", time.Unix(1, 0)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing = %v, want ErrNotFound", err)
	}
	rows, err := st.ListMemory("p1")
	if err != nil || len(rows) != 1 {
		t.Fatalf("list: %v rows=%d", err, len(rows))
	}
	if err := st.DeleteMemory("m1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetMemory("m1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete = %v, want ErrNotFound", err)
	}
}

func TestMemoryCascadesWithProject(t *testing.T) {
	st := openTestStore(t)
	_ = st.CreateMemory(ProjectMemory{ID: "m1", ProjectID: "p1", Kind: "decision", Title: "t"})
	if err := st.DeleteProject("p1"); err != nil {
		t.Fatalf("delete project: %v", err)
	}
	rows, _ := st.ListMemory("p1")
	if len(rows) != 0 {
		t.Fatalf("memory not cascaded: %d rows", len(rows))
	}
}

func TestJournalCursorPagination(t *testing.T) {
	st := openTestStore(t)
	for i := 0; i < 5; i++ {
		if _, err := st.AppendJournalEntry(JournalEntry{
			ProjectID:  "p1",
			Kind:       "session",
			Summary:    "entry",
			OccurredAt: time.Unix(int64(100+i), 0),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// First page of 2, newest-first.
	page1, next, err := st.ListJournal("p1", "", 0, 2)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 || page1[0].ID <= page1[1].ID {
		t.Fatalf("page1 wrong order/size: %+v", page1)
	}
	if next == 0 {
		t.Fatal("expected a next cursor")
	}
	page2, next2, err := st.ListJournal("p1", "", next, 2)
	if err != nil || len(page2) != 2 {
		t.Fatalf("page2: %v size=%d", err, len(page2))
	}
	if page2[0].ID >= page1[1].ID {
		t.Fatalf("page2 overlaps page1: %+v vs %+v", page2, page1)
	}
	page3, next3, _ := st.ListJournal("p1", "", next2, 2)
	if len(page3) != 1 {
		t.Fatalf("page3 size = %d, want 1", len(page3))
	}
	if next3 != 0 {
		t.Fatalf("next3 = %d, want 0 (end)", next3)
	}
}

func TestJournalKindFilter(t *testing.T) {
	st := openTestStore(t)
	_, _ = st.AppendJournalEntry(JournalEntry{ProjectID: "p1", Kind: "session", Summary: "s"})
	_, _ = st.AppendJournalEntry(JournalEntry{ProjectID: "p1", Kind: "pr", Summary: "p"})
	only, _, err := st.ListJournal("p1", "pr", 0, 50)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(only) != 1 || only[0].Kind != "pr" {
		t.Fatalf("kind filter wrong: %+v", only)
	}
}
