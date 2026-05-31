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
	// First page of 2, newest-first by occurred_at.
	page1, next, err := st.ListJournal("p1", "", "", 2)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 || !page1[0].OccurredAt.After(page1[1].OccurredAt) {
		t.Fatalf("page1 wrong order/size: %+v", page1)
	}
	if next == "" {
		t.Fatal("expected a next cursor")
	}
	page2, next2, err := st.ListJournal("p1", "", next, 2)
	if err != nil || len(page2) != 2 {
		t.Fatalf("page2: %v size=%d", err, len(page2))
	}
	if !page1[1].OccurredAt.After(page2[0].OccurredAt) {
		t.Fatalf("page2 overlaps page1: %+v vs %+v", page2, page1)
	}
	page3, next3, _ := st.ListJournal("p1", "", next2, 2)
	if len(page3) != 1 {
		t.Fatalf("page3 size = %d, want 1", len(page3))
	}
	if next3 != "" {
		t.Fatalf("next3 = %q, want empty (end)", next3)
	}
}

// Regression for the Codex review: a journal entry inserted later (larger
// rowid) but with an earlier occurred_at — as happens when an earlier
// session's async summarizer finishes after a later session's, or when a
// PR/deploy event is backfilled — must not jump to the top of the timeline.
func TestJournalOrdersByOccurredNotInsertion(t *testing.T) {
	st := openTestStore(t)
	// Insert the OLDER-occurring event LAST so it gets the larger rowid.
	newer, _ := st.AppendJournalEntry(JournalEntry{
		ProjectID: "p1", Kind: "session", Summary: "newer",
		OccurredAt: time.Unix(2000, 0),
	})
	older, _ := st.AppendJournalEntry(JournalEntry{
		ProjectID: "p1", Kind: "session", Summary: "older",
		OccurredAt: time.Unix(1000, 0),
	})
	if older.ID <= newer.ID {
		t.Fatalf("test setup: expected older row to have the larger id (%d vs %d)", older.ID, newer.ID)
	}
	page, _, err := st.ListJournal("p1", "", "", 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page) != 2 || page[0].Summary != "newer" || page[1].Summary != "older" {
		t.Fatalf("timeline not ordered by occurred_at: %+v", page)
	}
}

func TestJournalKindFilter(t *testing.T) {
	st := openTestStore(t)
	_, _ = st.AppendJournalEntry(JournalEntry{ProjectID: "p1", Kind: "session", Summary: "s"})
	_, _ = st.AppendJournalEntry(JournalEntry{ProjectID: "p1", Kind: "pr", Summary: "p"})
	only, _, err := st.ListJournal("p1", "pr", "", 50)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(only) != 1 || only[0].Kind != "pr" {
		t.Fatalf("kind filter wrong: %+v", only)
	}
}

func TestJournalRejectsBadCursor(t *testing.T) {
	st := openTestStore(t)
	if _, _, err := st.ListJournal("p1", "", "not-a-cursor", 10); err == nil {
		t.Fatal("expected error for malformed cursor")
	}
}
