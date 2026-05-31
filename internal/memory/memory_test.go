package memory

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/claver/agent/internal/store"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.CreateProject(store.Project{ID: "p1", Name: "demo"}); err != nil {
		t.Fatalf("project: %v", err)
	}
	m := New(st)
	seq := 0
	m.IDGen = func() string {
		seq++
		return "id" + string(rune('0'+seq))
	}
	now := time.Unix(1000, 0)
	m.Now = func() time.Time { return now }
	return m
}

func TestCreateMemoryValidation(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.CreateMemory("", KindConvention, "t", "", ""); err != ErrNoProject {
		t.Fatalf("empty project = %v", err)
	}
	if _, err := m.CreateMemory("p1", "bogus", "t", "", ""); err != ErrBadKind {
		t.Fatalf("bad kind = %v", err)
	}
	if _, err := m.CreateMemory("p1", KindConvention, "   ", "", ""); err != ErrEmptyTitle {
		t.Fatalf("empty title = %v", err)
	}
	row, err := m.CreateMemory("p1", KindConvention, "Use tabs", "body", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if row.ID == "" || row.Kind != KindConvention {
		t.Fatalf("bad row: %+v", row)
	}
}

// AC: "Every started session loads relevant memory into the agent prompt
// context (token-bounded; truncate by recency + relevance)." Render is the
// piece sessions inject; here we verify the token bound truncates and the
// header survives.
func TestRenderTokenBounded(t *testing.T) {
	m := newTestManager(t)
	m.RenderBudget = 400
	for i := 0; i < 20; i++ {
		if _, err := m.CreateMemory("p1", KindGotcha, "Gotcha number that is fairly long", strings.Repeat("x", 80), ""); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	out := m.Render("p1")
	if out == "" {
		t.Fatal("expected non-empty render")
	}
	if len(out) > 600 { // budget + the truncation footer, generous slack
		t.Fatalf("render not bounded: %d bytes", len(out))
	}
	if !strings.Contains(out, "Project memory") {
		t.Fatalf("missing header: %q", out)
	}
	if !strings.Contains(out, "omitted to fit context budget") {
		t.Fatalf("expected truncation footer in bounded render")
	}
}

func TestRenderEmptyForNoMemory(t *testing.T) {
	m := newTestManager(t)
	if got := m.Render("p1"); got != "" {
		t.Fatalf("expected empty render, got %q", got)
	}
}

// AC: "Render orders by recency + relevance" — gotchas/conventions before
// decisions/file_notes.
func TestRenderRelevanceOrdering(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.CreateMemory("p1", KindFileNote, "A file note", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateMemory("p1", KindGotcha, "A gotcha", "", ""); err != nil {
		t.Fatal(err)
	}
	out := m.Render("p1")
	gi := strings.Index(out, "A gotcha")
	fi := strings.Index(out, "A file note")
	if gi < 0 || fi < 0 || gi > fi {
		t.Fatalf("gotcha should precede file note: gi=%d fi=%d\n%s", gi, fi, out)
	}
}

type fakeSummarizer struct {
	summary SessionSummary
	calls   int
}

func (f *fakeSummarizer) Summarize(_ context.Context, _, _, _ string) (SessionSummary, error) {
	f.calls++
	return f.summary, nil
}

// AC: "Session-end hook summarizes the session in 1–3 bullets and writes a
// journal entry; the AI may also propose new memory entries which require
// one-tap user confirmation."
func TestSessionEndWritesJournalAndProposesMemory(t *testing.T) {
	m := newTestManager(t)
	m.Transcript = func(string) (string, error) { return "did some work", nil }
	m.Summarizer = &fakeSummarizer{summary: SessionSummary{
		Bullets: []string{"Implemented X", "Fixed Y"},
		Proposed: []ProposedMemory{
			{Kind: KindConvention, Title: "Run gofmt before commit", Body: "CI fails otherwise"},
		},
	}}
	ended := time.Unix(2000, 0)
	sess := store.Session{ID: "s1", ProjectID: "p1", Agent: "claude", EndedAt: &ended}

	if err := m.OnSessionEnd(context.Background(), sess); err != nil {
		t.Fatalf("OnSessionEnd: %v", err)
	}

	// Journal entry written.
	entries, _, err := m.ListJournal("p1", "", 0, 50)
	if err != nil || len(entries) != 1 {
		t.Fatalf("journal entries = %d err=%v", len(entries), err)
	}
	if entries[0].Kind != JournalSession || entries[0].RefID != "s1" {
		t.Fatalf("bad journal entry: %+v", entries[0])
	}
	if !strings.Contains(entries[0].Summary, "Implemented X") {
		t.Fatalf("summary missing bullet: %q", entries[0].Summary)
	}
	if !entries[0].OccurredAt.Equal(ended) {
		t.Fatalf("occurred_at = %v, want session end %v", entries[0].OccurredAt, ended)
	}

	// AI-proposed memory must NOT be persisted yet — it requires confirmation.
	rows, _ := m.ListMemory("p1")
	if len(rows) != 0 {
		t.Fatalf("AI memory persisted without confirmation: %+v", rows)
	}
	props := m.ListProposals("p1")
	if len(props) != 1 || props[0].Title != "Run gofmt before commit" {
		t.Fatalf("expected 1 pending proposal, got %+v", props)
	}

	// One-tap confirm persists it.
	row, err := m.ConfirmProposal(props[0].ID)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if row.SourceSessionID != "s1" {
		t.Fatalf("confirmed row should carry source session: %+v", row)
	}
	rows, _ = m.ListMemory("p1")
	if len(rows) != 1 {
		t.Fatalf("confirmed memory not persisted: %d", len(rows))
	}
	if len(m.ListProposals("p1")) != 0 {
		t.Fatal("proposal should be cleared after confirm")
	}
}

func TestRejectProposalDoesNotPersist(t *testing.T) {
	m := newTestManager(t)
	m.Transcript = func(string) (string, error) { return "x", nil }
	m.Summarizer = &fakeSummarizer{summary: SessionSummary{
		Bullets:  []string{"b"},
		Proposed: []ProposedMemory{{Kind: KindGotcha, Title: "T"}},
	}}
	_ = m.OnSessionEnd(context.Background(), store.Session{ID: "s1", ProjectID: "p1", Agent: "claude"})
	props := m.ListProposals("p1")
	if len(props) != 1 {
		t.Fatalf("want 1 proposal, got %d", len(props))
	}
	if err := m.RejectProposal(props[0].ID); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rows, _ := m.ListMemory("p1"); len(rows) != 0 {
		t.Fatalf("rejected proposal persisted: %+v", rows)
	}
	if err := m.RejectProposal("nope"); err != ErrNoProposal {
		t.Fatalf("reject missing = %v", err)
	}
}

func TestSessionEndIdempotent(t *testing.T) {
	m := newTestManager(t)
	m.Transcript = func(string) (string, error) { return "x", nil }
	m.Summarizer = &fakeSummarizer{summary: SessionSummary{Bullets: []string{"b"}}}
	sess := store.Session{ID: "s1", ProjectID: "p1", Agent: "claude"}
	_ = m.OnSessionEnd(context.Background(), sess)
	_ = m.OnSessionEnd(context.Background(), sess)
	entries, _, _ := m.ListJournal("p1", "", 0, 50)
	if len(entries) != 1 {
		t.Fatalf("expected idempotent single entry, got %d", len(entries))
	}
}

func TestSessionEndWithoutSummarizerStillJournals(t *testing.T) {
	m := newTestManager(t)
	// No summarizer wired.
	if err := m.OnSessionEnd(context.Background(), store.Session{ID: "s1", ProjectID: "p1", Agent: "codex"}); err != nil {
		t.Fatalf("OnSessionEnd: %v", err)
	}
	entries, _, _ := m.ListJournal("p1", "", 0, 50)
	if len(entries) != 1 || !strings.Contains(entries[0].Summary, "codex") {
		t.Fatalf("fallback journal entry missing: %+v", entries)
	}
}

func TestExportJournalMarkdown(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.AppendJournal("p1", JournalSession, "Did a thing", "s1", time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	md, err := m.ExportJournalMarkdown("p1", "Demo")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(md, "# Project journal — Demo") {
		t.Fatalf("missing title: %q", md)
	}
	if !strings.Contains(md, "Did a thing") || !strings.Contains(md, "session") {
		t.Fatalf("missing entry: %q", md)
	}
}

func TestExportEmptyJournal(t *testing.T) {
	m := newTestManager(t)
	md, err := m.ExportJournalMarkdown("p1", "Demo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md, "No journal entries yet") {
		t.Fatalf("expected empty marker: %q", md)
	}
}
