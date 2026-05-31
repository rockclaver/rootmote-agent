// Package memory owns long-lived per-project agent memory and the project
// journal. Memory rows (conventions, gotchas, decisions, file notes) are
// rendered into a token-bounded block that every new session loads as context,
// so the agent gets visibly better at a repo over time. The journal is an
// auto-summarized timeline of sessions, PRs, deploys, alerts, and approvals —
// the canonical "what happened on this project" log.
//
// Both live in the user-owned VPS SQLite store. The Manager wraps the store
// with validation, a token-bounded renderer, a session-end summarizer hook,
// and an in-memory queue of AI-proposed memory entries that require explicit
// one-tap user confirmation before they are persisted.
package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rockclaver/claver/agent/internal/store"
)

// Memory kinds. The set is closed so the UI can render a fixed filter list and
// the renderer can group deterministically.
const (
	KindConvention = "convention"
	KindGotcha     = "gotcha"
	KindDecision   = "decision"
	KindFileNote   = "file_note"
)

// Journal kinds.
const (
	JournalSession  = "session"
	JournalPR       = "pr"
	JournalDeploy   = "deploy"
	JournalAlert    = "alert"
	JournalApproval = "approval"
)

// Errors surfaced to the server layer, which maps them to wire error kinds.
var (
	ErrNotFound   = store.ErrNotFound
	ErrBadKind    = errors.New("unknown memory kind")
	ErrEmptyTitle = errors.New("memory title required")
	ErrNoProject  = errors.New("project id required")
	ErrBadJournal = errors.New("unknown journal kind")
	ErrNoProposal = errors.New("proposal not found")
)

// defaultRenderBudget bounds the rendered memory block. Memory is injected as
// the first turn of context for a fresh session, so it must stay small enough
// to leave the model room to work. We budget in characters (~4 chars/token);
// 8 KiB ≈ 2K tokens is a comfortable ceiling.
const defaultRenderBudget = 8 * 1024

// ProposedMemory is a single memory entry an AI session suggested at session
// end. It is not persisted until the user confirms it.
type ProposedMemory struct {
	Kind  string `json:"kind"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

// SessionSummary is what a Summarizer returns for a finished session: 1–3
// bullet points describing what happened, plus any memory entries the model
// thinks are worth keeping.
type SessionSummary struct {
	Bullets  []string         `json:"bullets"`
	Proposed []ProposedMemory `json:"proposed_memory"`
}

// Summarizer turns a finished session's transcript into a SessionSummary.
// Production wiring shells out to the host claude/codex CLI; tests inject a
// deterministic fake.
type Summarizer interface {
	Summarize(ctx context.Context, projectID, sessionID, transcript string) (SessionSummary, error)
}

// Proposal is one pending AI-proposed memory entry awaiting user confirmation.
type Proposal struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	SessionID string    `json:"session_id"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"-"`
}

// Manager wraps the store and owns the proposal queue.
type Manager struct {
	Store *store.Store
	Now   func() time.Time
	IDGen func() string
	// Summarizer, when set, is used by OnSessionEnd. When nil, OnSessionEnd
	// still records a minimal journal entry but proposes no memory.
	Summarizer Summarizer
	// Transcript returns a finished session's text log. Wired to
	// sessions.Manager.Log so summarization reads the persisted stream.
	Transcript func(sessionID string) (string, error)
	// RenderBudget bounds the injected memory block in characters. Zero uses
	// defaultRenderBudget.
	RenderBudget int

	mu        sync.Mutex
	proposals map[string]*Proposal
	order     []string
	// ended dedupes OnSessionEnd so a Stop racing the reaper does not write
	// two journal entries for the same session.
	ended map[string]struct{}
}

// New constructs a Manager backed by st.
func New(st *store.Store) *Manager {
	return &Manager{
		Store:     st,
		Now:       time.Now,
		IDGen:     randomID,
		proposals: map[string]*Proposal{},
		ended:     map[string]struct{}{},
	}
}

func randomID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func validKind(k string) bool {
	switch k {
	case KindConvention, KindGotcha, KindDecision, KindFileNote:
		return true
	}
	return false
}

func validJournalKind(k string) bool {
	switch k {
	case JournalSession, JournalPR, JournalDeploy, JournalAlert, JournalApproval:
		return true
	}
	return false
}

// CreateMemory validates and persists a user- or system-created memory entry.
func (m *Manager) CreateMemory(projectID, kind, title, body, sourceSessionID string) (store.ProjectMemory, error) {
	if projectID == "" {
		return store.ProjectMemory{}, ErrNoProject
	}
	if !validKind(kind) {
		return store.ProjectMemory{}, ErrBadKind
	}
	if strings.TrimSpace(title) == "" {
		return store.ProjectMemory{}, ErrEmptyTitle
	}
	now := m.Now()
	row := store.ProjectMemory{
		ID:              m.IDGen(),
		ProjectID:       projectID,
		Kind:            kind,
		Title:           strings.TrimSpace(title),
		Body:            body,
		CreatedAt:       now,
		UpdatedAt:       now,
		SourceSessionID: sourceSessionID,
	}
	if err := m.Store.CreateMemory(row); err != nil {
		return store.ProjectMemory{}, err
	}
	return row, nil
}

// UpdateMemory edits the kind/title/body of an existing entry.
func (m *Manager) UpdateMemory(id, kind, title, body string) (store.ProjectMemory, error) {
	if !validKind(kind) {
		return store.ProjectMemory{}, ErrBadKind
	}
	if strings.TrimSpace(title) == "" {
		return store.ProjectMemory{}, ErrEmptyTitle
	}
	if err := m.Store.UpdateMemory(id, kind, strings.TrimSpace(title), body, m.Now()); err != nil {
		return store.ProjectMemory{}, err
	}
	return m.Store.GetMemory(id)
}

// DeleteMemory removes one entry.
func (m *Manager) DeleteMemory(id string) error {
	return m.Store.DeleteMemory(id)
}

// ListMemory returns a project's memory rows newest-updated first.
func (m *Manager) ListMemory(projectID string) ([]store.ProjectMemory, error) {
	return m.Store.ListMemory(projectID)
}

// AppendJournal validates and writes one timeline entry.
func (m *Manager) AppendJournal(projectID, kind, summary, refID string, occurredAt time.Time) (store.JournalEntry, error) {
	if projectID == "" {
		return store.JournalEntry{}, ErrNoProject
	}
	if !validJournalKind(kind) {
		return store.JournalEntry{}, ErrBadJournal
	}
	if occurredAt.IsZero() {
		occurredAt = m.Now()
	}
	return m.Store.AppendJournalEntry(store.JournalEntry{
		ProjectID:  projectID,
		Kind:       kind,
		Summary:    summary,
		OccurredAt: occurredAt,
		RefID:      refID,
	})
}

// ListJournal returns a cursor-paginated page of the project's timeline,
// ordered by occurrence time. cursor is the opaque token from a prior page
// ("" for the newest page); nextCursor is "" at the end of history.
func (m *Manager) ListJournal(projectID, kind, cursor string, limit int) ([]store.JournalEntry, string, error) {
	return m.Store.ListJournal(projectID, kind, cursor, limit)
}

// Render builds the token-bounded memory block injected into a new session.
//
// Ordering is recency-first within a relevance grouping: conventions and
// gotchas (things that shape how you must write code, or that broke last time)
// come before decisions and file notes. Within each group, most-recently
// updated wins. Entries are appended until the character budget is reached,
// then truncated — so the freshest, highest-signal memory survives a tight
// budget. Returns "" when the project has no memory.
func (m *Manager) Render(projectID string) string {
	rows, err := m.Store.ListMemory(projectID)
	if err != nil || len(rows) == 0 {
		return ""
	}
	budget := m.RenderBudget
	if budget <= 0 {
		budget = defaultRenderBudget
	}
	prio := map[string]int{KindGotcha: 0, KindConvention: 1, KindDecision: 2, KindFileNote: 3}
	sort.SliceStable(rows, func(i, j int) bool {
		pi, pj := prio[rows[i].Kind], prio[rows[j].Kind]
		if pi != pj {
			return pi < pj
		}
		return rows[i].UpdatedAt.After(rows[j].UpdatedAt)
	})

	var b strings.Builder
	b.WriteString("# Project memory (read-only context from past sessions)\n")
	b.WriteString("These notes were captured on earlier sessions for this project. ")
	b.WriteString("Treat them as established context; do not re-litigate them.\n")
	header := b.Len()
	truncated := false
	for _, r := range rows {
		line := formatMemoryLine(r)
		if b.Len()+len(line) > budget {
			truncated = true
			break
		}
		b.WriteString(line)
	}
	if b.Len() == header {
		// Even the first entry overran the budget; include nothing further.
		return ""
	}
	if truncated {
		b.WriteString("\n(older memory omitted to fit context budget)\n")
	}
	return b.String()
}

func formatMemoryLine(r store.ProjectMemory) string {
	var b strings.Builder
	b.WriteString("\n## [")
	b.WriteString(r.Kind)
	b.WriteString("] ")
	b.WriteString(r.Title)
	b.WriteString("\n")
	if strings.TrimSpace(r.Body) != "" {
		b.WriteString(strings.TrimSpace(r.Body))
		b.WriteString("\n")
	}
	return b.String()
}

// OnSessionEnd is the session-end hook. It pulls the finished session's
// transcript, summarizes it into 1–3 bullets, writes a journal entry of kind
// "session", and enqueues any AI-proposed memory entries for confirmation. It
// is idempotent per session id so a Stop racing the reaper writes one entry.
//
// Errors are returned for the caller to log; a summarizer failure still
// records a minimal journal entry so the timeline never silently drops a
// session.
func (m *Manager) OnSessionEnd(ctx context.Context, sess store.Session) error {
	m.mu.Lock()
	if _, done := m.ended[sess.ID]; done {
		m.mu.Unlock()
		return nil
	}
	m.ended[sess.ID] = struct{}{}
	m.mu.Unlock()

	var transcript string
	if m.Transcript != nil {
		transcript, _ = m.Transcript(sess.ID)
	}

	var summary SessionSummary
	var sumErr error
	if m.Summarizer != nil && strings.TrimSpace(transcript) != "" {
		summary, sumErr = m.Summarizer.Summarize(ctx, sess.ProjectID, sess.ID, transcript)
	}

	text := renderBullets(summary.Bullets)
	if text == "" {
		text = fmt.Sprintf("%s session ended", sess.Agent)
	}
	occurred := m.Now()
	if sess.EndedAt != nil {
		occurred = *sess.EndedAt
	}
	if _, err := m.AppendJournal(sess.ProjectID, JournalSession, text, sess.ID, occurred); err != nil {
		return err
	}

	for _, p := range summary.Proposed {
		if !validKind(p.Kind) || strings.TrimSpace(p.Title) == "" {
			continue
		}
		m.enqueueProposal(sess.ProjectID, sess.ID, p)
	}
	return sumErr
}

func renderBullets(bullets []string) string {
	out := make([]string, 0, len(bullets))
	for _, b := range bullets {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		out = append(out, "• "+b)
		if len(out) == 3 { // 1–3 bullets per the spec
			break
		}
	}
	return strings.Join(out, "\n")
}

func (m *Manager) enqueueProposal(projectID, sessionID string, p ProposedMemory) Proposal {
	m.mu.Lock()
	defer m.mu.Unlock()
	prop := Proposal{
		ID:        m.IDGen(),
		ProjectID: projectID,
		SessionID: sessionID,
		Kind:      p.Kind,
		Title:     strings.TrimSpace(p.Title),
		Body:      p.Body,
		CreatedAt: m.Now(),
	}
	stored := prop
	m.proposals[prop.ID] = &stored
	m.order = append(m.order, prop.ID)
	return stored
}

// ListProposals returns pending AI-proposed memory entries for a project in
// submission order. Pass "" for all projects.
func (m *Manager) ListProposals(projectID string) []Proposal {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Proposal, 0, len(m.order))
	for _, id := range m.order {
		p, ok := m.proposals[id]
		if !ok {
			continue
		}
		if projectID != "" && p.ProjectID != projectID {
			continue
		}
		out = append(out, *p)
	}
	return out
}

// ConfirmProposal persists a pending proposal as a real memory row and removes
// it from the queue. This is the one-tap user confirmation the spec requires
// before AI-proposed memory is written.
func (m *Manager) ConfirmProposal(id string) (store.ProjectMemory, error) {
	m.mu.Lock()
	p, ok := m.proposals[id]
	if !ok {
		m.mu.Unlock()
		return store.ProjectMemory{}, ErrNoProposal
	}
	snap := *p
	m.removeProposalLocked(id)
	m.mu.Unlock()
	return m.CreateMemory(snap.ProjectID, snap.Kind, snap.Title, snap.Body, snap.SessionID)
}

// RejectProposal drops a pending proposal without persisting it.
func (m *Manager) RejectProposal(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.proposals[id]; !ok {
		return ErrNoProposal
	}
	m.removeProposalLocked(id)
	return nil
}

func (m *Manager) removeProposalLocked(id string) {
	delete(m.proposals, id)
	for i, oid := range m.order {
		if oid == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
}

// ExportJournalMarkdown renders a project's entire journal as Markdown,
// newest first. projectName is used only for the document title.
func (m *Manager) ExportJournalMarkdown(projectID, projectName string) (string, error) {
	if projectID == "" {
		return "", ErrNoProject
	}
	var b strings.Builder
	title := projectName
	if title == "" {
		title = projectID
	}
	b.WriteString("# Project journal — ")
	b.WriteString(title)
	b.WriteString("\n")

	var cursor string
	wrote := false
	for {
		page, next, err := m.Store.ListJournal(projectID, "", cursor, 200)
		if err != nil {
			return "", err
		}
		for _, e := range page {
			wrote = true
			b.WriteString("\n## ")
			b.WriteString(e.OccurredAt.UTC().Format("2006-01-02 15:04 MST"))
			b.WriteString(" — ")
			b.WriteString(e.Kind)
			b.WriteString("\n")
			if strings.TrimSpace(e.Summary) != "" {
				b.WriteString(e.Summary)
				b.WriteString("\n")
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if !wrote {
		b.WriteString("\n_No journal entries yet._\n")
	}
	return b.String(), nil
}
