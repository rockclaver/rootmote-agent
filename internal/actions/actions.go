// Package actions is the agent-side Action Orchestrator: the top-level AI
// Action Plane entry point that turns a natural-language operational request
// ("the Ancient API is crashing, check Docker and fix it") into a durable,
// auditable job.
//
// This package is the Phase 1 tracer (see plans/ai-action-plane.md). It owns
// the job lifecycle and ledger only: persist the request, the chosen worker,
// status transitions, and an append-only event trail; run a read-only planner;
// and record its observation. Crucially, Phase 1 performs NO mutation — the
// planner is read-only and the orchestrator never touches Docker, systemd,
// processes, the filesystem, or any host state. Target resolution, the action
// registry, server-side policy, real AI diagnosis, and remediation arrive in
// later phases. Keeping execution out of this package now means the safety
// model (no raw shell, typed actions only) is preserved by construction.
//
// Persistence goes through the Store interface so the orchestrator survives an
// agent restart and the mobile client can list job history without an
// in-memory cache. The Planner is an interface so the host process can wire a
// real CLI-backed planner in production and a stub in tests without dragging
// LLM specifics into this package.
package actions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rockclaver/claver-agent/internal/notifications"
	"github.com/rockclaver/claver-agent/internal/store"
)

// Worker identifies which AI CLI should plan/execute a job. "auto" defers the
// choice to deterministic auto-pick (Phase 4); Phase 1 only records it.
type Worker string

const (
	WorkerAuto   Worker = "auto"
	WorkerClaude Worker = "claude"
	WorkerCodex  Worker = "codex"
)

// validWorker reports whether w is a recognised worker choice.
func validWorker(w Worker) bool {
	switch w {
	case WorkerAuto, WorkerClaude, WorkerCodex:
		return true
	}
	return false
}

// Status is a job's lifecycle state. Phase 1 only ever reaches the read-only
// terminal states (observed, needs_target) plus cancelled/failed; the
// mutating states (approving, executing, completed) arrive in later phases.
type Status string

const (
	// StatusSubmitted is the initial state right after a request is accepted.
	StatusSubmitted Status = "submitted"
	// StatusPlanning means the read-only planner is gathering observations.
	StatusPlanning Status = "planning"
	// StatusObserved is a terminal Phase 1 state: the planner produced a
	// read-only observation and proposed no mutation.
	StatusObserved Status = "observed"
	// StatusNeedsTarget is a terminal Phase 1 state: the planner could not
	// resolve which server/project/resource the request refers to.
	StatusNeedsTarget Status = "needs_target"
	// StatusFailed is a terminal state: the planner errored (timeout, parse,
	// auth) or an internal error occurred.
	StatusFailed Status = "failed"
	// StatusCancelled is a terminal state: the user cancelled the job.
	StatusCancelled Status = "cancelled"
)

// terminal reports whether a status is final and cannot transition further.
func (s Status) terminal() bool {
	switch s {
	case StatusObserved, StatusNeedsTarget, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// Job is the in-memory view of one action job: the persisted ledger row plus
// its event trail. It is the shape returned by Submit/Get/List/Cancel.
type Job struct {
	ID          string    `json:"id"`
	RequestText string    `json:"request_text"`
	Worker      Worker    `json:"worker"`
	Status      Status    `json:"status"`
	Result      string    `json:"result,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Events      []Event   `json:"events,omitempty"`
}

// Event is one entry in a job's append-only evidence/lifecycle trail.
type Event struct {
	Seq       int64     `json:"seq"`
	Type      string    `json:"type"`
	Message   string    `json:"message,omitempty"`
	Data      string    `json:"data,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Request is the planner input: the resolved job identity and the raw command
// text. The planner is deliberately given only what Phase 1 needs; richer
// evidence/grounding is added at the planner boundary in Phase 4.
type Request struct {
	JobID  string
	Text   string
	Worker Worker
}

// PlannerEvent lets a planner attach observation/evidence rows to the job
// trail (e.g. "checked docker ps", "no matching container"). They are recorded
// verbatim as job events.
type PlannerEvent struct {
	Type    string
	Message string
	Data    string
}

// Result is the planner's structured, read-only outcome. Status MUST be either
// StatusObserved or StatusNeedsTarget; any other value is treated as an
// invalid plan and the job is failed. Phase 1 carries no executable steps.
type Result struct {
	Status  Status
	Summary string
	Events  []PlannerEvent
}

// Planner is the AI bridge. Implementations form a prompt from the request,
// invoke the model (or, in Phase 1, a read-only/stub planner), and return a
// structured read-only Result. A returned error means the planner itself
// failed; the orchestrator records it and fails the job.
type Planner interface {
	Plan(ctx context.Context, req Request) (Result, error)
}

// PlannerFunc adapts a plain function to Planner.
type PlannerFunc func(ctx context.Context, req Request) (Result, error)

func (f PlannerFunc) Plan(ctx context.Context, req Request) (Result, error) { return f(ctx, req) }

// Store is the persistence surface the orchestrator needs. *store.Store
// satisfies it; tests can supply a fake.
type Store interface {
	CreateActionJob(j store.ActionJob) error
	GetActionJob(id string) (store.ActionJob, error)
	ListActionJobs() ([]store.ActionJob, error)
	UpdateActionJob(id, status, result string, updatedAt time.Time) error
	AppendActionJobEvent(event store.ActionJobEvent) (store.ActionJobEvent, error)
	ActionJobEvents(jobID string) ([]store.ActionJobEvent, error)
}

// Config wires a Manager. Store and Planner are required; Notifications, Now,
// IDFunc, and Dispatch have sensible defaults.
type Config struct {
	Store   Store
	Planner Planner
	// Notifications, when non-nil, receives a completion notification with a
	// deep link when a job reaches a terminal state.
	Notifications notifications.Sink
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
	// IDFunc mints job IDs. Defaults to a 12-byte random hex id.
	IDFunc func() string
	// Dispatch runs the planning work for a submitted job. Defaults to running
	// it in a new goroutine so Submit returns immediately. Tests inject an
	// inline dispatcher for determinism.
	Dispatch func(func())
}

// Manager is the Action Orchestrator. It is safe for concurrent use; all
// shared state lives in the Store.
type Manager struct {
	cfg Config
}

// New constructs a Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.Store == nil {
		return nil, errors.New("actions: Store required")
	}
	if cfg.Planner == nil {
		return nil, errors.New("actions: Planner required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.IDFunc == nil {
		cfg.IDFunc = randomID
	}
	if cfg.Dispatch == nil {
		cfg.Dispatch = func(f func()) { go f() }
	}
	return &Manager{cfg: cfg}, nil
}

// Submit accepts a new action request, persists it as a submitted job, records
// the "submitted" event, and dispatches read-only planning. It returns the
// freshly created job (status submitted, no planner output yet).
func (m *Manager) Submit(ctx context.Context, text string, worker Worker) (Job, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Job{}, errors.New("actions: request text required")
	}
	if worker == "" {
		worker = WorkerAuto
	}
	if !validWorker(worker) {
		return Job{}, fmt.Errorf("actions: unknown worker %q", worker)
	}

	now := m.cfg.Now()
	row := store.ActionJob{
		ID:          m.cfg.IDFunc(),
		RequestText: text,
		Worker:      string(worker),
		Status:      string(StatusSubmitted),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := m.cfg.Store.CreateActionJob(row); err != nil {
		return Job{}, err
	}
	m.appendEvent(row.ID, "submitted", "action submitted", "")

	id := row.ID
	m.cfg.Dispatch(func() { m.process(context.Background(), id) })

	return m.Get(id)
}

// process runs the read-only planner for a job and records the outcome. It is
// the unit-testable core of the lifecycle: tests inject an inline Dispatch so
// this runs synchronously inside Submit, or call it indirectly via Submit.
func (m *Manager) process(ctx context.Context, id string) {
	row, err := m.cfg.Store.GetActionJob(id)
	if err != nil {
		return
	}
	// A job cancelled before planning started must not be revived.
	if Status(row.Status).terminal() {
		return
	}

	m.transition(id, StatusPlanning, "")
	m.appendEvent(id, "planning", "gathering read-only observations", "")

	res, err := m.cfg.Planner.Plan(ctx, Request{
		JobID:  id,
		Text:   row.RequestText,
		Worker: Worker(row.Worker),
	})
	if err != nil {
		m.fail(id, "planner failed: "+err.Error())
		return
	}
	for _, ev := range res.Events {
		t := ev.Type
		if t == "" {
			t = "observation"
		}
		m.appendEvent(id, t, ev.Message, ev.Data)
	}

	// Re-check for a concurrent cancel before writing the terminal state.
	if cur, err := m.cfg.Store.GetActionJob(id); err == nil && Status(cur.Status) == StatusCancelled {
		return
	}

	switch res.Status {
	case StatusObserved, StatusNeedsTarget:
		m.transition(id, res.Status, res.Summary)
		m.appendEvent(id, string(res.Status), res.Summary, "")
		m.notifyTerminal(ctx, id, res.Status, res.Summary)
	default:
		m.fail(id, fmt.Sprintf("planner returned invalid status %q", res.Status))
	}
}

// Cancel marks a non-terminal job cancelled. Cancelling a terminal job is a
// no-op that returns the job unchanged.
func (m *Manager) Cancel(id string) (Job, error) {
	row, err := m.cfg.Store.GetActionJob(id)
	if err != nil {
		return Job{}, err
	}
	if Status(row.Status).terminal() {
		return m.Get(id)
	}
	m.transition(id, StatusCancelled, row.Result)
	m.appendEvent(id, "cancelled", "cancelled by user", "")
	return m.Get(id)
}

// Get returns one job with its full event trail.
func (m *Manager) Get(id string) (Job, error) {
	row, err := m.cfg.Store.GetActionJob(id)
	if err != nil {
		return Job{}, err
	}
	events, err := m.cfg.Store.ActionJobEvents(id)
	if err != nil {
		return Job{}, err
	}
	return toJob(row, events), nil
}

// List returns all jobs newest-first. Event trails are omitted for brevity;
// call Get for a single job's events.
func (m *Manager) List() ([]Job, error) {
	rows, err := m.cfg.Store.ListActionJobs()
	if err != nil {
		return nil, err
	}
	out := make([]Job, 0, len(rows))
	for _, r := range rows {
		out = append(out, toJob(r, nil))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (m *Manager) transition(id string, status Status, result string) {
	_ = m.cfg.Store.UpdateActionJob(id, string(status), result, m.cfg.Now())
}

func (m *Manager) fail(id, msg string) {
	m.transition(id, StatusFailed, msg)
	m.appendEvent(id, "failed", msg, "")
}

func (m *Manager) appendEvent(jobID, typ, message, data string) {
	_, _ = m.cfg.Store.AppendActionJobEvent(store.ActionJobEvent{
		JobID:     jobID,
		Type:      typ,
		Message:   message,
		Data:      data,
		CreatedAt: m.cfg.Now(),
	})
}

// notifyTerminal emits a single completion notification with a deep link to
// the job detail screen. Phase 1 jobs are read-only, so the body never claims a
// fix was applied.
func (m *Manager) notifyTerminal(ctx context.Context, id string, status Status, summary string) {
	if m.cfg.Notifications == nil {
		return
	}
	body := summary
	if body == "" {
		if status == StatusNeedsTarget {
			body = "could not resolve the target"
		} else {
			body = "observation complete"
		}
	}
	_ = m.cfg.Notifications.Publish(ctx, notifications.Notification{
		ID:        "action-" + id,
		Type:      "action.completed",
		Title:     "Action " + string(status),
		Body:      body,
		Severity:  "info",
		CreatedAt: m.cfg.Now(),
		Data: map[string]any{
			"job_id":    id,
			"status":    string(status),
			"deep_link": "action/" + id,
		},
	})
}

func toJob(row store.ActionJob, events []store.ActionJobEvent) Job {
	j := Job{
		ID:          row.ID,
		RequestText: row.RequestText,
		Worker:      Worker(row.Worker),
		Status:      Status(row.Status),
		Result:      row.Result,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
	for _, e := range events {
		j.Events = append(j.Events, Event{
			Seq:       e.Seq,
			Type:      e.Type,
			Message:   e.Message,
			Data:      e.Data,
			CreatedAt: e.CreatedAt,
		})
	}
	return j
}

func randomID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
