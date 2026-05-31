// Package inbox aggregates triage-worthy events from across the agent's
// subsystems (pending AI proposals, fired infra alerts, finished sessions,
// failed CI runs, PRs awaiting review) into a single chronologically-sorted
// feed that the mobile app renders as its home tab.
//
// The aggregation is per-agent: the mobile app calls inbox.list / inbox.stream
// on every connected server and merges client-side. This package is therefore
// only responsible for snapshotting and broadcasting one host's signals.
package inbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

// Type enumerates the source types of inbox items.
type Type string

const (
	TypeAIProposal      Type = "ai_proposal"
	TypeAlertFired      Type = "alert_fired"
	TypeSessionFinished Type = "session_finished"
	TypeCIFailed        Type = "ci_failed"
	TypePRReview        Type = "pr_review"
)

// Item is one entry in the unified feed.
//
// ID must be stable across calls for the same underlying entity so the client
// can dedupe, persist dismissals, and merge stream updates with list results.
// Convention: "<type>:<source-stable-id>".
type Item struct {
	ID         string         `json:"id"`
	Type       Type           `json:"type"`
	Title      string         `json:"title"`
	Body       string         `json:"body"`
	Severity   string         `json:"severity,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	Actionable bool           `json:"actionable"`
	ActionKind string         `json:"action_kind,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
}

// Source produces the current set of items for one signal kind. Sources are
// polled on every inbox.list call so they must be cheap (in-memory queries on
// already-loaded managers, not network round-trips).
type Source interface {
	Items(ctx context.Context) ([]Item, error)
}

// SourceFunc adapts a plain function to Source.
type SourceFunc func(ctx context.Context) ([]Item, error)

func (f SourceFunc) Items(ctx context.Context) ([]Item, error) { return f(ctx) }

// Manager owns the inbox subsystem. It has no persistence: dismissals are a
// per-device concern handled by the mobile client.
type Manager struct {
	mu      sync.Mutex
	sources []Source
	subs    map[int64]chan Item
	nextSub int64
}

// New constructs an empty Manager. Register sources with AddSource.
func New() *Manager {
	return &Manager{subs: make(map[int64]chan Item)}
}

// AddSource registers s. Safe to call before serving.
func (m *Manager) AddSource(s Source) {
	if s == nil {
		return
	}
	m.mu.Lock()
	m.sources = append(m.sources, s)
	m.mu.Unlock()
}

// Publish broadcasts item to all live subscribers. It is non-blocking: a slow
// subscriber that has filled its buffer simply misses this update (the next
// inbox.list refresh will recover state). Used by sources that emit on
// state-change events (e.g. an alert firing).
func (m *Manager) Publish(item Item) {
	m.mu.Lock()
	subs := make([]chan Item, 0, len(m.subs))
	for _, ch := range m.subs {
		subs = append(subs, ch)
	}
	m.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- item:
		default:
		}
	}
}

// Subscribe registers a new subscriber. The returned cleanup must be called
// to release resources. The channel is closed by cleanup.
func (m *Manager) Subscribe(ctx context.Context) (<-chan Item, func()) {
	ch := make(chan Item, 32)
	m.mu.Lock()
	m.nextSub++
	id := m.nextSub
	m.subs[id] = ch
	m.mu.Unlock()
	cleanup := func() {
		m.mu.Lock()
		if _, ok := m.subs[id]; ok {
			delete(m.subs, id)
			close(ch)
		}
		m.mu.Unlock()
	}
	return ch, cleanup
}

// cursor is the opaque pagination state. Items are sorted newest-first; the
// cursor records the position of the last item the client has already seen,
// and List returns items strictly older.
type cursor struct {
	AtMS int64  `json:"t"`
	ID   string `json:"i"`
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, error) {
	if s == "" {
		return cursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, errors.New("invalid cursor")
	}
	var c cursor
	if err := json.Unmarshal(b, &c); err != nil {
		return cursor{}, errors.New("invalid cursor")
	}
	return c, nil
}

// ListResult is the wire shape returned by List.
type ListResult struct {
	Items      []Item `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// List collects items from every source, sorts them newest-first with stable
// tie-breaking on ID, and returns at most limit items past after. limit is
// clamped to [1, 200] (default 50).
func (m *Manager) List(ctx context.Context, after string, limit int) (ListResult, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	cur, err := decodeCursor(after)
	if err != nil {
		return ListResult{}, err
	}

	m.mu.Lock()
	srcs := append([]Source(nil), m.sources...)
	m.mu.Unlock()

	merged := make([]Item, 0, 64)
	seen := make(map[string]struct{})
	for _, s := range srcs {
		items, err := s.Items(ctx)
		if err != nil {
			continue
		}
		for _, it := range items {
			if it.ID == "" {
				continue
			}
			if _, dup := seen[it.ID]; dup {
				continue
			}
			seen[it.ID] = struct{}{}
			merged = append(merged, it)
		}
	}

	sort.SliceStable(merged, func(i, j int) bool {
		ai, aj := merged[i].CreatedAt.UnixMilli(), merged[j].CreatedAt.UnixMilli()
		if ai != aj {
			return ai > aj // newest first
		}
		return merged[i].ID < merged[j].ID
	})

	if cur.AtMS != 0 || cur.ID != "" {
		idx := sort.Search(len(merged), func(i int) bool {
			ms := merged[i].CreatedAt.UnixMilli()
			if ms != cur.AtMS {
				return ms < cur.AtMS
			}
			return merged[i].ID > cur.ID
		})
		merged = merged[idx:]
	}

	out := ListResult{}
	if len(merged) > limit {
		page := merged[:limit]
		last := page[len(page)-1]
		out.Items = page
		out.NextCursor = encodeCursor(cursor{AtMS: last.CreatedAt.UnixMilli(), ID: last.ID})
	} else {
		out.Items = merged
	}
	if out.Items == nil {
		out.Items = []Item{}
	}
	return out, nil
}
