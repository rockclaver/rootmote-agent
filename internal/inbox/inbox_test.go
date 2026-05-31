package inbox

import (
	"context"
	"testing"
	"time"

	"github.com/rockclaver/claver/agent/internal/notifications"
)

func staticSource(items ...Item) Source {
	return SourceFunc(func(ctx context.Context) ([]Item, error) {
		return items, nil
	})
}

func mkItem(id string, t time.Time) Item {
	return Item{ID: id, CreatedAt: t, Type: TypeAlertFired, Title: id}
}

func TestList_SortsNewestFirstWithStableTieBreak(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	m := New()
	// Same timestamp pair — tie-break must be deterministic on ID.
	m.AddSource(staticSource(
		mkItem("b", base.Add(2*time.Second)),
		mkItem("a", base.Add(2*time.Second)),
		mkItem("z", base.Add(1*time.Second)),
		mkItem("y", base),
	))
	res, err := m.List(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := []string{}
	for _, it := range res.Items {
		got = append(got, it.ID)
	}
	// Newest first; within the same ms, ascending ID.
	want := []string{"a", "b", "z", "y"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: %v vs %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("order mismatch at %d: got %v want %v", i, got, want)
		}
	}
}

func TestList_DedupesByID(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	m := New()
	m.AddSource(staticSource(mkItem("dup", base)))
	m.AddSource(staticSource(mkItem("dup", base.Add(time.Minute))))
	res, _ := m.List(context.Background(), "", 0)
	if len(res.Items) != 1 {
		t.Fatalf("expected 1 deduped item, got %d", len(res.Items))
	}
}

func TestList_CursorPaginationIsStable(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	m := New()
	items := []Item{}
	for i := 0; i < 10; i++ {
		items = append(items, mkItem(string(rune('a'+i)), base.Add(time.Duration(i)*time.Second)))
	}
	m.AddSource(staticSource(items...))

	// First page of 3 then walk pages until exhausted; collected order
	// must match a single full-list call.
	full, _ := m.List(context.Background(), "", 0)
	var paged []Item
	cursor := ""
	for {
		page, err := m.List(context.Background(), cursor, 3)
		if err != nil {
			t.Fatalf("page list: %v", err)
		}
		paged = append(paged, page.Items...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(paged) != len(full.Items) {
		t.Fatalf("paged len %d vs full %d", len(paged), len(full.Items))
	}
	for i := range paged {
		if paged[i].ID != full.Items[i].ID {
			t.Fatalf("page divergence at %d: %s vs %s", i, paged[i].ID, full.Items[i].ID)
		}
	}
}

func TestList_LimitClampedAndEmptyItemsNeverNil(t *testing.T) {
	m := New()
	res, _ := m.List(context.Background(), "", 1000)
	if res.Items == nil {
		t.Fatalf("Items should be non-nil empty slice")
	}
	if len(res.Items) != 0 {
		t.Fatalf("expected 0 items")
	}
}

func TestSubscribe_PublishDelivers(t *testing.T) {
	m := New()
	ctx := context.Background()
	ch, cleanup := m.Subscribe(ctx)
	defer cleanup()
	want := mkItem("x", time.Now())
	m.Publish(want)
	select {
	case got := <-ch:
		if got.ID != want.ID {
			t.Fatalf("got %s want %s", got.ID, want.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("publish did not deliver to subscriber")
	}
}

func TestSubscribe_CleanupCloses(t *testing.T) {
	m := New()
	ch, cleanup := m.Subscribe(context.Background())
	cleanup()
	if _, ok := <-ch; ok {
		t.Fatal("channel should be closed after cleanup")
	}
	// Double cleanup is a no-op.
	cleanup()
}

func TestBridgeAlertNotifications_AlertFiringHitsFeedWithinOneTick(t *testing.T) {
	// Integration AC: an alert firing must appear in the feed within one
	// streaming tick. The hub publishes synchronously, so "one tick" is
	// effectively "before the next select".
	hub := notifications.NewHub()
	m := New()
	cleanup := BridgeAlertNotifications(hub, m)
	defer cleanup()
	ch, sub := m.Subscribe(context.Background())
	defer sub()

	when := time.Unix(1_700_000_500, 0)
	_ = hub.Publish(context.Background(), notifications.Notification{
		ID:        "infra-alert-123",
		Type:      "infra.alert",
		Title:     "Disk full",
		Body:      "Disk /var usage 95.0%",
		Severity:  "warning",
		CreatedAt: when,
		Data: map[string]any{
			"rule":   "disk_usage",
			"target": "/var",
			"clear":  false,
		},
	})

	select {
	case got := <-ch:
		if got.Type != TypeAlertFired {
			t.Fatalf("type=%s want %s", got.Type, TypeAlertFired)
		}
		if got.ID != "alert:disk_usage:/var" {
			t.Fatalf("id=%s", got.ID)
		}
		if !got.CreatedAt.Equal(when) {
			t.Fatalf("createdAt mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("alert firing did not reach inbox stream")
	}
}

func TestBridgeAlertNotifications_IgnoresClearedAlerts(t *testing.T) {
	hub := notifications.NewHub()
	m := New()
	defer BridgeAlertNotifications(hub, m)()
	ch, sub := m.Subscribe(context.Background())
	defer sub()
	_ = hub.Publish(context.Background(), notifications.Notification{
		Type:     "infra.alert",
		Severity: "resolved",
		Data:     map[string]any{"clear": true, "rule": "disk_usage", "target": "/var"},
	})
	select {
	case it := <-ch:
		t.Fatalf("did not expect cleared alert to surface: %+v", it)
	case <-time.After(50 * time.Millisecond):
	}
}
