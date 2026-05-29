package server

import (
	"testing"
	"time"
)

func TestIDSet_AddReturnsTrueOnSecondHit(t *testing.T) {
	now := time.Unix(0, 0)
	set := newIDSet(64, time.Minute, func() time.Time { return now })
	if set.add("x") {
		t.Fatal("first add should report not-present")
	}
	if !set.add("x") {
		t.Fatal("second add should report present")
	}
}

func TestIDSet_TTLExpiresEntries(t *testing.T) {
	now := time.Unix(0, 0)
	set := newIDSet(64, time.Minute, func() time.Time { return now })
	set.add("x")
	now = now.Add(2 * time.Minute)
	if set.add("x") {
		t.Fatal("entry should have expired after TTL")
	}
}

func TestIDSet_CapEvictsOldest(t *testing.T) {
	now := time.Unix(0, 0)
	set := newIDSet(3, time.Hour, func() time.Time { return now })
	for _, k := range []string{"a", "b", "c"} {
		now = now.Add(time.Millisecond)
		set.add(k)
	}
	now = now.Add(time.Millisecond)
	set.add("d") // evicts "a"
	if set.add("a") {
		t.Fatal("oldest entry should have been evicted under cap pressure")
	}
}
