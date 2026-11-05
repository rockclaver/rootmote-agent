package store

import (
	"errors"
	"testing"
	"time"
)

func TestIncidentBinding_FirstWriteWins(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first := IncidentBinding{IncidentID: "inc-1", MonitorKind: "systemd_unit", Target: "nginx.service", Severity: "critical", Summary: "nginx failed", EventID: "mevt_1"}
	created, err := s.PutIncidentBinding(first)
	if err != nil || !created {
		t.Fatalf("first put = %v, %v; want created", created, err)
	}
	created, err = s.PutIncidentBinding(IncidentBinding{IncidentID: "inc-1", MonitorKind: "docker_container", Target: "other"})
	if err != nil || created {
		t.Fatalf("second put = %v, %v; want not created", created, err)
	}
	got, err := s.GetIncidentBinding("inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.MonitorKind != "systemd_unit" || got.Target != "nginx.service" || got.Summary != "nginx failed" || got.EventID != "mevt_1" {
		t.Fatalf("binding = %+v, want the first one", got)
	}
	if _, err := s.GetIncidentBinding("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing binding error = %v, want ErrNotFound", err)
	}
}

func TestExecutionsForIncident_NewestFirstAndPrimaryOnly(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Unix(1_700_000_000, 0)
	mk := func(id, incident, kind string, at time.Duration) {
		t.Helper()
		_, _, err := s.CreateExecution(RemediationExecution{
			ID: id, IncidentID: incident, RunbookID: "rb-" + id, RunbookHash: "h", Status: RemediationProposed,
			Kind: kind, CreatedAt: base.Add(at),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	mk("a", "inc-1", RemediationKindExecute, 0)
	mk("b", "inc-1", RemediationKindExecute, time.Minute)
	mk("c", "inc-1", RemediationKindRollback, 2*time.Minute)
	mk("d", "inc-2", RemediationKindExecute, 3*time.Minute)

	got, err := s.ExecutionsForIncident("inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "b" || got[1].ID != "a" {
		t.Fatalf("executions = %+v, want b then a (no rollback, no other incident)", got)
	}
}
