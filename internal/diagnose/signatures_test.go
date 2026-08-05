package diagnose

import (
	"reflect"
	"testing"
	"time"
)

func TestMatch_DetectsEverySignatureType(t *testing.T) {
	fixed := time.Date(2026, 8, 5, 12, 47, 0, 0, time.UTC)

	cases := []struct {
		name       string
		bundle     Bundle
		wantType   string
		wantEvidID string
	}{
		{
			name:       "container_restart_loop",
			bundle:     Bundle{Signals: []Signal{{ID: "sig_container_restart_loop", Type: "container_restart_loop", Value: 5}}},
			wantType:   "container_restart_loop",
			wantEvidID: "sig_container_restart_loop",
		},
		{
			name:       "oom_kill",
			bundle:     Bundle{Signals: []Signal{{ID: "sig_oom_kill", Type: "oom_kill", Value: 2}}},
			wantType:   "oom_kill",
			wantEvidID: "sig_oom_kill",
		},
		{
			name:       "container_stopped",
			bundle:     Bundle{Components: []Component{{ID: "cmp_docker_api", Kind: "docker_container", Name: "api", State: "exited"}}},
			wantType:   "container_stopped",
			wantEvidID: "cmp_docker_api",
		},
		{
			name:       "unit_failed",
			bundle:     Bundle{Components: []Component{{ID: "cmp_systemd_myservice", Kind: "systemd_unit", Name: "myservice", State: "failed"}}},
			wantType:   "unit_failed",
			wantEvidID: "cmp_systemd_myservice",
		},
		{
			name:       "disk_exhausted",
			bundle:     Bundle{Metrics: []Metric{{ID: "met_disk_used_percent_root", Name: "disk_used_percent", Value: 95}}},
			wantType:   "disk_exhausted",
			wantEvidID: "met_disk_used_percent_root",
		},
		{
			name:       "inode_exhausted",
			bundle:     Bundle{Metrics: []Metric{{ID: "met_inode_used_percent_root", Name: "inode_used_percent", Value: 97}}},
			wantType:   "inode_exhausted",
			wantEvidID: "met_inode_used_percent_root",
		},
		{
			name:       "memory_pressure",
			bundle:     Bundle{Metrics: []Metric{{ID: "met_available_memory_percent", Name: "available_memory_percent", Value: 3}}},
			wantType:   "memory_pressure",
			wantEvidID: "met_available_memory_percent",
		},
		{
			name:       "recent_deployment",
			bundle:     Bundle{RecentChanges: []Change{{ID: "chg_container_restart_1", Type: "container_restart", OccurredAt: fixed, Detail: "api restarted"}}},
			wantType:   "recent_deployment",
			wantEvidID: "chg_container_restart_1",
		},
		{
			name:       "proxy_upstream_error",
			bundle:     Bundle{Logs: []LogExcerpt{{ID: "log_docker_api", Content: "upstream timed out while reading response header from upstream"}}},
			wantType:   "proxy_upstream_error",
			wantEvidID: "log_docker_api",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigs := Match(tc.bundle)
			if len(sigs) != 1 {
				t.Fatalf("Match returned %d signatures, want 1: %+v", len(sigs), sigs)
			}
			if sigs[0].Type != tc.wantType {
				t.Fatalf("Type = %q, want %q", sigs[0].Type, tc.wantType)
			}
			if !reflect.DeepEqual(sigs[0].EvidenceIDs, []string{tc.wantEvidID}) {
				t.Fatalf("EvidenceIDs = %v, want [%q]", sigs[0].EvidenceIDs, tc.wantEvidID)
			}
			if sigs[0].Confidence <= 0 || sigs[0].Confidence > 1 {
				t.Fatalf("Confidence = %v, want in (0,1]", sigs[0].Confidence)
			}
			if sigs[0].Title == "" {
				t.Fatal("Title is empty")
			}
		})
	}
}

func TestMatch_OnlyReferencesEvidenceIdsPresentInTheBundle(t *testing.T) {
	fixed := time.Date(2026, 8, 5, 12, 47, 0, 0, time.UTC)
	b := Bundle{
		Signals: []Signal{
			{ID: "sig_container_restart_loop", Type: "container_restart_loop", Value: 7},
			{ID: "sig_oom_kill", Type: "oom_kill", Value: 1},
		},
		Components: []Component{
			{ID: "cmp_docker_api", Kind: "docker_container", Name: "api", State: "exited"},
			{ID: "cmp_systemd_myservice", Kind: "systemd_unit", Name: "myservice", State: "failed"},
		},
		Metrics: []Metric{
			{ID: "met_disk_used_percent_root", Name: "disk_used_percent", Value: 96},
			{ID: "met_available_memory_percent", Name: "available_memory_percent", Value: 4},
		},
		RecentChanges: []Change{
			{ID: "chg_container_restart_1", Type: "container_restart", OccurredAt: fixed, Detail: "api restarted"},
		},
		Logs: []LogExcerpt{
			{ID: "log_docker_api", Content: "502 Bad Gateway from upstream"},
		},
	}

	known := map[string]bool{}
	for _, id := range b.EvidenceIDs() {
		known[id] = true
	}

	sigs := Match(b)
	if len(sigs) == 0 {
		t.Fatal("Match returned no signatures for a bundle designed to trigger every type")
	}
	for _, s := range sigs {
		if len(s.EvidenceIDs) == 0 {
			t.Fatalf("signature %+v has no evidenceIds", s)
		}
		for _, id := range s.EvidenceIDs {
			if !known[id] {
				t.Fatalf("signature %+v references unknown evidence id %q (bundle has %v)", s, id, b.EvidenceIDs())
			}
		}
	}
}

func TestMatch_IsStableAndSortedByConfidence(t *testing.T) {
	b := Bundle{
		Signals: []Signal{
			{ID: "sig_oom_kill", Type: "oom_kill", Value: 1},                              // confidence 1.0
			{ID: "sig_container_restart_loop", Type: "container_restart_loop", Value: 12}, // confidence 0.95
		},
		Components: []Component{
			{ID: "cmp_docker_api", Kind: "docker_container", Name: "api", State: "exited"},          // confidence 0.85
			{ID: "cmp_systemd_myservice", Kind: "systemd_unit", Name: "myservice", State: "failed"}, // confidence 0.9
		},
		RecentChanges: []Change{
			{ID: "chg_container_restart_1", Type: "container_restart", Detail: "api restarted"}, // confidence 0.5
		},
	}

	sigs1 := Match(b)
	sigs2 := Match(b)
	if !reflect.DeepEqual(sigs1, sigs2) {
		t.Fatalf("Match is not stable across calls:\n%+v\n%+v", sigs1, sigs2)
	}

	for i := 1; i < len(sigs1); i++ {
		prev, cur := sigs1[i-1], sigs1[i]
		if prev.Confidence < cur.Confidence {
			t.Fatalf("signatures not sorted by descending confidence at index %d: %+v then %+v", i, prev, cur)
		}
		if prev.Confidence == cur.Confidence && prev.ID > cur.ID {
			t.Fatalf("equal-confidence signatures not sorted by ascending ID at index %d: %+v then %+v", i, prev, cur)
		}
	}
	if sigs1[0].Type != "oom_kill" {
		t.Fatalf("highest-confidence signature = %q, want oom_kill", sigs1[0].Type)
	}
}

func TestMatch_EmptyBundleYieldsNoSignatures(t *testing.T) {
	if sigs := Match(Bundle{}); len(sigs) != 0 {
		t.Fatalf("Match(Bundle{}) = %+v, want empty", sigs)
	}
}
