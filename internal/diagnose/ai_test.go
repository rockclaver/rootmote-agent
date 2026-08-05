package diagnose

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
)

func sampleBundle() Bundle {
	return Bundle{
		IncidentID: "inc_01",
		CapturedAt: time.Date(2026, 8, 5, 12, 47, 0, 0, time.UTC),
		Service:    Service{Name: "api", Kind: "docker_container", Status: "down"},
		Redaction:  redact.Report{Applied: true, Rules: []string{redact.RuleEnvValue}},
		Signals: []Signal{
			{ID: "sig_container_restart_loop", Type: "container_restart_loop", Value: 5, WindowSeconds: 240, Detail: "api restarted 5 times in 4m"},
		},
		Logs: []LogExcerpt{
			{ID: "log_docker_api", Source: "docker:api", LineCount: 200, Redacted: true, Content: "exit code 137"},
		},
		Components: []Component{
			{ID: "cmp_docker_api", Kind: "docker_container", Name: "api", State: "restarting", Health: "unhealthy", Detail: "exit code 137"},
		},
		Metrics: []Metric{
			{ID: "met_available_memory_percent", Name: "available_memory_percent", Value: 2.8, Unit: "%"},
		},
	}
}

func sampleSignatures() []Signature {
	return []Signature{
		{ID: "sig_oom_kill", Type: "oom_kill", Title: "Kernel OOM-killed api", EvidenceIDs: []string{"log_docker_api"}, Confidence: 1.0},
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

func TestBuildPrompt_ListsValidEvidenceIdsAndProhibitions(t *testing.T) {
	b := sampleBundle()
	sigs := sampleSignatures()
	prompt := BuildPrompt(b, sigs)

	for _, id := range b.EvidenceIDs() {
		if !strings.Contains(prompt, id) {
			t.Fatalf("prompt does not list valid evidence id %q:\n%s", id, prompt)
		}
	}
	for _, want := range []string{
		"evidenceId",   // every hypothesis cites evidence
		"never invent", // never invent command output
		"never claim",  // never claim resolution before verification
	} {
		if !strings.Contains(strings.ToLower(prompt), strings.ToLower(want)) {
			t.Fatalf("prompt missing required instruction %q:\n%s", want, prompt)
		}
	}
}

func TestParseAssessment_AcceptsSchemaConformantOutput(t *testing.T) {
	b := sampleBundle()
	sigs := sampleSignatures()
	validJSON := mustJSON(t, map[string]any{
		"summary":       "The API container is being killed because the host has exhausted available memory.",
		"impact":        "The public API is unavailable.",
		"confidence":    0.93,
		"probableCause": "Container exceeded available host memory",
		"hypotheses": []map[string]any{
			{"cause": "Container exceeded available host memory", "confidence": 0.93,
				"evidenceIds": []string{"sig_container_restart_loop", "log_docker_api"}},
		},
		"recommendedActions": []map[string]any{
			{"actionId": "restart_api_after_memory_reclaim", "risk": "medium",
				"reason": "Reclaiming memory and restarting should restore service.", "requiresApproval": true},
		},
		"missingEvidence": []string{"container memory limit"},
	})

	cases := []struct {
		name string
		raw  string
	}{
		{"direct json", validJSON},
		{"markdown fenced", "```json\n" + validJSON + "\n```"},
		{"claude result envelope", mustJSON(t, map[string]string{"result": validJSON})},
		{"embedded in prose", "Here is my assessment:\n" + validJSON + "\nLet me know if you need more."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := ParseAssessment(tc.raw, b, sigs)
			if err != nil {
				t.Fatalf("ParseAssessment: %v", err)
			}
			if !a.AIAvailable {
				t.Fatalf("assessment.AIAvailable = false, want true")
			}
			if a.SummaryText == "" || a.Confidence != 0.93 {
				t.Fatalf("assessment fields not parsed: %+v", a)
			}
			if a.IncidentID != b.IncidentID || !a.CapturedAt.Equal(b.CapturedAt) || a.Service != b.Service {
				t.Fatalf("assessment envelope fields not filled from bundle: %+v", a)
			}
			if len(a.Signatures) != len(sigs) || a.Signatures[0].ID != sigs[0].ID {
				t.Fatalf("assessment.Signatures = %+v, want the deterministic sigs passed in", a.Signatures)
			}
			if len(a.Hypotheses) != 1 || len(a.Hypotheses[0].EvidenceIDs) != 2 {
				t.Fatalf("assessment.Hypotheses = %+v", a.Hypotheses)
			}
		})
	}
}

func TestParseAssessment_RejectsEachSchemaViolation(t *testing.T) {
	b := sampleBundle()
	sigs := sampleSignatures()

	cases := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{
			name:    "unparseable prose",
			raw:     "the container looks unhealthy, not sure why",
			wantErr: ErrAIOutputUnparseable,
		},
		{
			name:    "non-object top level (json array)",
			raw:     `["summary", "not an object"]`,
			wantErr: ErrAIOutputUnparseable,
		},
		{
			name: "empty summary",
			raw: mustJSON(t, map[string]any{
				"summary": "", "confidence": 0.8,
				"hypotheses": []map[string]any{{"cause": "x", "confidence": 0.8, "evidenceIds": []string{"log_docker_api"}}},
			}),
			wantErr: ErrAIEmptySummary,
		},
		{
			name: "confidence above 1",
			raw: mustJSON(t, map[string]any{
				"summary": "api is down", "confidence": 1.5,
				"hypotheses": []map[string]any{{"cause": "x", "confidence": 0.8, "evidenceIds": []string{"log_docker_api"}}},
			}),
			wantErr: ErrAIConfidenceOutOfRange,
		},
		{
			name: "confidence below 0",
			raw: mustJSON(t, map[string]any{
				"summary": "api is down", "confidence": -0.1,
				"hypotheses": []map[string]any{{"cause": "x", "confidence": 0.8, "evidenceIds": []string{"log_docker_api"}}},
			}),
			wantErr: ErrAIConfidenceOutOfRange,
		},
		{
			name: "zero hypotheses",
			raw: mustJSON(t, map[string]any{
				"summary": "api is down", "confidence": 0.8, "hypotheses": []map[string]any{},
			}),
			wantErr: ErrAINoHypotheses,
		},
		{
			name: "hypothesis with no evidenceIds",
			raw: mustJSON(t, map[string]any{
				"summary": "api is down", "confidence": 0.8,
				"hypotheses": []map[string]any{{"cause": "x", "confidence": 0.8, "evidenceIds": []string{}}},
			}),
			wantErr: ErrAIHypothesisNoEvidence,
		},
		{
			name: "hypothesis referencing unknown evidence id",
			raw: mustJSON(t, map[string]any{
				"summary": "api is down", "confidence": 0.8,
				"hypotheses": []map[string]any{{"cause": "x", "confidence": 0.8, "evidenceIds": []string{"log_does_not_exist"}}},
			}),
			wantErr: ErrAIUnknownEvidenceID,
		},
		{
			name: "recommendedActions risk outside low|medium|high",
			raw: mustJSON(t, map[string]any{
				"summary": "api is down", "confidence": 0.8,
				"hypotheses":         []map[string]any{{"cause": "x", "confidence": 0.8, "evidenceIds": []string{"log_docker_api"}}},
				"recommendedActions": []map[string]any{{"actionId": "a", "risk": "critical", "reason": "r", "requiresApproval": true}},
			}),
			wantErr: ErrAIInvalidRisk,
		},
		{
			name: "summary claims resolution",
			raw: mustJSON(t, map[string]any{
				"summary": "The issue is now resolved.", "confidence": 0.8,
				"hypotheses": []map[string]any{{"cause": "x", "confidence": 0.8, "evidenceIds": []string{"log_docker_api"}}},
			}),
			wantErr: ErrAIClaimsResolution,
		},
		{
			name: "impact claims resolution",
			raw: mustJSON(t, map[string]any{
				"summary": "api container is down", "impact": "The API is back online now.", "confidence": 0.8,
				"hypotheses": []map[string]any{{"cause": "x", "confidence": 0.8, "evidenceIds": []string{"log_docker_api"}}},
			}),
			wantErr: ErrAIClaimsResolution,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAssessment(tc.raw, b, sigs)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseAssessment(%s) err = %v, want errors.Is(_, %v)", tc.name, err, tc.wantErr)
			}
		})
	}

	// Every case above must be a genuinely distinct error value so callers
	// can tell rejection modes apart -- not just distinct strings that all
	// happen to wrap the same sentinel.
	seen := map[error]bool{}
	for _, tc := range cases {
		seen[tc.wantErr] = true
	}
	if len(seen) < 7 {
		t.Fatalf("only %d distinct sentinel errors exercised across %d cases, want each schema violation to have its own", len(seen), len(cases))
	}
}

func TestParseAssessment_RejectsHypothesisCitingUnknownEvidence(t *testing.T) {
	b := sampleBundle()
	sigs := sampleSignatures()
	raw := mustJSON(t, map[string]any{
		"summary":    "api container is down",
		"confidence": 0.8,
		"hypotheses": []map[string]any{
			{"cause": "unrelated theory", "confidence": 0.5, "evidenceIds": []string{"sig_totally_made_up"}},
		},
	})
	_, err := ParseAssessment(raw, b, sigs)
	if !errors.Is(err, ErrAIUnknownEvidenceID) {
		t.Fatalf("err = %v, want ErrAIUnknownEvidenceID", err)
	}
	if !strings.Contains(err.Error(), "sig_totally_made_up") {
		t.Fatalf("err = %v, want it to name the offending id", err)
	}
}

func TestParseAssessment_RejectsResolutionClaims(t *testing.T) {
	b := sampleBundle()
	sigs := sampleSignatures()
	for _, phrase := range []string{
		"The container is fixed now.",
		"The container has been repaired.",
		"The service is back online.",
		"The issue is now handled.",
	} {
		raw := mustJSON(t, map[string]any{
			"summary":    phrase,
			"confidence": 0.8,
			"hypotheses": []map[string]any{{"cause": "x", "confidence": 0.8, "evidenceIds": []string{"log_docker_api"}}},
		})
		if _, err := ParseAssessment(raw, b, sigs); !errors.Is(err, ErrAIClaimsResolution) {
			t.Fatalf("summary %q: err = %v, want ErrAIClaimsResolution", phrase, err)
		}
	}
}
