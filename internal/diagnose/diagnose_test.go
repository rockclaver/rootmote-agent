package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
	"github.com/rockclaver/rootmote-agent/internal/infra"
)

// aiFakeInfraSource returns a fixed HostMetrics snapshot and no OOM events, so
// tests can deterministically trigger the memory_pressure signature via the
// real Collector + Match without wiring real docker/systemd sources.
type aiFakeInfraSource struct{ hm infra.HostMetrics }

func (f aiFakeInfraSource) Sample(context.Context) infra.HostMetrics { return f.hm }
func (f aiFakeInfraSource) OOMEvents(context.Context, time.Time) ([]infra.OOMEvent, error) {
	return nil, nil
}

// recordingProposer captures the prompt it was given and returns a
// pre-programmed response/error, so tests can inspect what Run sent before
// asserting on the outcome.
type recordingProposer struct {
	provider   string
	lastPrompt string
	raw        string
	err        error
}

func (p *recordingProposer) Provider() string { return p.provider }
func (p *recordingProposer) Propose(_ context.Context, prompt string) (string, error) {
	p.lastPrompt = prompt
	return p.raw, p.err
}

// newDiagnoseTestPipeline builds a real Pipeline wired to a real Collector +
// Match (no fakes below the diagnose package boundary) so Run's contract is
// exercised end to end: a fixed low-available-memory HostMetrics reading
// deterministically produces exactly one memory_pressure Signature.
func newDiagnoseTestPipeline(t *testing.T, proposer Proposer, threshold float64) (*Pipeline, Target, time.Time) {
	t.Helper()
	redactor, err := redact.New(nil)
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	fixedNow := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	hm := infra.HostMetrics{
		Timestamp: fixedNow,
		Memory:    infra.MemoryMetric{MetricReason: infra.MetricReason{Available: true}, Percent: 97.2}, // available = 2.8%
	}
	collector := NewCollector(CollectorConfig{
		Infra:    aiFakeInfraSource{hm: hm},
		Redactor: redactor,
		Now:      func() time.Time { return fixedNow },
	})
	pipeline := NewPipeline(PipelineConfig{
		Collector:           collector,
		Proposer:            proposer,
		ConfidenceThreshold: threshold,
		Now:                 func() time.Time { return fixedNow },
	})
	target := Target{IncidentID: "inc_test", Target: "api"}
	return pipeline, target, fixedNow
}

func TestRun_DeterministicBeforeAI(t *testing.T) {
	proposer := &recordingProposer{provider: "test-ai"}
	pipeline, target, _ := newDiagnoseTestPipeline(t, proposer, DefaultConfidenceThreshold)

	// The proposer's canned response references the id of the evidence the
	// collector produces, so this only succeeds if collection + Match ran
	// before Propose was called.
	proposer.raw = mustJSON(t, map[string]any{
		"summary":    "Host memory pressure is starving the api container.",
		"confidence": 0.9,
		"hypotheses": []map[string]any{
			{"cause": "low available memory", "confidence": 0.9, "evidenceIds": []string{"met_available_memory_percent"}},
		},
	})

	assessment, bundle := pipeline.Run(context.Background(), target)

	if proposer.lastPrompt == "" {
		t.Fatal("Proposer.Propose was never called")
	}
	if !strings.Contains(proposer.lastPrompt, "sig_memory_pressure") {
		t.Fatalf("prompt sent to the AI is missing the deterministic signature id computed before the AI call:\n%s", proposer.lastPrompt)
	}
	if !strings.Contains(proposer.lastPrompt, "met_available_memory_percent") {
		t.Fatalf("prompt is missing the collected evidence id:\n%s", proposer.lastPrompt)
	}
	if !assessment.AIAvailable {
		t.Fatalf("assessment.AIAvailable = false, want true (proposer returned a valid response): %+v", assessment)
	}
	if len(bundle.EvidenceIDs()) == 0 {
		t.Fatal("bundle has no evidence -- collection did not run")
	}
}

func TestRun_WithoutProposerStillProducesAssessment(t *testing.T) {
	pipeline, target, _ := newDiagnoseTestPipeline(t, nil, DefaultConfidenceThreshold)

	assessment, bundle := pipeline.Run(context.Background(), target)

	if assessment.AIAvailable {
		t.Fatalf("assessment.AIAvailable = true with no Proposer configured: %+v", assessment)
	}
	if assessment.SummaryText == "" || assessment.Confidence <= 0 {
		t.Fatalf("deterministic assessment not populated: %+v", assessment)
	}
	if len(assessment.Hypotheses) == 0 {
		t.Fatalf("deterministic assessment has no hypotheses: %+v", assessment)
	}
	if len(bundle.Metrics) == 0 {
		t.Fatal("bundle has no metrics")
	}
}

func TestRun_AIUnavailableFallsBackToDeterministic(t *testing.T) {
	cases := []struct {
		name     string
		proposer *recordingProposer
	}{
		{name: "ErrAIUnavailable", proposer: &recordingProposer{provider: "x", err: ErrAIUnavailable}},
		{name: "transport error", proposer: &recordingProposer{provider: "x", err: errors.New("connection refused")}},
		{name: "schema-invalid response", proposer: &recordingProposer{provider: "x", raw: mustJSON(t, map[string]any{"summary": ""})}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pipeline, target, _ := newDiagnoseTestPipeline(t, tc.proposer, DefaultConfidenceThreshold)
			assessment, _ := pipeline.Run(context.Background(), target)
			if assessment.AIAvailable {
				t.Fatalf("assessment.AIAvailable = true, want false (AI failed): %+v", assessment)
			}
			if assessment.SummaryText == "" || assessment.Confidence <= 0 || len(assessment.Hypotheses) == 0 {
				t.Fatalf("deterministic fallback not populated: %+v", assessment)
			}
		})
	}
}

func TestRun_MarksLowConfidenceUncertain(t *testing.T) {
	lowThreshold, targetLow, _ := newDiagnoseTestPipeline(t, nil, 0.5)
	notUncertain, _ := lowThreshold.Run(context.Background(), targetLow)
	if notUncertain.Uncertain {
		t.Fatalf("Uncertain = true at confidence %.3f with threshold 0.5, want false", notUncertain.Confidence)
	}

	highThreshold, targetHigh, _ := newDiagnoseTestPipeline(t, nil, 0.99)
	uncertain, _ := highThreshold.Run(context.Background(), targetHigh)
	if !uncertain.Uncertain {
		t.Fatalf("Uncertain = false at confidence %.3f with threshold 0.99, want true", uncertain.Confidence)
	}
	if notUncertain.Confidence != uncertain.Confidence {
		t.Fatalf("same deterministic collection produced different confidences: %.3f vs %.3f", notUncertain.Confidence, uncertain.Confidence)
	}
}

func TestSummary_CarriesNoEvidenceContent(t *testing.T) {
	const rawSecretLog = "DB_PASSWORD=hunter2verysecret sk-ant-oat01-verysecretapikeyvalue"
	const rawSecretDetail = "container env dump: API_KEY=sk-secretvalue1234567890abcdef"
	bundle := Bundle{
		IncidentID: "inc_secret",
		CapturedAt: time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		Service:    Service{Name: "api", Kind: "docker_container", Status: "down"},
		Redaction:  redact.Report{Applied: true, Rules: []string{redact.RuleEnvValue, redact.RuleAPIKey}},
		Logs: []LogExcerpt{
			{ID: "log_docker_api", Source: "docker:api", LineCount: 1, Content: rawSecretLog},
		},
		Components: []Component{
			{ID: "cmp_docker_api", Kind: "docker_container", Name: "api", State: "restarting", Detail: rawSecretDetail},
		},
		Metrics: []Metric{
			{ID: "met_available_memory_percent", Name: "available_memory_percent", Value: 2.8, Unit: "%"},
		},
	}
	// Sanity check: the bundle really does carry the secret content, so this
	// test would actually catch a regression rather than passing vacuously.
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	if !bytes.Contains(bundleJSON, []byte("hunter2verysecret")) {
		t.Fatal("test setup bug: bundle does not actually carry the secret log content")
	}

	sigs := Match(bundle)
	if len(sigs) == 0 {
		t.Fatal("expected at least one deterministic signature from the memory metric")
	}
	deterministic := deterministicAssessment(bundle, sigs)

	aiRaw := mustJSON(t, map[string]any{
		"summary":    "api is down due to host memory pressure",
		"confidence": 0.9,
		"hypotheses": []map[string]any{
			{"cause": "low available memory", "confidence": 0.9,
				"evidenceIds": []string{"met_available_memory_percent", "log_docker_api", "cmp_docker_api"}},
		},
	})
	viaAI, err := ParseAssessment(aiRaw, bundle, sigs)
	if err != nil {
		t.Fatalf("ParseAssessment: %v", err)
	}

	secrets := []string{"hunter2verysecret", "sk-ant-oat01-verysecretapikeyvalue", "sk-secretvalue1234567890abcdef", rawSecretLog, rawSecretDetail}
	for _, a := range []Assessment{deterministic, viaAI} {
		summaryJSON, err := json.Marshal(a.Summary())
		if err != nil {
			t.Fatalf("marshal Summary: %v", err)
		}
		for _, secret := range secrets {
			if bytes.Contains(summaryJSON, []byte(secret)) {
				t.Fatalf("Summary JSON leaks evidence content %q:\n%s", secret, summaryJSON)
			}
		}
	}
}
