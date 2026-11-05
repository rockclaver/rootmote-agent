package diagnose

import (
	"context"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
)

// DefaultConfidenceThreshold is used when PipelineConfig.ConfidenceThreshold
// is zero or negative.
const DefaultConfidenceThreshold = 0.6

// Hypothesis is one candidate explanation an assessment offers, grounded in
// specific evidence IDs from the collected bundle.
type Hypothesis struct {
	Cause       string   `json:"cause"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidenceIds"`
}

// Assessment is the deterministic diagnostic result: the signatures that
// matched the collected evidence, with the best one as the headline. It
// carries no logs or raw evidence; the Bundle holds those and never leaves
// the agent except through the redacted playbook request.
type Assessment struct {
	IncidentID    string        `json:"incidentId"`
	CapturedAt    time.Time     `json:"capturedAt"`
	Redaction     redact.Report `json:"redaction"`
	Service       Service       `json:"service"`
	SummaryText   string        `json:"summary"`
	Confidence    float64       `json:"confidence"`
	Uncertain     bool          `json:"uncertain"`
	ProbableCause string        `json:"probableCause,omitempty"`
	Hypotheses    []Hypothesis  `json:"hypotheses"`
	Signatures    []Signature   `json:"signatures"`
}

// PipelineConfig configures a Pipeline.
type PipelineConfig struct {
	// Collector performs the bounded, redacted evidence collection pass.
	// Required.
	Collector *Collector
	// ConfidenceThreshold is the cutoff below which an assessment is marked
	// Uncertain. Zero or negative takes DefaultConfidenceThreshold.
	ConfidenceThreshold float64
}

// Pipeline runs the bounded collect, then match-signatures workflow.
type Pipeline struct {
	cfg PipelineConfig
}

// NewPipeline builds a Pipeline from cfg, applying the default confidence
// threshold when none is set.
func NewPipeline(cfg PipelineConfig) *Pipeline {
	if cfg.ConfidenceThreshold <= 0 {
		cfg.ConfidenceThreshold = DefaultConfidenceThreshold
	}
	return &Pipeline{cfg: cfg}
}

// Collect runs just the bounded, redacted collection phase, for callers that
// need the evidence bundle without a full diagnosis.
func (p *Pipeline) Collect(ctx context.Context, t Target) Bundle {
	return p.cfg.Collector.Collect(ctx, t)
}

// Run collects evidence and matches the deterministic signatures against it.
func (p *Pipeline) Run(ctx context.Context, t Target) (Assessment, Bundle) {
	bundle := p.cfg.Collector.Collect(ctx, t)
	assessment := Assess(bundle, Match(bundle))
	assessment.Uncertain = assessment.Confidence < p.cfg.ConfidenceThreshold
	return assessment, bundle
}

// Assess builds the rule-based Assessment from a bundle and its matched
// signatures. The highest-confidence signature (Match sorts descending by
// confidence, then id) supplies the headline summary, probable cause and
// confidence; every signature becomes one hypothesis carrying its own
// evidence IDs.
func Assess(b Bundle, sigs []Signature) Assessment {
	a := Assessment{
		IncidentID: b.IncidentID,
		CapturedAt: b.CapturedAt,
		Redaction:  b.Redaction,
		Service:    b.Service,
		Signatures: sigs,
		Hypotheses: []Hypothesis{},
	}
	if len(sigs) == 0 {
		a.SummaryText = "No known failure signature matched; manual investigation required."
		return a
	}
	top := sigs[0]
	a.SummaryText = top.Title
	a.ProbableCause = top.Title
	a.Confidence = top.Confidence
	a.Hypotheses = make([]Hypothesis, len(sigs))
	for i, sig := range sigs {
		a.Hypotheses[i] = Hypothesis{Cause: sig.Title, Confidence: sig.Confidence, EvidenceIDs: sig.EvidenceIDs}
	}
	return a
}
