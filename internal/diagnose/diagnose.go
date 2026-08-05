package diagnose

import (
	"context"
	"time"
)

// DefaultConfidenceThreshold is used when PipelineConfig.ConfidenceThreshold
// is zero or negative.
const DefaultConfidenceThreshold = 0.6

// PipelineConfig configures a Pipeline.
type PipelineConfig struct {
	// Collector performs the bounded, redacted evidence collection pass.
	// Required.
	Collector *Collector
	// Proposer bridges to an AI provider. Nil (or unavailable at call time)
	// means deterministic-only diagnosis (AC6).
	Proposer Proposer
	// ConfidenceThreshold is the cutoff below which an assessment is marked
	// Uncertain (AC4). Zero/negative takes DefaultConfidenceThreshold.
	ConfidenceThreshold float64
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
	// Logf receives non-fatal diagnostics (AI unavailable, AI output
	// rejected). Nil silences logging.
	Logf func(string, ...any)
}

// Pipeline runs the bounded collect -> deterministic-signature -> AI
// diagnostic workflow (AC1).
type Pipeline struct {
	cfg PipelineConfig
}

// NewPipeline builds a Pipeline from cfg, applying defaults for a
// zero-valued ConfidenceThreshold/Now.
func NewPipeline(cfg PipelineConfig) *Pipeline {
	if cfg.ConfidenceThreshold <= 0 {
		cfg.ConfidenceThreshold = DefaultConfidenceThreshold
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Pipeline{cfg: cfg}
}

func (p *Pipeline) logf(format string, args ...any) {
	if p.cfg.Logf != nil {
		p.cfg.Logf(format, args...)
	}
}

// Collect runs just the bounded, redacted collection phase -- no
// deterministic signatures, no AI -- for callers that need the evidence
// bundle without running (or re-running) a full diagnosis, e.g. serving
// incident.evidence when no diagnosis has been run yet for that incident.
func (p *Pipeline) Collect(ctx context.Context, t Target) Bundle {
	return p.cfg.Collector.Collect(ctx, t)
}

// Run executes the full workflow: collect (bounded, redacted) -> pure
// deterministic signatures -> AI, only when a Proposer is configured. It
// NEVER returns an error for an AI failure: ErrAIUnavailable, any other
// transport/exec error from Propose, or a ParseAssessment schema rejection
// are all logged and the pipeline falls back to the deterministic
// assessment with AIAvailable=false (AC6). Uncertain is always recomputed
// from the final Confidence against ConfidenceThreshold (AC4).
func (p *Pipeline) Run(ctx context.Context, t Target) (Assessment, Bundle) {
	bundle := p.cfg.Collector.Collect(ctx, t)
	sigs := Match(bundle)
	assessment := deterministicAssessment(bundle, sigs)

	if p.cfg.Proposer != nil {
		prompt := BuildPrompt(bundle, sigs)
		raw, err := p.cfg.Proposer.Propose(ctx, prompt)
		if err != nil {
			p.logf("diagnose: AI proposer unavailable for incident %s: %v", t.IncidentID, err)
		} else if parsed, perr := ParseAssessment(raw, bundle, sigs); perr != nil {
			p.logf("diagnose: rejecting AI output for incident %s: %v", t.IncidentID, perr)
		} else {
			parsed.AIProvider = p.cfg.Proposer.Provider()
			assessment = parsed
		}
	}

	assessment.Uncertain = assessment.Confidence < p.cfg.ConfidenceThreshold
	return assessment, bundle
}

// deterministicAssessment builds the rule-based-only Assessment from the
// collected bundle and its matched signatures, before any AI involvement.
// The highest-confidence signature (Match sorts descending by confidence
// then id) supplies the headline summary/probable cause/confidence; every
// signature becomes one hypothesis carrying its own evidence IDs.
func deterministicAssessment(b Bundle, sigs []Signature) Assessment {
	a := Assessment{
		IncidentID: b.IncidentID,
		CapturedAt: b.CapturedAt,
		Redaction:  b.Redaction,
		Service:    b.Service,
		Signatures: sigs,
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

// Summary strips an Assessment down to what may leave the server: no logs,
// no component detail, no bundle, no raw evidence IDs beyond what the
// hypotheses/signatures already cite by id. This is the ONLY shape posted
// to the relay (AC5).
func (a Assessment) Summary() Summary {
	return Summary{
		Summary:            a.SummaryText,
		Impact:             a.Impact,
		ProbableCause:      a.ProbableCause,
		Confidence:         a.Confidence,
		Uncertain:          a.Uncertain,
		AIAvailable:        a.AIAvailable,
		AIProvider:         a.AIProvider,
		RedactionApplied:   a.Redaction.Applied,
		Hypotheses:         a.Hypotheses,
		RecommendedActions: a.RecommendedActions,
		MissingEvidence:    a.MissingEvidence,
		CapturedAt:         a.CapturedAt,
	}
}

// Summary is the redacted diagnostic summary posted to the relay -- the
// only Assessment-derived shape that ever leaves this server (AC5).
type Summary struct {
	Summary            string              `json:"summary"`
	Impact             string              `json:"impact,omitempty"`
	ProbableCause      string              `json:"probableCause,omitempty"`
	Confidence         float64             `json:"confidence"`
	Uncertain          bool                `json:"uncertain"`
	AIAvailable        bool                `json:"aiAvailable"`
	AIProvider         string              `json:"aiProvider,omitempty"`
	RedactionApplied   bool                `json:"redactionApplied"`
	Hypotheses         []Hypothesis        `json:"hypotheses"`
	RecommendedActions []RecommendedAction `json:"recommendedActions"`
	MissingEvidence    []string            `json:"missingEvidence"`
	CapturedAt         time.Time           `json:"capturedAt"`
}
