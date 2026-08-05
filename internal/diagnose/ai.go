// Package diagnose implements the agent-side bounded diagnostic pipeline
// (Watchtower Phase 5, issue #73): collect redacted evidence, run
// deterministic failure-signature checks, then optionally ask an AI provider
// for a schema-validated assessment. Raw evidence never leaves this process;
// only Assessment.Summary() may be posted to the relay.
package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
)

// Hypothesis is one candidate explanation an assessment offers, grounded in
// specific evidence IDs from the collected bundle.
type Hypothesis struct {
	Cause       string   `json:"cause"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidenceIds"`
}

// RecommendedAction is one remediation an assessment suggests. It is
// advisory only -- diagnose never executes anything itself.
type RecommendedAction struct {
	ActionID         string `json:"actionId"`
	Risk             string `json:"risk"` // low | medium | high
	Reason           string `json:"reason"`
	RequiresApproval bool   `json:"requiresApproval"`
}

// Assessment is the full diagnostic result: deterministic signatures plus,
// when an AI provider is available and its output validates, an AI-composed
// summary. Only Assessment.Summary() -- never Assessment itself -- may leave
// the server (AC5): this type still carries Service/Redaction/Signatures,
// which is deliberately excluded from the wire-safe Summary.
//
// The Go field for the wire "summary" key is named SummaryText rather than
// Summary: a method named Summary (see below) cannot share an identifier
// with a field on the same type. The json tag is what the wire contract
// binds, and that is unaffected.
type Assessment struct {
	IncidentID         string              `json:"incidentId"`
	CapturedAt         time.Time           `json:"capturedAt"`
	AIAvailable        bool                `json:"aiAvailable"`
	AIProvider         string              `json:"aiProvider,omitempty"`
	Redaction          redact.Report       `json:"redaction"`
	Service            Service             `json:"service"`
	SummaryText        string              `json:"summary"`
	Impact             string              `json:"impact,omitempty"`
	Confidence         float64             `json:"confidence"`
	Uncertain          bool                `json:"uncertain"`
	ProbableCause      string              `json:"probableCause,omitempty"`
	Hypotheses         []Hypothesis        `json:"hypotheses"`
	RecommendedActions []RecommendedAction `json:"recommendedActions"`
	MissingEvidence    []string            `json:"missingEvidence"`
	Signatures         []Signature         `json:"signatures"`
}

// ErrAIUnavailable is returned by a Proposer that has no usable AI provider.
var ErrAIUnavailable = errors.New("diagnose: no AI provider available")

// Proposer bridges to an AI CLI or API. Implementations must return
// ErrAIUnavailable rather than a generic error when no provider is usable.
type Proposer interface {
	Provider() string
	Propose(ctx context.Context, prompt string) (string, error)
}

// ParseAssessment's distinct rejection errors -- one per PRD 13 schema
// violation -- so callers (and tests) can tell failure modes apart with
// errors.Is. Errors returned by ParseAssessment wrap these with extra
// context via fmt.Errorf's %w.
var (
	// ErrAIOutputUnparseable means raw contained no extractable JSON object
	// (or its top-level shape was not an object at all).
	ErrAIOutputUnparseable = errors.New("diagnose: AI output is not a parseable JSON object")
	// ErrAIEmptySummary means the parsed object's "summary" was empty.
	ErrAIEmptySummary = errors.New("diagnose: AI summary is empty")
	// ErrAIConfidenceOutOfRange means "confidence" was outside [0,1].
	ErrAIConfidenceOutOfRange = errors.New("diagnose: AI confidence is outside [0,1]")
	// ErrAINoHypotheses means "hypotheses" was empty.
	ErrAINoHypotheses = errors.New("diagnose: AI produced zero hypotheses")
	// ErrAIHypothesisNoEvidence means a hypothesis had no evidenceIds.
	ErrAIHypothesisNoEvidence = errors.New("diagnose: AI hypothesis cites no evidence")
	// ErrAIUnknownEvidenceID means a hypothesis cited an id absent from the bundle.
	ErrAIUnknownEvidenceID = errors.New("diagnose: AI hypothesis cites an unknown evidence id")
	// ErrAIInvalidRisk means a recommendedActions[].risk was not low|medium|high.
	ErrAIInvalidRisk = errors.New("diagnose: AI recommended action has an invalid risk")
	// ErrAIClaimsResolution means summary/impact text claimed the issue is
	// already resolved -- the AI must diagnose, never assert a fix worked.
	ErrAIClaimsResolution = errors.New("diagnose: AI output claims resolution before verification")
)

// resolutionClaim matches language that asserts the incident is already
// fixed -- forbidden per AC3/AC4: the AI diagnoses, it never verifies.
var resolutionClaim = regexp.MustCompile(`(?i)\b(resolved|fixed|repaired|back online|issue is now)\b`)

// aiResponse is the exact JSON shape BuildPrompt instructs the model to
// return. It intentionally omits envelope fields (incidentId, capturedAt,
// service, redaction, signatures, aiAvailable, aiProvider) that
// ParseAssessment fills in from the bundle/signatures it already has --
// the model never invents those.
type aiResponse struct {
	Summary            string              `json:"summary"`
	Impact             string              `json:"impact"`
	Confidence         float64             `json:"confidence"`
	ProbableCause      string              `json:"probableCause"`
	Hypotheses         []Hypothesis        `json:"hypotheses"`
	RecommendedActions []RecommendedAction `json:"recommendedActions"`
	MissingEvidence    []string            `json:"missingEvidence"`
}

// BuildPrompt renders the REDACTED bundle plus its deterministic signatures
// into the strict PRD 13 instruction: the exact JSON schema to return, the
// explicit list of valid evidenceIds taken from the bundle, and the three
// prohibitions -- every hypothesis cites evidence, never invent command
// output, never claim resolution before verification.
func BuildPrompt(b Bundle, sigs []Signature) string {
	ids := b.EvidenceIDs()
	idsJSON, _ := json.Marshal(ids)
	sigsJSON, _ := json.Marshal(sigs)
	bundleJSON, _ := json.Marshal(b)

	var out strings.Builder
	out.WriteString("You are an on-call SRE diagnosing a failing service from bounded, redacted ")
	out.WriteString("evidence collected by a monitoring agent. Respond with a JSON object only -- ")
	out.WriteString("no prose, no code fences -- with exactly these keys:\n")
	out.WriteString("  summary:            string, one sentence describing what is wrong right now (required)\n")
	out.WriteString("  impact:             string, optional, one sentence describing user-facing impact\n")
	out.WriteString("  confidence:         number in [0,1], your overall confidence in this diagnosis\n")
	out.WriteString("  probableCause:      string, optional, short label for the most likely root cause\n")
	out.WriteString("  hypotheses:         array, at least one entry, each {cause:string, confidence:number, evidenceIds:[string,...]} with evidenceIds non-empty\n")
	out.WriteString("  recommendedActions: array of {actionId:string, risk:\"low\"|\"medium\"|\"high\", reason:string, requiresApproval:bool}\n")
	out.WriteString("  missingEvidence:    array of strings describing what would sharpen the diagnosis but was not collected\n\n")
	out.WriteString("STRICT RULES (violating any of these gets your response rejected):\n")
	out.WriteString("  1. Every hypothesis MUST cite at least one evidenceId, and every evidenceId cited anywhere MUST be one of the VALID EVIDENCE IDS listed below -- never cite an id that is not in that list.\n")
	out.WriteString("  2. Never invent command output, log lines, or metric values that are not present in the EVIDENCE BUNDLE below -- reason only from what was actually collected.\n")
	out.WriteString("  3. Never claim the issue is resolved, fixed, repaired, back online, or otherwise already healthy -- you are diagnosing, not verifying a fix. State only what the evidence supports right now.\n\n")
	fmt.Fprintf(&out, "VALID EVIDENCE IDS: %s\n\n", idsJSON)
	out.WriteString("DETERMINISTIC SIGNATURES (already matched by rule-based checks):\n")
	out.Write(sigsJSON)
	out.WriteString("\n\nEVIDENCE BUNDLE (redacted):\n")
	out.Write(bundleJSON)
	out.WriteString("\n")
	return out.String()
}

// ParseAssessment parses raw CLI/API output (tolerating markdown fences, a
// claude-style {"result": "..."} envelope, JSONL event streams, and JSON
// embedded in prose -- mirroring internal/runbook's CLIProposer parsing) and
// validates it against the PRD 13 schema and the bundle's evidence IDs.
func ParseAssessment(raw string, b Bundle, sigs []Signature) (Assessment, error) {
	resp, err := parseAIResponse(raw)
	if err != nil {
		return Assessment{}, err
	}

	if strings.TrimSpace(resp.Summary) == "" {
		return Assessment{}, ErrAIEmptySummary
	}
	if resp.Confidence < 0 || resp.Confidence > 1 {
		return Assessment{}, fmt.Errorf("%w: %v", ErrAIConfidenceOutOfRange, resp.Confidence)
	}
	if len(resp.Hypotheses) == 0 {
		return Assessment{}, ErrAINoHypotheses
	}
	valid := make(map[string]bool, len(b.Signals)+len(b.Logs)+len(b.Components)+len(b.RecentChanges)+len(b.Metrics))
	for _, id := range b.EvidenceIDs() {
		valid[id] = true
	}
	for _, h := range resp.Hypotheses {
		if len(h.EvidenceIDs) == 0 {
			return Assessment{}, ErrAIHypothesisNoEvidence
		}
		for _, id := range h.EvidenceIDs {
			if !valid[id] {
				return Assessment{}, fmt.Errorf("%w: %q", ErrAIUnknownEvidenceID, id)
			}
		}
	}
	for _, ra := range resp.RecommendedActions {
		switch ra.Risk {
		case "low", "medium", "high":
		default:
			return Assessment{}, fmt.Errorf("%w: %q", ErrAIInvalidRisk, ra.Risk)
		}
	}
	if resolutionClaim.MatchString(resp.Summary) || resolutionClaim.MatchString(resp.Impact) {
		return Assessment{}, ErrAIClaimsResolution
	}

	return Assessment{
		IncidentID:         b.IncidentID,
		CapturedAt:         b.CapturedAt,
		AIAvailable:        true,
		Redaction:          b.Redaction,
		Service:            b.Service,
		SummaryText:        resp.Summary,
		Impact:             resp.Impact,
		Confidence:         resp.Confidence,
		ProbableCause:      resp.ProbableCause,
		Hypotheses:         resp.Hypotheses,
		RecommendedActions: resp.RecommendedActions,
		MissingEvidence:    resp.MissingEvidence,
		Signatures:         sigs,
	}, nil
}

// parseAIResponse extracts an aiResponse from raw output, trying shapes in
// order of preference:
//
//  1. Direct JSON object matching aiResponse.
//  2. A claude-style envelope {"result": "<assistant text>"} whose text
//     contains the JSON object (optionally fenced).
//  3. A JSONL/event stream whose fragments concatenate into text containing
//     the JSON object.
//  4. Raw text with the JSON object embedded anywhere (fenced or in prose).
func parseAIResponse(raw string) (aiResponse, error) {
	data := bytes.TrimSpace([]byte(raw))
	if len(data) == 0 {
		return aiResponse{}, ErrAIOutputUnparseable
	}
	// Shape 1: exact JSON object, nothing else.
	if resp, ok := tryParseAI(data); ok {
		return resp, nil
	}
	// Shape 2: claude-style envelope.
	var env struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err == nil && env.Result != "" {
		if body := extractJSONObject([]byte(env.Result)); body != nil {
			if resp, ok := tryParseAI(body); ok {
				return resp, nil
			}
		}
	}
	// Shape 3: JSONL/event streams.
	if resp, ok := parseAIResponseStream(data); ok {
		return resp, nil
	}
	// Shape 4: raw text with embedded JSON.
	if body := extractJSONObject(data); body != nil {
		if resp, ok := tryParseAI(body); ok {
			return resp, nil
		}
	}
	return aiResponse{}, ErrAIOutputUnparseable
}

func parseAIResponseStream(stdout []byte) (aiResponse, bool) {
	var fragments []string
	for _, line := range bytes.Split(stdout, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if resp, ok := tryParseAI(line); ok {
			return resp, true
		}
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			continue
		}
		lineFragments := textFragments(v)
		for _, fragment := range lineFragments {
			if resp, ok := parseAIResponseText(fragment); ok {
				return resp, true
			}
		}
		fragments = append(fragments, lineFragments...)
	}
	if len(fragments) == 0 {
		return aiResponse{}, false
	}
	if resp, ok := parseAIResponseText(strings.Join(fragments, "")); ok {
		return resp, true
	}
	if resp, ok := parseAIResponseText(strings.Join(fragments, "\n")); ok {
		return resp, true
	}
	return aiResponse{}, false
}

func parseAIResponseText(s string) (aiResponse, bool) {
	if body := extractJSONObject([]byte(s)); body != nil {
		return tryParseAI(body)
	}
	return aiResponse{}, false
}

func textFragments(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, item := range x {
			out = append(out, textFragments(item)...)
		}
		return out
	case map[string]any:
		return textFragmentsFromMap(x)
	default:
		return nil
	}
}

func textFragmentsFromMap(m map[string]any) []string {
	keys := []string{"result", "message", "content", "text", "delta", "output_text", "final", "response", "msg", "data"}
	seen := make(map[string]bool, len(keys))
	var out []string
	for _, key := range keys {
		seen[key] = true
		if v, ok := m[key]; ok {
			out = append(out, textFragments(v)...)
		}
	}
	var rest []string
	for key := range m {
		if !seen[key] {
			rest = append(rest, key)
		}
	}
	sort.Strings(rest)
	for _, key := range rest {
		switch m[key].(type) {
		case string:
			continue
		default:
			out = append(out, textFragments(m[key])...)
		}
	}
	return out
}

// tryParseAI unmarshals b as an aiResponse and rejects an object that does
// not look like one at all (every distinguishing field zero-valued) --
// otherwise an unrelated JSON object such as {"foo":1} would be mistaken
// for a (schema-invalid, empty-summary) assessment instead of falling
// through to the next parse shape.
func tryParseAI(b []byte) (aiResponse, bool) {
	var r aiResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return aiResponse{}, false
	}
	if r.Summary == "" && r.ProbableCause == "" && r.Confidence == 0 && len(r.Hypotheses) == 0 {
		return aiResponse{}, false
	}
	return r, true
}

// extractJSONObject scans s for the first top-level {...} block and returns
// its bytes, or nil. Handles a leading ```json fence and trailing prose.
func extractJSONObject(s []byte) []byte {
	if i := bytes.Index(s, []byte("```")); i >= 0 {
		s = s[i+3:]
		if j := bytes.IndexByte(s, '\n'); j >= 0 {
			s = s[j+1:]
		}
		if end := bytes.Index(s, []byte("```")); end >= 0 {
			s = s[:end]
		}
	}
	start := bytes.IndexByte(s, '{')
	if start < 0 {
		return nil
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if esc {
			esc = false
			continue
		}
		if inStr {
			switch c {
			case '\\':
				esc = true
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return nil
}
