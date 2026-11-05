// Package runbook defines the immutable runbook shape that the remediation
// manager stores, hashes, approves and runs: an ordered list of catalog steps
// (see internal/steps) plus the risk level, rollback and verification
// metadata. It is types and the canonical content hash only; nothing here
// runs a command or creates a runbook by itself.
package runbook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/steps"
)

// SchemaVersion is the runbook content schema version hashed into
// ContentHash. Bumping it invalidates every previously computed hash rather
// than letting an incompatible field change silently compare apples to
// oranges.
const SchemaVersion = 2

// BlockedL3Reason is the fixed guidance recorded on every blocked L3
// runbook. It is deliberately a constant, not a per-runbook free-text
// field: the operator-facing message for "this cannot be auto-executed"
// must never vary by proposal content.
const BlockedL3Reason = "Destructive L3 remediation requires a maintenance session"

// Risk classifies the blast radius of executing a runbook end-to-end on the
// L0-L3 scale:
//
//	L0 - read-only observation or verification.
//	L1 - low-risk, reversible mutation with narrow interruption.
//	L2 - configuration or broader service change.
//	L3 - destructive, irreversible, or high-blast-radius; blocked.
type Risk string

const (
	RiskL0 Risk = "L0"
	RiskL1 Risk = "L1"
	RiskL2 Risk = "L2"
	RiskL3 Risk = "L3"
)

// Step is one concrete remediation action. Kind is a catalog step id and
// Params are that step's typed arguments. Command is the exact command
// display, derived from Kind and Params by steps.Command, never taken from
// the playbook author.
type Step struct {
	Kind        steps.ID `json:"kind"`
	Params      Params   `json:"params"`
	Description string   `json:"description"`
	Command     string   `json:"command,omitempty"`
	// Verify is the plain-text check the agent runs after the step, taken
	// from the catalog.
	Verify string `json:"verify,omitempty"`
	// Undoable is false when the catalog has no undo for the step. The app
	// lists those steps as "cannot be undone" before approval.
	Undoable bool `json:"undoable"`
}

// Source values for Runbook.Source.
const (
	SourceCatalog   = "catalog"
	SourceGenerated = "generated"
)

// ManualStep is something the user does by hand. The agent never runs it.
type ManualStep struct {
	Text    string `json:"text"`
	Command string `json:"command,omitempty"`
}

// Params are a step's arguments.
type Params = steps.Params

// Command is one exact, typed command display: used for a Runbook's ordered
// rollback steps.
type Command struct {
	Command     string `json:"command"`
	RunAs       string `json:"runAs"`
	Description string `json:"description"`
}

// VerificationCheck is one typed, bounded internal verification the agent
// runs after execution to confirm the remediation actually worked.
type VerificationCheck struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Target      string `json:"target"`
	Description string `json:"description"`
}

// Runbook is one stored, immutable entry, classified onto the L0-L3 scale and
// content-hashed.
type Runbook struct {
	ID              string `json:"id"`
	SchemaVersion   int    `json:"schemaVersion"`
	IncidentID      string `json:"incidentId,omitempty"`
	DiagnosisID     string `json:"diagnosisId,omitempty"`
	ProviderVersion string `json:"providerVersion,omitempty"`

	ServerID string `json:"server_id"`

	// Title is the short name the app shows for the playbook.
	Title string `json:"title"`
	// Source is SourceCatalog for a deterministic playbook or
	// SourceGenerated for one built by the playbook service.
	Source string `json:"source"`
	// ReviewCarefully is set when the playbook service flagged the evidence
	// as containing unusual instructions.
	ReviewCarefully bool `json:"reviewCarefully"`

	Summary         string `json:"summary"`
	RiskExplanation string `json:"riskExplanation,omitempty"`
	Risk            Risk   `json:"risk"`
	RunAs           string `json:"runAs,omitempty"`

	Steps              []Step              `json:"steps"`
	ManualSteps        []ManualStep        `json:"manualSteps"`
	AffectedFiles      []string            `json:"affectedFiles,omitempty"`
	AffectedServices   []string            `json:"affectedServices,omitempty"`
	Interruption       string              `json:"interruption,omitempty"`
	Rollback           []Command           `json:"rollback,omitempty"`
	Verification       []VerificationCheck `json:"verification,omitempty"`
	ExternalMonitorIDs []string            `json:"externalMonitorIds,omitempty"`

	Blocked       bool   `json:"blocked,omitempty"`
	BlockedReason string `json:"blockedReason,omitempty"`
	ContentHash   string `json:"contentHash,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// canonicalRunbook is the canonical, hashable shape of a Runbook: every
// execution-relevant field, and nothing else. Lifecycle/mutable fields (ID,
// timestamps, ContentHash itself, ...) are deliberately absent so
// recording an execution never changes an already-approved runbook's hash.
type canonicalRunbook struct {
	SchemaVersion      int                 `json:"schemaVersion"`
	IncidentID         string              `json:"incidentId"`
	ServerID           string              `json:"serverId"`
	DiagnosisID        string              `json:"diagnosisId"`
	Title              string              `json:"title"`
	Source             string              `json:"source"`
	ReviewCarefully    bool                `json:"reviewCarefully"`
	Risk               Risk                `json:"risk"`
	Steps              []canonicalStep     `json:"steps"`
	ManualSteps        []ManualStep        `json:"manualSteps"`
	RunAs              string              `json:"runAs"`
	AffectedFiles      []string            `json:"affectedFiles"`
	AffectedServices   []string            `json:"affectedServices"`
	Interruption       string              `json:"interruption"`
	Rollback           []Command           `json:"rollback"`
	Verification       []VerificationCheck `json:"verification"`
	ExternalMonitorIDs []string            `json:"externalMonitorIds"`
}

type canonicalStep struct {
	Kind     string         `json:"kind"`
	Params   map[string]any `json:"params"`
	Command  string         `json:"command"`
	Undoable bool           `json:"undoable"`
}

// ContentHash computes the canonical SHA-256 content hash of rb: the
// integrity fingerprint the phone binds its confirmation token to and the
// agent recomputes before ever mutating a host. Ordered fields (steps,
// rollback, verification, external monitor IDs) stay in their given order;
// the affected-file/service sets are hashed after sorting a copy. rb is
// never mutated by this call.
func ContentHash(rb Runbook) (string, error) {
	canonical := canonicalRunbook{
		SchemaVersion:      rb.SchemaVersion,
		IncidentID:         rb.IncidentID,
		ServerID:           rb.ServerID,
		DiagnosisID:        rb.DiagnosisID,
		Title:              rb.Title,
		Source:             rb.Source,
		ReviewCarefully:    rb.ReviewCarefully,
		Risk:               rb.Risk,
		Steps:              canonicalSteps(rb.Steps),
		ManualSteps:        append([]ManualStep(nil), rb.ManualSteps...),
		RunAs:              rb.RunAs,
		AffectedFiles:      sortedCopy(rb.AffectedFiles),
		AffectedServices:   sortedCopy(rb.AffectedServices),
		Interruption:       rb.Interruption,
		Rollback:           append([]Command(nil), rb.Rollback...),
		Verification:       append([]VerificationCheck(nil), rb.Verification...),
		ExternalMonitorIDs: append([]string(nil), rb.ExternalMonitorIDs...),
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("runbook: marshal canonical content: %w", err)
	}
	// Round-trip through a generic map so every nesting level's object keys
	// end up lexicographically sorted, independent of struct field order.
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return "", fmt.Errorf("runbook: canonicalize content: %w", err)
	}
	sorted, err := json.Marshal(generic)
	if err != nil {
		return "", fmt.Errorf("runbook: marshal sorted content: %w", err)
	}
	sum := sha256.Sum256(sorted)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalSteps(in []Step) []canonicalStep {
	out := make([]canonicalStep, len(in))
	for i, s := range in {
		out[i] = canonicalStep{Kind: string(s.Kind), Params: s.Params, Command: s.Command, Undoable: s.Undoable}
	}
	return out
}

// sortedCopy returns a lexicographically sorted copy of ss.
func sortedCopy(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}
