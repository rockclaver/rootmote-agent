// Package runbook turns a fired infrastructure alert (or an operator's
// manual remediation request) into an immutable, human-approvable runbook:
// when an alert fires, the manager grounds an AI proposer on the current
// infra read, asks for a structured Proposal, classifies its risk on the
// L0-L3 scale, computes a canonical content hash over every
// approval-relevant field, and — unless the runbook is blocked as L3 —
// fans each step out as an aiproposal entry. Approval still flows through
// the existing biometric + confirmation-token path on aiproposal — runbook
// never bypasses it.
//
// The package owns only orchestration: alert -> proposer -> classify ->
// hash -> aiproposal. The proposer is an interface (see Proposer) so the
// host process can wire a real CLI-backed proposer (see CLIProposer) in
// production and a stub in tests without dragging the LLM specifics into
// this package.
package runbook

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/notifications"
)

// DefaultThrottle is the minimum gap between two auto-proposals for the same
// (server, rule, target). Hardcoded in the AC ("at most one auto-proposal per
// alert per server per 10 minutes"). Exposed so tests can override.
const DefaultThrottle = 10 * time.Minute

// SchemaVersion is the runbook content schema version hashed into
// ContentHash. Bumping it invalidates every previously computed hash rather
// than letting an incompatible field change silently compare apples to
// oranges.
const SchemaVersion = 1

// BlockedL3Reason is the fixed guidance recorded on every blocked L3
// runbook. It is deliberately a constant, not a per-runbook free-text
// field: the operator-facing message for "this cannot be auto-executed"
// must never vary by proposal content.
const BlockedL3Reason = "Destructive L3 remediation requires a maintenance session"

// Risk classifies the blast radius of executing a runbook end-to-end on the
// agent's authoritative L0-L3 scale (see the Watchtower remediation design):
//
//	L0 - read-only observation or verification; may run automatically.
//	L1 - low-risk, reversible mutation with narrow interruption.
//	L2 - configuration or broader service change.
//	L3 - destructive, irreversible, or high-blast-radius; blocked by
//	     default and recommends a full maintenance session instead.
//
// There are no low/medium/high aliases: every caller uses RiskL0-RiskL3.
type Risk string

const (
	RiskL0 Risk = "L0"
	RiskL1 Risk = "L1"
	RiskL2 Risk = "L2"
	RiskL3 Risk = "L3"
)

// valid reports whether r is one of the four defined risk levels.
func (r Risk) valid() bool {
	switch r {
	case RiskL0, RiskL1, RiskL2, RiskL3:
		return true
	}
	return false
}

// Step is one concrete remediation action. Kind/Params map 1:1 to an
// aiproposal kind so the existing guard + token + execute path handles it
// verbatim; nothing in this file ever touches a host directly. Command is
// the exact command display for the step — it is always derived
// server-side from Kind+Params by tokenBindingForKind, never taken
// verbatim from the AI, so what the operator sees is provably what will
// execute.
type Step struct {
	Kind        aiproposal.Kind `json:"kind"`
	Params      map[string]any  `json:"params"`
	Description string          `json:"description"`
	Command     string          `json:"command,omitempty"`
}

// Command is one exact, typed command display: used both for a Step's
// rendered command and for a Runbook's ordered rollback steps.
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

// Proposal is the AI's structured response: the full immutable runbook
// shape minus the orchestration fields (ID, hash, timestamps) the manager
// fills in. An empty Steps slice with a non-empty Summary is the "no
// automated fix recommended" path: the manager records it but produces no
// approval card and emits no push.
type Proposal struct {
	Summary            string              `json:"summary"`
	RiskExplanation    string              `json:"riskExplanation,omitempty"`
	Risk               Risk                `json:"risk"`
	Steps              []Step              `json:"steps"`
	RunAs              string              `json:"runAs,omitempty"`
	AffectedFiles      []string            `json:"affectedFiles,omitempty"`
	AffectedServices   []string            `json:"affectedServices,omitempty"`
	Interruption       string              `json:"interruption,omitempty"`
	Rollback           []Command           `json:"rollback,omitempty"`
	Verification       []VerificationCheck `json:"verification,omitempty"`
	ExternalMonitorIDs []string            `json:"externalMonitorIds,omitempty"`
}

// Alert is the trigger payload the manager hands to the proposer. It mirrors
// the relevant fields from a notifications.Notification of type "infra.alert"
// so the proposer does not need to know about the wider notification schema.
type Alert struct {
	ServerID string
	Rule     string
	Target   string
	Body     string
	Severity string
	FiredAt  time.Time
}

// Grounding bundles the four host-read snapshots the AC says the AI must be
// grounded on. Each is opaque to runbook — the proposer is responsible for
// serialising them into its prompt. nil fields signal an unavailable
// subsystem; the proposer should degrade gracefully rather than refusing.
type Grounding struct {
	Metrics   any
	Services  any
	Processes any
	Firewall  any
}

// Snapshotter produces a Grounding for the current host. The wiring in
// rootmote-agent main injects a closure that calls infra/systemd/process/
// firewall managers; tests can supply a static struct.
type Snapshotter interface {
	Snapshot(ctx context.Context) Grounding
}

// SnapshotFunc adapts a plain function to Snapshotter.
type SnapshotFunc func(ctx context.Context) Grounding

func (f SnapshotFunc) Snapshot(ctx context.Context) Grounding { return f(ctx) }

// Proposer is the AI bridge. Implementations are responsible for: forming a
// prompt that includes the alert + grounding, invoking the model, parsing
// out a valid Proposal, and degrading to an empty-Steps Proposal rather than
// returning an error for "no fix recommended". A returned error means the
// proposer itself failed (timeout, parse failure, auth) — the manager logs
// it and skips this alert; the throttle still ticks so a flapping alert
// can't tight-loop the proposer.
type Proposer interface {
	Propose(ctx context.Context, alert Alert, grounding Grounding) (Proposal, error)
}

// Runbook is one stored, immutable entry: the AI's structured proposal —
// classified onto the L0-L3 scale and content-hashed — plus the IDs of the
// aiproposals fanned out from its steps. The client uses RunbookID to open
// the approval-card screen; ProposalIDs lets it render the steps with their
// per-step lifecycle (pending / executing / executed / declined). A blocked
// L3 runbook is still recorded and audited but carries no proposal IDs at
// all — see BlockedL3Reason.
type Runbook struct {
	ID              string `json:"id"`
	SchemaVersion   int    `json:"schemaVersion"`
	IncidentID      string `json:"incidentId,omitempty"`
	DiagnosisID     string `json:"diagnosisId,omitempty"`
	ProviderVersion string `json:"providerVersion,omitempty"`

	AlertKey  string `json:"alert_key"`
	ServerID  string `json:"server_id"`
	Rule      string `json:"rule"`
	Target    string `json:"target"`
	SessionID string `json:"session_id,omitempty"`

	Summary         string `json:"summary"`
	RiskExplanation string `json:"riskExplanation,omitempty"`
	Risk            Risk   `json:"risk"`
	RunAs           string `json:"runAs,omitempty"`

	Steps              []Step              `json:"steps"`
	AffectedFiles      []string            `json:"affectedFiles,omitempty"`
	AffectedServices   []string            `json:"affectedServices,omitempty"`
	Interruption       string              `json:"interruption,omitempty"`
	Rollback           []Command           `json:"rollback,omitempty"`
	Verification       []VerificationCheck `json:"verification,omitempty"`
	ExternalMonitorIDs []string            `json:"externalMonitorIds,omitempty"`

	Blocked       bool   `json:"blocked,omitempty"`
	BlockedReason string `json:"blockedReason,omitempty"`
	ContentHash   string `json:"contentHash,omitempty"`

	ProposalIDs []string   `json:"proposal_ids"`
	CreatedAt   time.Time  `json:"created_at"`
	Skipped     bool       `json:"skipped,omitempty"` // true when AI returned "no fix"
	SkippedMsg  string     `json:"skipped_msg,omitempty"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// Config wires Manager. AIProposals + Proposer are required; Snapshotter,
// Notifications, Session, and Now have sensible zero-value behaviour.
type Config struct {
	AIProposals *aiproposal.Manager
	Proposer    Proposer
	// ProposerForAgent returns a proposer for a user-selected CLI agent
	// ("claude" or "codex"). It is used by manual remediation requests where
	// the operator chooses which signed-in tool should draft the runbook.
	ProposerForAgent func(agent string) Proposer
	Snapshotter      Snapshotter
	Notifications    *notifications.Hub
	// Session is an optional hook that opens (or reuses) an AI-attributed
	// session for the runbook and returns the session ID. Implementations
	// may persist the prompt + response as session events so the operator
	// sees the AI reasoning trace. A nil Session means the runbook will not
	// be attributed to a session, but everything else still works — the AC
	// language is "opens (or reuses) a session", not "fails if none".
	Session func(ctx context.Context, alert Alert) (sessionID string, prompt func(promptText, response string)) // optional
	Now     func() time.Time
	// Throttle overrides DefaultThrottle. Tests use a tiny value to keep
	// runs fast.
	Throttle time.Duration
}

// Manager turns alerts into runbooks. It is process-local; nothing persists
// across an agent restart, which matches the short-lived nature of the
// aiproposal queue it fans into.
type Manager struct {
	cfg Config

	mu          sync.Mutex
	runbooks    map[string]*Runbook
	order       []string
	lastFiredAt map[string]time.Time // key = throttleKey(alert)
}

// New constructs an empty Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.AIProposals == nil {
		return nil, errors.New("runbook: AIProposals required")
	}
	if cfg.Proposer == nil {
		return nil, errors.New("runbook: Proposer required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Throttle <= 0 {
		cfg.Throttle = DefaultThrottle
	}
	return &Manager{
		cfg:         cfg,
		runbooks:    map[string]*Runbook{},
		lastFiredAt: map[string]time.Time{},
	}, nil
}

// Start subscribes to the notification hub. The returned cleanup unsubscribes.
// Safe to call with a nil hub (returns a no-op cleanup) so unit tests that
// drive Handle directly do not need a hub.
func (m *Manager) Start(ctx context.Context) func() {
	if m.cfg.Notifications == nil {
		return func() {}
	}
	return m.cfg.Notifications.Subscribe(func(n notifications.Notification) {
		alert, ok := alertFromNotification(n)
		if !ok {
			return
		}
		// Run async so a slow proposer never blocks the notification fanout
		// (the hub fans synchronously). The throttle prevents storming.
		go m.Handle(ctx, alert)
	})
}

// Handle is the unit-testable entry point: given one alert, propose +
// fan-out subject to the throttle. Returns the Runbook (or zero value when
// throttled / proposer failed). Errors are intentionally swallowed and
// returned as nil — runbook is best-effort, not request-response.
func (m *Manager) Handle(ctx context.Context, a Alert) Runbook {
	if !m.tryClaim(a) {
		return Runbook{}
	}
	return m.proposeAndMaterialise(ctx, a, m.cfg.Proposer)
}

// HandleManual is the user-initiated variant. It bypasses alert throttling
// because the operator explicitly asked for a fresh runbook, and optionally
// routes through a selected CLI agent.
func (m *Manager) HandleManual(ctx context.Context, a Alert, agent string) (Runbook, error) {
	proposer := m.cfg.Proposer
	if agent != "" {
		if m.cfg.ProposerForAgent == nil {
			return Runbook{}, fmt.Errorf("runbook: selected agent %q is not supported", agent)
		}
		proposer = m.cfg.ProposerForAgent(agent)
		if proposer == nil {
			return Runbook{}, fmt.Errorf("runbook: selected agent %q is not supported", agent)
		}
	}
	return m.proposeAndMaterialiseErr(ctx, a, proposer)
}

func (m *Manager) proposeAndMaterialise(ctx context.Context, a Alert, proposer Proposer) Runbook {
	rb, err := m.proposeAndMaterialiseErr(ctx, a, proposer)
	if err != nil {
		// Don't release the throttle on failure: that's exactly the
		// flapping-alert case the throttle exists to bound.
		return Runbook{}
	}
	return rb
}

func (m *Manager) proposeAndMaterialiseErr(ctx context.Context, a Alert, proposer Proposer) (Runbook, error) {
	g := Grounding{}
	if m.cfg.Snapshotter != nil {
		g = m.cfg.Snapshotter.Snapshot(ctx)
	}
	p, err := proposer.Propose(ctx, a, g)
	if err != nil {
		return Runbook{}, err
	}
	rb := m.materialise(ctx, a, p)
	if rb.ID == "" {
		return Runbook{}, errors.New("runbook: AI proposer did not produce a runbook")
	}
	return rb, nil
}

// tryClaim atomically records "we just fired for this alert key" and returns
// false if a previous fire is still inside the throttle window.
func (m *Manager) tryClaim(a Alert) bool {
	key := throttleKey(a)
	now := m.cfg.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if last, ok := m.lastFiredAt[key]; ok && now.Sub(last) < m.cfg.Throttle {
		return false
	}
	m.lastFiredAt[key] = now
	return true
}

func throttleKey(a Alert) string {
	return a.ServerID + "|" + a.Rule + "|" + a.Target
}

// classifyProposal determines the authoritative Risk for p and whether it
// must be blocked from execution. Classification only ever raises risk:
// the model's self-reported Risk is honoured as a floor, never trusted to
// lower a step the manager independently judges more dangerous. An invalid
// or missing self-reported Risk defaults to RiskL2 (the manager does not
// trust an absent classification to mean "safe"). Raw AI-authored shell
// (security.fix/run_script) and a firewall change that risks locking out
// management access always classify as L3 and are blocked — an L3 verdict,
// regardless of source, is always blocked: the destructive/irreversible/
// high-blast-radius definition of L3 admits no auto-executable exception.
func classifyProposal(p Proposal) (Risk, bool) {
	risk := p.Risk
	if !risk.valid() {
		risk = RiskL2
	}
	if forcesL3(p.Steps) {
		return RiskL3, true
	}
	if risk == RiskL3 {
		return RiskL3, true
	}
	return risk, false
}

// forcesL3 reports whether any step in steps must classify the whole
// runbook as L3 regardless of the model's self-reported risk.
func forcesL3(steps []Step) bool {
	for _, step := range steps {
		if isRunScriptStep(step) || isFirewallLockoutStep(step) {
			return true
		}
	}
	return false
}

// isRunScriptStep reports whether step is an AI-authored raw-shell
// remediation (aiproposal.KindSecurityFix, params.kind=="run_script"). Raw
// shell has no typed guard rails, so it always forces L3.
func isRunScriptStep(step Step) bool {
	if step.Kind != aiproposal.KindSecurityFix {
		return false
	}
	kind, _ := step.Params["kind"].(string)
	return kind == "run_script"
}

// isFirewallLockoutStep reports whether step removes the firewall rule
// for port 22 (SSH) — the canonical "firewall lockout risk" the design
// calls out as L3 even though infra.firewall.rule_remove is otherwise a
// narrow, reversible mutation.
func isFirewallLockoutStep(step Step) bool {
	if step.Kind != aiproposal.KindFirewallRemove {
		return false
	}
	return intFrom(step.Params["port"]) == 22
}

// materialise records the runbook, fans steps out as aiproposals (unless
// blocked as L3), and emits one "infra.runbook" notification with the
// deep-link payload.
func (m *Manager) materialise(ctx context.Context, a Alert, p Proposal) Runbook {
	now := m.cfg.Now()
	id := randomID()

	// Render each step's exact command display server-side from its typed
	// Kind+Params — never taken verbatim from the AI — so what the
	// operator sees in the approval sheet is provably what will execute.
	// tokenBindingForKind is the single source of truth for both the
	// confirmation-token binding and this display; a step that fails
	// validation here is left with an empty Command and is skipped from
	// the aiproposal fan-out below.
	steps := make([]Step, len(p.Steps))
	for i, step := range p.Steps {
		params := step.Params
		if params == nil {
			params = map[string]any{}
		}
		steps[i] = Step{Kind: step.Kind, Params: params, Description: step.Description}
		if _, _, command, _, err := tokenBindingForKind(step.Kind, params); err == nil {
			steps[i].Command = command
		}
	}

	risk, blocked := classifyProposal(p)

	rb := Runbook{
		ID:                 id,
		SchemaVersion:      SchemaVersion,
		AlertKey:           a.Rule + ":" + a.Target,
		ServerID:           a.ServerID,
		Rule:               a.Rule,
		Target:             a.Target,
		Summary:            p.Summary,
		RiskExplanation:    p.RiskExplanation,
		Risk:               risk,
		RunAs:              p.RunAs,
		Steps:              steps,
		AffectedFiles:      append([]string(nil), p.AffectedFiles...),
		AffectedServices:   append([]string(nil), p.AffectedServices...),
		Interruption:       p.Interruption,
		Rollback:           append([]Command(nil), p.Rollback...),
		Verification:       append([]VerificationCheck(nil), p.Verification...),
		ExternalMonitorIDs: append([]string(nil), p.ExternalMonitorIDs...),
		CreatedAt:          now,
	}
	if blocked {
		rb.Blocked = true
		rb.BlockedReason = BlockedL3Reason
	}

	// Run the optional Session hook so the AC's "agent automatically opens
	// (or reuses) a session ... grounded in ..." is honoured even when the
	// proposer is a one-shot CLI invocation rather than an interactive
	// session. The hook may return an empty session ID; that's fine.
	if m.cfg.Session != nil {
		sid, record := m.cfg.Session(ctx, a)
		rb.SessionID = sid
		if record != nil {
			record("alert fired: "+a.Body, p.Summary)
		}
	}

	// "no automated fix recommended" path: persist the runbook with
	// Skipped=true, emit no proposal cards, emit no push. The summary still
	// surfaces in inbox so the operator can see the AI considered it.
	if len(p.Steps) == 0 {
		rb.Skipped = true
		if p.Summary != "" {
			rb.SkippedMsg = p.Summary
		} else {
			rb.SkippedMsg = "no automated fix recommended"
		}
		rb.ContentHash = mustContentHash(rb)
		m.store(rb)
		return rb
	}

	// Blocked L3 path: the runbook is fully recorded and audited (steps,
	// exact commands, rollback, verification — everything an operator
	// needs to see why it was blocked and what a maintenance session would
	// do) but produces zero executable proposal IDs. incident.runbook.execute
	// (Task 3) rejects an L3 runbook outright even if one somehow reached
	// it; this package additionally never gives it anything to execute.
	if rb.Blocked {
		rb.ContentHash = mustContentHash(rb)
		m.store(rb)
		m.publish(ctx, rb)
		return rb
	}

	for _, step := range rb.Steps {
		rationale := step.Description
		if rationale == "" {
			rationale = p.Summary
		}
		action, projectID, _, files, err := tokenBindingForKind(step.Kind, step.Params)
		if err != nil {
			// Skip invalid steps but keep the runbook so the operator
			// sees what the AI proposed and why it was malformed. The
			// step is recorded with no proposal ID.
			rb.ProposalIDs = append(rb.ProposalIDs, "")
			continue
		}
		ap, err := m.cfg.AIProposals.Create(aiproposal.Proposal{
			Kind:           step.Kind,
			Params:         step.Params,
			Rationale:      rationale,
			SessionID:      rb.SessionID,
			TokenAction:    action,
			TokenProjectID: projectID,
			TokenFiles:     files,
		})
		if err != nil {
			rb.ProposalIDs = append(rb.ProposalIDs, "")
			continue
		}
		rb.ProposalIDs = append(rb.ProposalIDs, ap.ID)
	}

	rb.ContentHash = mustContentHash(rb)
	m.store(rb)
	m.publish(ctx, rb)
	return rb
}

// mustContentHash computes rb's content hash, treating a hash failure as a
// programmer error: Params originates from json.Unmarshal (string, float64,
// bool, nil, []any, map[string]any only) and is therefore always
// marshalable, so ContentHash cannot fail on any runbook this package
// constructs.
func mustContentHash(rb Runbook) string {
	hash, err := ContentHash(rb)
	if err != nil {
		panic(fmt.Sprintf("runbook: content hash: %v", err))
	}
	return hash
}

// canonicalRunbook is the canonical, hashable shape of a Runbook: every
// execution-relevant field the design's canonical-hash section lists, and
// nothing else. Lifecycle/mutable fields (ID, timestamps, ContentHash
// itself, Skipped*, ProposalIDs, SessionID, ...) are deliberately absent —
// recording an execution or a lifecycle transition must never change an
// already-approved runbook's hash.
type canonicalRunbook struct {
	SchemaVersion      int                 `json:"schemaVersion"`
	IncidentID         string              `json:"incidentId"`
	ServerID           string              `json:"serverId"`
	DiagnosisID        string              `json:"diagnosisId"`
	Risk               Risk                `json:"risk"`
	Steps              []canonicalStep     `json:"steps"`
	RunAs              string              `json:"runAs"`
	AffectedFiles      []string            `json:"affectedFiles"`
	AffectedServices   []string            `json:"affectedServices"`
	Interruption       string              `json:"interruption"`
	Rollback           []Command           `json:"rollback"`
	Verification       []VerificationCheck `json:"verification"`
	ExternalMonitorIDs []string            `json:"externalMonitorIds"`
}

type canonicalStep struct {
	Kind        string         `json:"kind"`
	Params      map[string]any `json:"params"`
	Command     string         `json:"command"`
	Description string         `json:"description"`
}

// ContentHash computes the canonical SHA-256 content hash of rb: the
// integrity fingerprint the phone binds its confirmation token to and the
// agent recomputes before ever mutating a host (see the approval/integrity
// section of the remediation design). Ordered fields (steps, rollback,
// verification, external monitor IDs) stay in their given order; the
// affected-file/service sets are hashed after sorting a *copy* so two
// operationally-identical runbooks that merely enumerate the same set in a
// different order hash identically — rb is never mutated by this call.
func ContentHash(rb Runbook) (string, error) {
	canonical := canonicalRunbook{
		SchemaVersion:      rb.SchemaVersion,
		IncidentID:         rb.IncidentID,
		ServerID:           rb.ServerID,
		DiagnosisID:        rb.DiagnosisID,
		Risk:               rb.Risk,
		Steps:              canonicalSteps(rb.Steps),
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
	// Round-trip through a generic map so every nesting level's object
	// keys end up lexicographically sorted — encoding/json sorts
	// map[string]any keys on Marshal — independent of the Go struct
	// field declaration order above. This is what makes the hash
	// reproducible across processes/versions without hand-sorting every
	// struct's fields.
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

func canonicalSteps(steps []Step) []canonicalStep {
	out := make([]canonicalStep, len(steps))
	for i, s := range steps {
		out[i] = canonicalStep{
			Kind:        string(s.Kind),
			Params:      s.Params,
			Command:     s.Command,
			Description: s.Description,
		}
	}
	return out
}

// sortedCopy returns a lexicographically sorted copy of ss; ss itself is
// never mutated.
func sortedCopy(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}

// tokenBindingForKind mirrors the binding helpers the server uses for
// human-initiated infra mutations so the aiproposal's confirmation token
// hashes the same way regardless of source. Kept here (rather than imported
// from server) because importing server would close an architectural cycle:
// server already imports runbook. It is also the single source of truth for
// each step's exact command display (see Step.Command): the display is
// derived from the same validated typed action that executes, never a
// friendly-only substitute.
func tokenBindingForKind(kind aiproposal.Kind, params map[string]any) (action, projectID, command string, files []string, err error) {
	switch kind {
	case aiproposal.KindServiceAction:
		name, _ := params["name"].(string)
		act, _ := params["action"].(string)
		if name == "" || act == "" {
			return "", "", "", nil, errors.New("service step missing name/action")
		}
		// Binding shape matches serviceLifecycleTokenBinding in server.
		return "infra.service." + act, "infra", fmt.Sprintf("systemctl %s %s", act, name), []string{name}, nil
	case aiproposal.KindProcessKill:
		pid := intFrom(params["pid"])
		startTicks := uint64From(params["start_time_ticks"])
		sig, _ := params["signal"].(string)
		if pid <= 0 || startTicks == 0 {
			return "", "", "", nil, errors.New("process_kill step missing pid/start_time_ticks")
		}
		if sig == "" {
			sig = "TERM"
		}
		return "infra.process.kill", "infra", fmt.Sprintf("kill -%s %d", sig, pid), []string{fmt.Sprintf("pid:%d:%d:%s", pid, startTicks, sig)}, nil
	case aiproposal.KindFirewallAdd, aiproposal.KindFirewallRemove:
		port := intFrom(params["port"])
		if port <= 0 {
			return "", "", "", nil, errors.New("firewall step missing port")
		}
		proto, _ := params["protocol"].(string)
		if proto == "" {
			proto = "tcp"
		}
		actStr, _ := params["action"].(string)
		source, _ := params["source"].(string)
		verb := "rule_add"
		cmdVerb := "insert"
		if kind == aiproposal.KindFirewallRemove {
			verb = "rule_remove"
			cmdVerb = "delete"
		}
		policy := actStr
		if policy == "" {
			policy = "deny"
		}
		cmd := fmt.Sprintf("ufw %s %s %d/%s", cmdVerb, policy, port, proto)
		return "infra.firewall." + verb, "infra", cmd, []string{fmt.Sprintf("%s:%s:%d:%s:%s", actStr, proto, port, source, "")}, nil
	case aiproposal.KindSecurityFix:
		fixKind, _ := params["kind"].(string)
		if fixKind == "" {
			return "", "", "", nil, errors.New("security fix step missing kind")
		}
		if fixKind == "run_script" {
			script, _ := params["script"].(string)
			if strings.TrimSpace(script) == "" {
				return "", "", "", nil, errors.New("security fix step missing script")
			}
			// Bind to the exact script text (not a short label) so the
			// confirmation token's action hash — and the displayed
			// command — pin approval to precisely what will execute as
			// root.
			return "security.fix.run_script", "security", script, []string{script}, nil
		}
		cmd, err := securityFixCommand(fixKind, params)
		if err != nil {
			return "", "", "", nil, err
		}
		return "security.fix." + fixKind, "security", cmd, []string{securityFixTarget(fixKind, params)}, nil
	}
	return "", "", "", nil, fmt.Errorf("runbook: unsupported step kind %q", kind)
}

func securityFixTarget(kind string, params map[string]any) string {
	switch kind {
	case "close_port":
		proto, _ := params["protocol"].(string)
		if proto == "" {
			proto = "tcp"
		}
		return fmt.Sprintf("%s/%d", proto, intFrom(params["port"]))
	case "kill_process":
		return fmt.Sprintf("pid/%d/%d", intFrom(params["pid"]), uint64From(params["start_time_ticks"]))
	case "enable_auditd":
		return "auditd"
	default:
		return kind
	}
}

func securityFixCommand(kind string, params map[string]any) (string, error) {
	switch kind {
	case "close_port":
		proto, _ := params["protocol"].(string)
		if proto == "" {
			proto = "tcp"
		}
		port := intFrom(params["port"])
		if port <= 0 {
			return "", errors.New("close_port step missing port")
		}
		return fmt.Sprintf("iptables -A INPUT -p %s --dport %d -j DROP", proto, port), nil
	case "kill_process":
		pid := intFrom(params["pid"])
		if pid <= 0 {
			return "", errors.New("kill_process step missing pid")
		}
		sig, _ := params["signal"].(string)
		if sig == "" {
			sig = "TERM"
		}
		return fmt.Sprintf("kill -%s %d", sig, pid), nil
	case "enable_auditd":
		return "systemctl enable --now auditd", nil
	default:
		return "", fmt.Errorf("runbook: unsupported security fix kind %q", kind)
	}
}

func intFrom(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

func uint64From(v any) uint64 {
	switch n := v.(type) {
	case float64:
		return uint64(n)
	case int:
		return uint64(n)
	case int64:
		return uint64(n)
	case uint64:
		return n
	}
	return 0
}

func (m *Manager) store(rb Runbook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored := rb
	m.runbooks[rb.ID] = &stored
	m.order = append(m.order, rb.ID)
}

// publish broadcasts a single "infra.runbook" notification whose payload
// gives the mobile client everything it needs to deep-link into the
// approval-card screen (RunbookID) and to render the row in inbox (Summary,
// Risk, ProposalIDs count, Blocked/BlockedReason for the L3 case).
func (m *Manager) publish(ctx context.Context, rb Runbook) {
	if m.cfg.Notifications == nil {
		return
	}
	severity := "warning"
	if rb.Blocked || rb.Risk == RiskL2 || rb.Risk == RiskL3 {
		severity = "critical"
	}
	body := rb.Summary
	if rb.Blocked {
		switch {
		case rb.Summary != "":
			body = rb.Summary + " — " + rb.BlockedReason
		default:
			body = rb.BlockedReason
		}
	}
	if body == "" {
		body = fmt.Sprintf("%d-step runbook for %s", len(rb.ProposalIDs), rb.AlertKey)
	}
	_ = m.cfg.Notifications.Publish(ctx, notifications.Notification{
		ID:        "infra-runbook-" + rb.ID,
		Type:      "infra.runbook",
		Title:     "AI runbook: " + rb.Rule,
		Body:      body,
		Severity:  severity,
		CreatedAt: rb.CreatedAt,
		Data: map[string]any{
			"runbook_id":     rb.ID,
			"alert_key":      rb.AlertKey,
			"server_id":      rb.ServerID,
			"rule":           rb.Rule,
			"target":         rb.Target,
			"summary":        rb.Summary,
			"risk":           string(rb.Risk),
			"session_id":     rb.SessionID,
			"proposal_ids":   rb.ProposalIDs,
			"step_count":     len(rb.Steps),
			"deep_link":      "runbook/" + rb.ID,
			"blocked":        rb.Blocked,
			"blocked_reason": rb.BlockedReason,
			"content_hash":   rb.ContentHash,
		},
	})
}

// Get returns one runbook by ID.
func (m *Manager) Get(id string) (Runbook, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rb, ok := m.runbooks[id]
	if !ok {
		return Runbook{}, false
	}
	return *rb, true
}

// List returns runbooks newest-first.
func (m *Manager) List() []Runbook {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Runbook, 0, len(m.order))
	for _, id := range m.order {
		if rb, ok := m.runbooks[id]; ok {
			out = append(out, *rb)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// alertFromNotification adapts an "infra.alert" notification into the
// Alert shape this package consumes. It returns ok=false for non-alert
// notifications and for the "alert cleared" edge (Data["clear"]=true) so
// recovery notifications do not trigger a runbook.
func alertFromNotification(n notifications.Notification) (Alert, bool) {
	if n.Type != "infra.alert" {
		return Alert{}, false
	}
	if clr, ok := n.Data["clear"].(bool); ok && clr {
		return Alert{}, false
	}
	serverID, _ := n.Data["server_id"].(string)
	rule, _ := n.Data["rule"].(string)
	target, _ := n.Data["target"].(string)
	return Alert{
		ServerID: serverID,
		Rule:     rule,
		Target:   target,
		Body:     n.Body,
		Severity: n.Severity,
		FiredAt:  n.CreatedAt,
	}, true
}

func randomID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
