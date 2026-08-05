package runbook

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/notifications"
)

// stubProposer returns a canned Proposal and counts invocations so throttle
// tests can assert "called exactly once".
type stubProposer struct {
	mu        sync.Mutex
	result    Proposal
	err       error
	calls     int
	gotAlert  Alert
	gotGround Grounding
}

func (s *stubProposer) Propose(_ context.Context, a Alert, g Grounding) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.gotAlert = a
	s.gotGround = g
	return s.result, s.err
}

func (s *stubProposer) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func newTestManager(t *testing.T, proposer Proposer) (*Manager, *aiproposal.Manager, *notifications.Hub) {
	t.Helper()
	apm := aiproposal.New()
	hub := notifications.NewHub()
	m, err := New(Config{
		AIProposals:   apm,
		Proposer:      proposer,
		Notifications: hub,
		Now:           func() time.Time { return time.Unix(1700000000, 0) },
		Throttle:      50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m, apm, hub
}

func sampleAlert() Alert {
	return Alert{
		ServerID: "local",
		Rule:     "disk_usage",
		Target:   "/",
		Body:     "Disk / usage 91.0%",
		Severity: "warning",
		FiredAt:  time.Unix(1700000000, 0),
	}
}

// completeRunbookFixture returns a fully populated, content-hashed Runbook
// covering every approval-relevant field so hash tests can mutate a single
// field at a time and assert the hash moves.
func completeRunbookFixture() Runbook {
	rb := Runbook{
		ID:              "rb-1",
		SchemaVersion:   SchemaVersion,
		IncidentID:      "inc-1",
		ServerID:        "srv-1",
		DiagnosisID:     "diag-1",
		ProviderVersion: "claude-1",
		AlertKey:        "disk_usage:/",
		Rule:            "disk_usage",
		Target:          "/",
		Summary:         "restart api and rotate logs",
		RiskExplanation: "reversible service restart with a brief interruption",
		Risk:            RiskL1,
		RunAs:           "root",
		Steps: []Step{
			{
				Kind:        aiproposal.KindServiceAction,
				Params:      map[string]any{"name": "api.service", "action": "restart"},
				Description: "restart api",
				Command:     "systemctl restart api.service",
			},
		},
		AffectedFiles:    []string{"/etc/api.conf", "/var/log/api.log"},
		AffectedServices: []string{"api.service", "log-rotate.service"},
		Interruption:     "api unavailable for ~5s during restart",
		Rollback: []Command{
			{Command: "systemctl start api.service", RunAs: "root", Description: "start api again if restart failed"},
		},
		Verification: []VerificationCheck{
			{ID: "chk-1", Kind: "service_active", Target: "api.service", Description: "api.service is active"},
		},
		ExternalMonitorIDs: []string{"mon-1", "mon-2"},
		CreatedAt:          time.Unix(1700000000, 0),
	}
	hash, err := ContentHash(rb)
	if err != nil {
		panic(err)
	}
	rb.ContentHash = hash
	return rb
}

// cloneRunbook deep-copies rb's slice/map fields so a test can mutate the
// clone without aliasing the original's backing arrays.
func cloneRunbook(rb Runbook) Runbook {
	c := rb
	c.Steps = make([]Step, len(rb.Steps))
	for i, s := range rb.Steps {
		c.Steps[i] = s
		c.Steps[i].Params = cloneParams(s.Params)
	}
	c.AffectedFiles = append([]string(nil), rb.AffectedFiles...)
	c.AffectedServices = append([]string(nil), rb.AffectedServices...)
	c.Rollback = append([]Command(nil), rb.Rollback...)
	c.Verification = append([]VerificationCheck(nil), rb.Verification...)
	c.ExternalMonitorIDs = append([]string(nil), rb.ExternalMonitorIDs...)
	c.ProposalIDs = append([]string(nil), rb.ProposalIDs...)
	return c
}

func cloneParams(p map[string]any) map[string]any {
	if p == nil {
		return nil
	}
	out := make(map[string]any, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// TestClassifyRisk is the exact table from the Task 1 plan: self-reported
// risk is honoured as a floor, but AI-authored raw shell always forces L3
// and blocks execution regardless of what the model self-reported.
func TestClassifyRisk(t *testing.T) {
	tests := []struct {
		name     string
		proposal Proposal
		want     Risk
		blocked  bool
	}{
		{"read only", Proposal{Risk: RiskL0}, RiskL0, false},
		{"service restart", Proposal{Risk: RiskL1, Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "api.service", "action": "restart"}}}}, RiskL1, false},
		{"configuration change", Proposal{Risk: RiskL2}, RiskL2, false},
		{"raw shell forced destructive", Proposal{Risk: RiskL1, Steps: []Step{{Kind: aiproposal.KindSecurityFix, Params: map[string]any{"kind": "run_script", "script": "rm -rf /srv/app/cache"}}}}, RiskL3, true},
		{"self-reported L3 is blocked even with no forcing step", Proposal{Risk: RiskL3, Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "api.service", "action": "restart"}}}}, RiskL3, true},
		{"firewall deny on ssh port forces destructive lockout risk", Proposal{Risk: RiskL1, Steps: []Step{{Kind: aiproposal.KindFirewallAdd, Params: map[string]any{"action": "deny", "port": 22, "protocol": "tcp"}}}}, RiskL3, true},
		{"firewall reject on ssh port forces destructive lockout risk", Proposal{Risk: RiskL1, Steps: []Step{{Kind: aiproposal.KindFirewallAdd, Params: map[string]any{"action": "reject", "port": 22, "protocol": "tcp"}}}}, RiskL3, true},
		{"firewall allow on ssh port remains the reported level", Proposal{Risk: RiskL1, Steps: []Step{{Kind: aiproposal.KindFirewallAdd, Params: map[string]any{"action": "allow", "port": 22, "protocol": "tcp"}}}}, RiskL1, false},
		{"security close_port ssh forces destructive lockout risk", Proposal{Risk: RiskL1, Steps: []Step{{Kind: aiproposal.KindSecurityFix, Params: map[string]any{"kind": "close_port", "backend": "ufw", "action": "deny", "port": 22, "protocol": "tcp"}}}}, RiskL3, true},
		{"missing/invalid self-reported risk defaults to L2, not silently safe", Proposal{Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "api.service", "action": "restart"}}}}, RiskL2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk, blocked := classifyProposal(tt.proposal)
			if risk != tt.want || blocked != tt.blocked {
				t.Fatalf("classify = %s,%v want %s,%v", risk, blocked, tt.want, tt.blocked)
			}
		})
	}
}

func TestTokenBindingForKind_RequiresValidatedFirewallBackendAndRendersExactCommands(t *testing.T) {
	tests := []struct {
		name    string
		kind    aiproposal.Kind
		params  map[string]any
		command string
		wantErr bool
	}{
		{"ufw add", aiproposal.KindFirewallAdd, map[string]any{"backend": "ufw", "action": "allow", "port": 443, "protocol": "tcp"}, "ufw allow 443/tcp", false},
		{"ufw remove", aiproposal.KindFirewallRemove, map[string]any{"backend": "ufw", "action": "allow", "port": 443, "protocol": "tcp"}, "ufw delete allow 443/tcp", false},
		{"firewalld add", aiproposal.KindFirewallAdd, map[string]any{"backend": "firewalld", "action": "allow", "port": 443, "protocol": "tcp"}, "firewall-cmd --zone=public --add-port=443/tcp --permanent && firewall-cmd --reload", false},
		{"firewalld remove with zone", aiproposal.KindFirewallRemove, map[string]any{"backend": "firewalld", "action": "allow", "zone": "internal", "port": 443, "protocol": "tcp"}, "firewall-cmd --zone=internal --remove-port=443/tcp --permanent && firewall-cmd --reload", false},
		{"security close port ufw", aiproposal.KindSecurityFix, map[string]any{"kind": "close_port", "backend": "ufw", "port": 443, "protocol": "tcp"}, "ufw deny 443/tcp", false},
		{"security close port firewalld", aiproposal.KindSecurityFix, map[string]any{"kind": "close_port", "backend": "firewalld", "port": 443, "protocol": "tcp"}, "firewall-cmd --zone=public --remove-port=443/tcp --permanent && firewall-cmd --reload", false},
		{"missing backend", aiproposal.KindFirewallAdd, map[string]any{"action": "allow", "port": 443, "protocol": "tcp"}, "", true},
		{"missing action", aiproposal.KindFirewallAdd, map[string]any{"backend": "ufw", "port": 443, "protocol": "tcp"}, "", true},
		{"unsupported backend", aiproposal.KindFirewallAdd, map[string]any{"backend": "iptables", "action": "allow", "port": 443, "protocol": "tcp"}, "", true},
		{"firewalld explicit deny", aiproposal.KindFirewallAdd, map[string]any{"backend": "firewalld", "action": "deny", "port": 443, "protocol": "tcp"}, "", true},
		{"close port missing backend", aiproposal.KindSecurityFix, map[string]any{"kind": "close_port", "port": 443, "protocol": "tcp"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, command, _, err := tokenBindingForKind(tt.kind, tt.params)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected invalid backend/action to be rejected")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if command != tt.command {
				t.Fatalf("command=%q want %q", command, tt.command)
			}
		})
	}
}

func TestHandle_InvalidFirewallBackendOrActionDoesNotFanOut(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
	}{
		{"missing backend", map[string]any{"action": "allow", "port": 443, "protocol": "tcp"}},
		{"missing action", map[string]any{"backend": "ufw", "port": 443, "protocol": "tcp"}},
		{"firewalld deny", map[string]any{"backend": "firewalld", "action": "deny", "port": 443, "protocol": "tcp"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, apm, _ := newTestManager(t, &stubProposer{result: Proposal{
				Summary: "invalid firewall operation",
				Risk:    RiskL1,
				Steps:   []Step{{Kind: aiproposal.KindFirewallAdd, Params: tt.params}},
			}})
			rb := m.Handle(context.Background(), sampleAlert())
			if len(rb.ProposalIDs) != 1 || rb.ProposalIDs[0] != "" {
				t.Fatalf("invalid firewall step should get one empty proposal slot, got %+v", rb.ProposalIDs)
			}
			if len(apm.List()) != 0 {
				t.Fatalf("invalid firewall step fanned out %d aiproposals", len(apm.List()))
			}
		})
	}
}

func TestHandle_NonMarshalableParamsFailClosedWithoutFanout(t *testing.T) {
	m, apm, _ := newTestManager(t, &stubProposer{result: Proposal{
		Summary: "restart api",
		Risk:    RiskL1,
		Steps: []Step{{
			Kind:   aiproposal.KindServiceAction,
			Params: map[string]any{"name": "api.service", "action": "restart", "unexpected": func() {}},
		}},
	}})
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("non-marshalable Params must fail closed, not panic: %v", recovered)
		}
	}()

	rb := m.Handle(context.Background(), sampleAlert())
	if rb.ID != "" {
		t.Fatalf("non-marshalable Params should reject the runbook, got %+v", rb)
	}
	if len(apm.List()) != 0 {
		t.Fatalf("non-marshalable Params must not fan out aiproposals, got %d", len(apm.List()))
	}
}

func TestRisk_NoLowMediumHighAliasesExist(t *testing.T) {
	// Compile-time-ish guard: the only valid Risk values are L0-L3. This
	// test exists so a future regression that reintroduces a
	// low/medium/high alias constant is caught the moment it's used here.
	for _, r := range []Risk{RiskL0, RiskL1, RiskL2, RiskL3} {
		if !r.valid() {
			t.Fatalf("%q should be a valid risk level", r)
		}
	}
	for _, r := range []Risk{"low", "medium", "high", ""} {
		if r.valid() {
			t.Fatalf("%q must not be a valid risk level", r)
		}
	}
}

// TestContentHashChangesForEveryApprovalField is the exact test from the
// Task 1 plan: every approval-relevant field must move the hash.
func TestContentHashChangesForEveryApprovalField(t *testing.T) {
	base := completeRunbookFixture()
	original := base.ContentHash
	mutations := []func(*Runbook){
		func(r *Runbook) { r.Steps[0].Command = "systemctl stop api" },
		func(r *Runbook) { r.RunAs = "deploy" },
		func(r *Runbook) { r.AffectedFiles = append(r.AffectedFiles, "/etc/api.conf") },
		func(r *Runbook) { r.Rollback[0].Command = "systemctl restart api" },
		func(r *Runbook) { r.Verification[0].Target = "api.socket" },
	}
	for _, mutate := range mutations {
		candidate := cloneRunbook(base)
		mutate(&candidate)
		got, err := ContentHash(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if got == original {
			t.Fatal("approval-relevant mutation did not change hash")
		}
	}
}

// TestContentHashChangesForRemainingRequiredFields covers the immutable
// shape fields the plan's table didn't enumerate explicitly (schema
// version, incident/server/diagnosis IDs, risk, interruption, external
// monitor IDs, step kind/params) so every field in the canonical hash
// section of the design is actually load-bearing. Step Description is
// deliberately omitted: it is explanatory prose, not approved executable
// content.
func TestContentHashChangesForRemainingRequiredFields(t *testing.T) {
	base := completeRunbookFixture()
	original := base.ContentHash
	mutations := []func(*Runbook){
		func(r *Runbook) { r.SchemaVersion = r.SchemaVersion + 1 },
		func(r *Runbook) { r.IncidentID = "inc-2" },
		func(r *Runbook) { r.ServerID = "srv-2" },
		func(r *Runbook) { r.DiagnosisID = "diag-2" },
		func(r *Runbook) { r.Risk = RiskL2 },
		func(r *Runbook) { r.Interruption = "extended outage" },
		func(r *Runbook) { r.AffectedServices = append(r.AffectedServices, "extra.service") },
		func(r *Runbook) { r.ExternalMonitorIDs = append(r.ExternalMonitorIDs, "mon-3") },
		func(r *Runbook) { r.Steps[0].Params["name"] = "other.service" },
		func(r *Runbook) { r.Steps[0].Kind = aiproposal.KindProcessKill },
		func(r *Runbook) { r.Rollback[0].RunAs = "deploy" },
		func(r *Runbook) { r.Verification[0].Kind = "socket_listening" },
		func(r *Runbook) {
			r.Rollback = append(r.Rollback, Command{Command: "true", RunAs: "root", Description: "extra"})
		},
		func(r *Runbook) {
			r.Verification = append(r.Verification, VerificationCheck{ID: "chk-2", Kind: "socket_listening", Target: "api.socket"})
		},
	}
	for i, mutate := range mutations {
		candidate := cloneRunbook(base)
		mutate(&candidate)
		got, err := ContentHash(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if got == original {
			t.Fatalf("mutation #%d did not change the content hash", i)
		}
	}
}

// TestContentHash_LifecycleFieldsExcluded verifies mutable lifecycle
// fields (ID, timestamps, session, summary/skip bookkeeping, the hash
// itself, proposal IDs) are NOT part of the canonical hash: recording an
// execution or a lifecycle transition must never invalidate an
// already-approved runbook.
func TestContentHash_LifecycleFieldsExcluded(t *testing.T) {
	base := completeRunbookFixture()
	original := base.ContentHash
	resolved := time.Unix(1700000500, 0)
	mutations := []func(*Runbook){
		func(r *Runbook) { r.ID = "rb-2" },
		func(r *Runbook) { r.CreatedAt = r.CreatedAt.Add(time.Hour) },
		func(r *Runbook) { r.SessionID = "sess-99" },
		func(r *Runbook) { r.Summary = "different human summary" },
		func(r *Runbook) { r.RiskExplanation = "different explanation" },
		func(r *Runbook) { r.ProviderVersion = "codex-2" },
		func(r *Runbook) { r.AlertKey = "other:key" },
		func(r *Runbook) { r.ProposalIDs = []string{"p-1"} },
		func(r *Runbook) { r.ResolvedAt = &resolved },
		func(r *Runbook) { r.ContentHash = "stale" },
	}
	for i, mutate := range mutations {
		candidate := cloneRunbook(base)
		mutate(&candidate)
		got, err := ContentHash(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if got != original {
			t.Fatalf("lifecycle mutation #%d unexpectedly changed the content hash", i)
		}
	}
}

// TestContentHash_ExcludesStepDescription verifies explanatory step text
// cannot invalidate an approval: the approved canonical field list contains
// typed steps, normalized parameters, and exact command display, but not
// free-text Step.Description.
func TestContentHash_ExcludesStepDescription(t *testing.T) {
	base := completeRunbookFixture()
	candidate := cloneRunbook(base)
	candidate.Steps[0].Description = "operator-facing prose changed after review"

	got, err := ContentHash(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if got != base.ContentHash {
		t.Fatalf("Step.Description-only mutation changed the hash: %s vs %s", got, base.ContentHash)
	}
}

// TestContentHash_AffectedSetsOrderIndependent covers "set sorting":
// reordering the same set of affected files/services must hash identically.
func TestContentHash_AffectedSetsOrderIndependent(t *testing.T) {
	base := completeRunbookFixture()
	reordered := cloneRunbook(base)
	reordered.AffectedFiles = []string{"/var/log/api.log", "/etc/api.conf"}
	reordered.AffectedServices = []string{"log-rotate.service", "api.service"}

	h1, err := ContentHash(base)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ContentHash(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("reordering affected files/services (same set) changed the hash: %s vs %s", h1, h2)
	}
}

// TestContentHash_OrderedListsAreOrderSensitive covers "ordered list
// sensitivity": unlike affected files/services, steps/rollback/verification
// execute in order, so reordering them must change the hash.
func TestContentHash_OrderedListsAreOrderSensitive(t *testing.T) {
	base := completeRunbookFixture()
	base.Steps = append(base.Steps, Step{
		Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "log-rotate.service", "action": "restart"},
		Command: "systemctl restart log-rotate.service",
	})
	base.Rollback = append(base.Rollback, Command{Command: "systemctl stop log-rotate.service", RunAs: "root", Description: "stop the rotate step's target"})
	base.Verification = append(base.Verification, VerificationCheck{ID: "chk-2", Kind: "service_active", Target: "log-rotate.service"})
	base.ExternalMonitorIDs = append(base.ExternalMonitorIDs, "mon-3")

	baseHash, err := ContentHash(base)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("steps", func(t *testing.T) {
		reordered := cloneRunbook(base)
		reordered.Steps[0], reordered.Steps[1] = reordered.Steps[1], reordered.Steps[0]
		got, err := ContentHash(reordered)
		if err != nil {
			t.Fatal(err)
		}
		if got == baseHash {
			t.Fatal("reordering steps did not change the hash")
		}
	})

	t.Run("rollback", func(t *testing.T) {
		reordered := cloneRunbook(base)
		reordered.Rollback[0], reordered.Rollback[1] = reordered.Rollback[1], reordered.Rollback[0]
		got, err := ContentHash(reordered)
		if err != nil {
			t.Fatal(err)
		}
		if got == baseHash {
			t.Fatal("reordering rollback steps did not change the hash")
		}
	})

	t.Run("verification", func(t *testing.T) {
		reordered := cloneRunbook(base)
		reordered.Verification[0], reordered.Verification[1] = reordered.Verification[1], reordered.Verification[0]
		got, err := ContentHash(reordered)
		if err != nil {
			t.Fatal(err)
		}
		if got == baseHash {
			t.Fatal("reordering verification checks did not change the hash")
		}
	})

	t.Run("external monitor ids", func(t *testing.T) {
		reordered := cloneRunbook(base)
		reordered.ExternalMonitorIDs[0], reordered.ExternalMonitorIDs[1] = reordered.ExternalMonitorIDs[1], reordered.ExternalMonitorIDs[0]
		got, err := ContentHash(reordered)
		if err != nil {
			t.Fatal(err)
		}
		if got == baseHash {
		}
	})
}

// TestContentHash_DeterministicAndDoesNotMutateInput covers determinism
// (same input -> same hash, every call) and the "sort copies ... without
// mutating the runbook" requirement.
func TestContentHash_DeterministicAndDoesNotMutateInput(t *testing.T) {
	base := completeRunbookFixture()
	filesBefore := append([]string(nil), base.AffectedFiles...)
	servicesBefore := append([]string(nil), base.AffectedServices...)

	h1, err := ContentHash(base)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ContentHash(base)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("ContentHash is not deterministic: %s vs %s", h1, h2)
	}
	if !reflect.DeepEqual(base.AffectedFiles, filesBefore) {
		t.Fatalf("ContentHash mutated AffectedFiles order: %v (was %v)", base.AffectedFiles, filesBefore)
	}
	if !reflect.DeepEqual(base.AffectedServices, servicesBefore) {
		t.Fatalf("ContentHash mutated AffectedServices order: %v (was %v)", base.AffectedServices, servicesBefore)
	}
}

func TestHandle_CreatesRunbookAndFansOutSteps(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "rotate journal logs, restart postgres",
		Risk:    RiskL2,
		Steps: []Step{
			{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "postgres.service", "action": "restart"}, Description: "restart postgres"},
		},
	}}
	m, apm, _ := newTestManager(t, prop)

	rb := m.Handle(context.Background(), sampleAlert())
	if rb.ID == "" {
		t.Fatalf("expected runbook ID, got zero")
	}
	if len(rb.ProposalIDs) != 1 || rb.ProposalIDs[0] == "" {
		t.Fatalf("step not fanned out as aiproposal: %+v", rb.ProposalIDs)
	}
	if rb.Skipped {
		t.Fatalf("non-empty steps should not be Skipped")
	}
	if rb.Risk != RiskL2 {
		t.Fatalf("risk=%q want L2", rb.Risk)
	}
	if rb.Blocked {
		t.Fatalf("L2 runbook must not be blocked")
	}
	if rb.ContentHash == "" {
		t.Fatalf("expected a non-empty content hash")
	}
	if rb.Steps[0].Command != "systemctl restart postgres.service" {
		t.Fatalf("step command not derived from the typed action: %q", rb.Steps[0].Command)
	}

	// aiproposal must be queryable with the existing approve path's binding.
	ap, err := apm.Get(rb.ProposalIDs[0])
	if err != nil {
		t.Fatalf("aiproposal.Get: %v", err)
	}
	if ap.TokenAction != "infra.service.restart" {
		t.Fatalf("token action mismatch: %q", ap.TokenAction)
	}
	if len(ap.TokenFiles) != 1 || ap.TokenFiles[0] != "postgres.service" {
		t.Fatalf("token files mismatch: %+v", ap.TokenFiles)
	}
	if ap.Rationale != "restart postgres" {
		t.Fatalf("rationale mismatch: %q", ap.Rationale)
	}
}

func TestHandleManual_UsesSelectedAgentProposerAndBypassesThrottle(t *testing.T) {
	defaultProp := &stubProposer{result: Proposal{
		Summary: "default",
		Risk:    RiskL1,
		Steps:   []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "default.service", "action": "restart"}}},
	}}
	codexProp := &stubProposer{result: Proposal{
		Summary: "codex fix",
		Risk:    RiskL1,
		Steps:   []Step{{Kind: aiproposal.KindFirewallAdd, Params: map[string]any{"backend": "ufw", "action": "deny", "protocol": "tcp", "port": 6379}}},
	}}
	apm := aiproposal.New()
	m, err := New(Config{
		AIProposals: apm,
		Proposer:    defaultProp,
		ProposerForAgent: func(agent string) Proposer {
			if agent == "codex" {
				return codexProp
			}
			return nil
		},
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
		Throttle: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	rb1, err := m.HandleManual(context.Background(), sampleAlert(), "codex")
	if err != nil {
		t.Fatal(err)
	}
	rb2, err := m.HandleManual(context.Background(), sampleAlert(), "codex")
	if err != nil {
		t.Fatal(err)
	}
	if rb1.ID == "" || rb2.ID == "" {
		t.Fatalf("manual runbooks should be created, got %+v %+v", rb1, rb2)
	}
	if defaultProp.Calls() != 0 {
		t.Fatalf("default proposer calls=%d, want 0", defaultProp.Calls())
	}
	if codexProp.Calls() != 2 {
		t.Fatalf("codex proposer calls=%d, want 2", codexProp.Calls())
	}
	if len(apm.List()) != 2 {
		t.Fatalf("aiproposals=%d, want 2", len(apm.List()))
	}
}

func TestHandleManual_ReturnsProposerError(t *testing.T) {
	proposer := &stubProposer{err: errors.New("codex exec: auth token expired")}
	m, _, _ := newTestManager(t, proposer)

	_, err := m.HandleManual(context.Background(), sampleAlert(), "")
	if err == nil {
		t.Fatal("expected proposer error")
	}
	if !strings.Contains(err.Error(), "auth token expired") {
		t.Fatalf("err=%q", err)
	}
}

func TestHandle_SecurityFixStepFansOutAsProposal(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "enable auditd",
		Risk:    RiskL1,
		Steps: []Step{{
			Kind:        aiproposal.KindSecurityFix,
			Params:      map[string]any{"kind": "enable_auditd"},
			Description: "install and enable auditd",
		}},
	}}
	m, apm, _ := newTestManager(t, prop)

	rb := m.Handle(context.Background(), sampleAlert())
	if rb.ID == "" || len(rb.ProposalIDs) != 1 || rb.ProposalIDs[0] == "" {
		t.Fatalf("runbook/proposals = %+v", rb)
	}
	if rb.Blocked {
		t.Fatalf("enable_auditd is not raw shell and must not be blocked")
	}
	ap, err := apm.Get(rb.ProposalIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if ap.Kind != aiproposal.KindSecurityFix {
		t.Fatalf("kind = %q", ap.Kind)
	}
	if ap.TokenAction != "security.fix.enable_auditd" || ap.TokenProjectID != "security" || len(ap.TokenFiles) != 1 || ap.TokenFiles[0] != "auditd" {
		t.Fatalf("token binding = %s %s %+v", ap.TokenAction, ap.TokenProjectID, ap.TokenFiles)
	}
}

// TestHandle_RunScriptStepForcesL3BlockedNoProposalFanout covers the L3
// blocking contract end to end: any AI-authored raw shell step forces L3
// regardless of the model's self-reported risk, the runbook is fully
// recorded (steps + exact command display included) for audit, but zero
// aiproposals are created and BlockedReason recommends a maintenance
// session instead of an executable proposal.
func TestHandle_RunScriptStepForcesL3BlockedNoProposalFanout(t *testing.T) {
	script := "chmod 640 /etc/shadow && chown root:shadow /etc/shadow"
	prop := &stubProposer{result: Proposal{
		Summary: "tighten /etc/shadow permissions",
		Risk:    RiskL1, // model under-reports; manager must not trust this.
		Steps: []Step{{
			Kind:        aiproposal.KindSecurityFix,
			Params:      map[string]any{"kind": "run_script", "script": script},
			Description: "fix /etc/shadow ownership and permissions",
		}},
	}}
	m, apm, _ := newTestManager(t, prop)

	rb := m.Handle(context.Background(), sampleAlert())
	if rb.Risk != RiskL3 {
		t.Fatalf("risk = %q, want forced L3 for a run_script step", rb.Risk)
	}
	if !rb.Blocked {
		t.Fatal("expected Blocked=true for a run_script step")
	}
	if rb.BlockedReason != BlockedL3Reason {
		t.Fatalf("blocked reason = %q, want %q", rb.BlockedReason, BlockedL3Reason)
	}
	if len(rb.ProposalIDs) != 0 {
		t.Fatalf("blocked L3 runbook must create no executable proposal IDs, got %+v", rb.ProposalIDs)
	}
	if len(apm.List()) != 0 {
		t.Fatalf("blocked L3 runbook must fan out zero aiproposals, got %d", len(apm.List()))
	}
	// Still fully recorded/audited: the exact command is derived from the
	// same typed action a maintenance session would review.
	if len(rb.Steps) != 1 || rb.Steps[0].Command != script {
		t.Fatalf("blocked runbook should still record the exact command for audit: %+v", rb.Steps)
	}
	if rb.ContentHash == "" {
		t.Fatal("blocked runbook must still be content-hashed")
	}
}

// TestHandle_RunScriptStepMissingScriptStillBlockedNoFanout covers a
// malformed run_script step: it must still be classified/blocked as L3
// (it's still an AI-authored raw-shell attempt) even though there is no
// valid script to derive a command from.
func TestHandle_RunScriptStepMissingScriptStillBlockedNoFanout(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "bad step",
		Risk:    RiskL2,
		Steps: []Step{{
			Kind:   aiproposal.KindSecurityFix,
			Params: map[string]any{"kind": "run_script"},
		}},
	}}
	m, apm, _ := newTestManager(t, prop)

	rb := m.Handle(context.Background(), sampleAlert())
	if !rb.Blocked || rb.Risk != RiskL3 {
		t.Fatalf("expected blocked L3, got risk=%q blocked=%v", rb.Risk, rb.Blocked)
	}
	if len(rb.ProposalIDs) != 0 {
		t.Fatalf("expected zero proposal IDs for a blocked runbook, got %+v", rb.ProposalIDs)
	}
	if len(apm.List()) != 0 {
		t.Fatalf("expected zero aiproposals, got %d", len(apm.List()))
	}
}

func TestHandle_NoFixRecommendedProducesNoProposalsAndNoPush(t *testing.T) {
	prop := &stubProposer{result: Proposal{Summary: "manual investigation required"}}
	m, apm, hub := newTestManager(t, prop)

	var pushes int32
	unsub := hub.Subscribe(func(n notifications.Notification) {
		if n.Type == "infra.runbook" {
			atomic.AddInt32(&pushes, 1)
		}
	})
	defer unsub()

	rb := m.Handle(context.Background(), sampleAlert())
	if !rb.Skipped {
		t.Fatalf("expected Skipped=true")
	}
	if len(rb.ProposalIDs) != 0 {
		t.Fatalf("no-fix path must not create proposals: %+v", rb.ProposalIDs)
	}
	if len(apm.List()) != 0 {
		t.Fatalf("no-fix path created %d aiproposals", len(apm.List()))
	}
	if atomic.LoadInt32(&pushes) != 0 {
		t.Fatalf("no-fix path emitted %d push notifications", pushes)
	}
}

func TestHandle_ThrottlePreventsDuplicateWithinWindow(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "x", Risk: RiskL1,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "x.service", "action": "restart"}}},
	}}
	m, _, _ := newTestManager(t, prop)

	rb1 := m.Handle(context.Background(), sampleAlert())
	rb2 := m.Handle(context.Background(), sampleAlert())
	if rb1.ID == "" {
		t.Fatalf("first call should produce a runbook")
	}
	if rb2.ID != "" {
		t.Fatalf("throttled call should produce zero runbook, got %+v", rb2)
	}
	if prop.Calls() != 1 {
		t.Fatalf("proposer calls=%d, want 1 (throttled)", prop.Calls())
	}
}

func TestHandle_ThrottleAdvancesWithTimeAfterWindow(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "x", Risk: RiskL1,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "x.service", "action": "restart"}}},
	}}
	apm := aiproposal.New()
	clock := time.Unix(1700000000, 0)
	m, err := New(Config{
		AIProposals: apm,
		Proposer:    prop,
		Now:         func() time.Time { return clock },
		Throttle:    10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	if rb := m.Handle(context.Background(), sampleAlert()); rb.ID == "" {
		t.Fatalf("first should fire")
	}
	clock = clock.Add(11 * time.Minute)
	if rb := m.Handle(context.Background(), sampleAlert()); rb.ID == "" {
		t.Fatalf("post-window call should fire")
	}
	if prop.Calls() != 2 {
		t.Fatalf("proposer calls=%d, want 2", prop.Calls())
	}
}

func TestHandle_ThrottleScopedPerAlertKey(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "x", Risk: RiskL1,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "x.service", "action": "restart"}}},
	}}
	m, _, _ := newTestManager(t, prop)

	a1 := sampleAlert()
	a2 := sampleAlert()
	a2.Target = "/var" // different mountpoint => different key
	a3 := sampleAlert()
	a3.Rule = "unit_failed"
	a3.Target = "postgres.service"

	if rb := m.Handle(context.Background(), a1); rb.ID == "" {
		t.Fatalf("a1 should fire")
	}
	if rb := m.Handle(context.Background(), a2); rb.ID == "" {
		t.Fatalf("a2 different target should fire")
	}
	if rb := m.Handle(context.Background(), a3); rb.ID == "" {
		t.Fatalf("a3 different rule should fire")
	}
	if prop.Calls() != 3 {
		t.Fatalf("proposer calls=%d, want 3", prop.Calls())
	}
}

func TestHandle_ProposerErrorStillConsumesThrottleSlot(t *testing.T) {
	// Flapping-alert defence: if the proposer fails, we must NOT immediately
	// retry on the next alert burst (which would tight-loop). The throttle
	// slot is consumed on attempt, not on success.
	prop := &stubProposer{err: errors.New("api down")}
	m, _, _ := newTestManager(t, prop)

	for range 5 {
		_ = m.Handle(context.Background(), sampleAlert())
	}
	if prop.Calls() != 1 {
		t.Fatalf("proposer calls=%d, want 1 (throttle holds on failure)", prop.Calls())
	}
}

func TestHandle_InvalidStepSkippedNotFanout(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "kill bad process, restart good service",
		Risk:    RiskL1,
		Steps: []Step{
			{Kind: aiproposal.KindProcessKill, Params: map[string]any{"pid": 0}}, // invalid
			{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "good.service", "action": "restart"}},
		},
	}}
	m, apm, _ := newTestManager(t, prop)

	rb := m.Handle(context.Background(), sampleAlert())
	if len(rb.ProposalIDs) != 2 {
		t.Fatalf("ProposalIDs len=%d, want 2 (slot reserved per step)", len(rb.ProposalIDs))
	}
	if rb.ProposalIDs[0] != "" {
		t.Fatalf("invalid step should have empty proposal ID, got %q", rb.ProposalIDs[0])
	}
	if rb.ProposalIDs[1] == "" {
		t.Fatalf("valid step should have a proposal ID")
	}
	if rb.Steps[0].Command != "" {
		t.Fatalf("invalid step should have no derived command, got %q", rb.Steps[0].Command)
	}
	if len(apm.List()) != 1 {
		t.Fatalf("aiproposals=%d, want 1 (only valid step fanned out)", len(apm.List()))
	}
}

func TestHandle_PublishesRunbookNotificationWithDeepLink(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "restart it", Risk: RiskL2,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "api.service", "action": "restart"}}},
	}}
	m, _, hub := newTestManager(t, prop)

	gotCh := make(chan notifications.Notification, 1)
	unsub := hub.Subscribe(func(n notifications.Notification) {
		if n.Type == "infra.runbook" {
			select {
			case gotCh <- n:
			default:
			}
		}
	})
	defer unsub()

	rb := m.Handle(context.Background(), sampleAlert())
	select {
	case got := <-gotCh:
		if got.Severity != "critical" {
			t.Fatalf("L2 should map to critical severity, got %q", got.Severity)
		}
		if got.Data["runbook_id"].(string) != rb.ID {
			t.Fatalf("notification missing runbook_id")
		}
		if got.Data["deep_link"].(string) != "runbook/"+rb.ID {
			t.Fatalf("deep_link wrong: %v", got.Data["deep_link"])
		}
		ids, _ := got.Data["proposal_ids"].([]string)
		if len(ids) != 1 || ids[0] != rb.ProposalIDs[0] {
			t.Fatalf("proposal_ids missing from notification: %+v", got.Data["proposal_ids"])
		}
		if got.Data["blocked"].(bool) {
			t.Fatalf("non-blocked runbook must publish blocked=false")
		}
	case <-time.After(time.Second):
		t.Fatal("no runbook notification within deadline")
	}
}

// TestHandle_BlockedL3PublishesCriticalGuidanceNotification covers the
// blocked-runbook push: it is still critical and still deep-links to the
// runbook (so the operator can see the guidance), but carries zero
// proposal IDs and the fixed blocked-reason guidance.
func TestHandle_BlockedL3PublishesCriticalGuidanceNotification(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "reformat and reprovision disk",
		Risk:    RiskL1,
		Steps: []Step{{
			Kind:   aiproposal.KindSecurityFix,
			Params: map[string]any{"kind": "run_script", "script": "mkfs.ext4 /dev/sdb1"},
		}},
	}}
	m, _, hub := newTestManager(t, prop)

	gotCh := make(chan notifications.Notification, 1)
	unsub := hub.Subscribe(func(n notifications.Notification) {
		if n.Type == "infra.runbook" {
			select {
			case gotCh <- n:
			default:
			}
		}
	})
	defer unsub()

	rb := m.Handle(context.Background(), sampleAlert())
	if !rb.Blocked {
		t.Fatal("expected blocked runbook")
	}
	select {
	case got := <-gotCh:
		if got.Severity != "critical" {
			t.Fatalf("blocked L3 should publish critical severity, got %q", got.Severity)
		}
		if got.Data["blocked"].(bool) != true {
			t.Fatalf("notification must carry blocked=true")
		}
		if got.Data["blocked_reason"].(string) != BlockedL3Reason {
			t.Fatalf("notification blocked_reason = %q", got.Data["blocked_reason"])
		}
		ids, _ := got.Data["proposal_ids"].([]string)
		if len(ids) != 0 {
			t.Fatalf("blocked runbook notification must carry zero proposal ids, got %+v", ids)
		}
	case <-time.After(time.Second):
		t.Fatal("no runbook notification within deadline")
	}
}

func TestHandle_GroundingPassedToProposer(t *testing.T) {
	prop := &stubProposer{result: Proposal{Summary: "ok"}}
	apm := aiproposal.New()
	m, err := New(Config{
		AIProposals: apm,
		Proposer:    prop,
		Snapshotter: SnapshotFunc(func(_ context.Context) Grounding {
			return Grounding{Metrics: "M", Services: "S", Processes: "P", Firewall: "F"}
		}),
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
		Throttle: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	m.Handle(context.Background(), sampleAlert())
	if prop.gotGround.Metrics != "M" || prop.gotGround.Services != "S" ||
		prop.gotGround.Processes != "P" || prop.gotGround.Firewall != "F" {
		t.Fatalf("grounding not threaded: %+v", prop.gotGround)
	}
}

func TestStart_FiredAlertProducesProposalQuickly(t *testing.T) {
	// AC: "fired alert produces a proposal within N seconds". We assert
	// well under one second to keep CI fast while still proving the
	// alert -> hub -> manager -> aiproposal chain is wired async.
	prop := &stubProposer{result: Proposal{
		Summary: "x", Risk: RiskL1,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "x.service", "action": "restart"}}},
	}}
	m, apm, hub := newTestManager(t, prop)

	cleanup := m.Start(context.Background())
	defer cleanup()

	_ = hub.Publish(context.Background(), notifications.Notification{
		Type:      "infra.alert",
		Title:     "Infrastructure alert",
		Body:      "Disk / usage 91.0%",
		Severity:  "warning",
		CreatedAt: time.Unix(1700000000, 0),
		Data: map[string]any{
			"server_id": "local",
			"rule":      "disk_usage",
			"target":    "/",
		},
	})

	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("aiproposal not created within deadline; calls=%d, list=%d", prop.Calls(), len(apm.List()))
		default:
		}
		if len(apm.List()) == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStart_AlertClearedDoesNotTrigger(t *testing.T) {
	prop := &stubProposer{result: Proposal{Summary: "x"}}
	m, _, hub := newTestManager(t, prop)
	cleanup := m.Start(context.Background())
	defer cleanup()

	_ = hub.Publish(context.Background(), notifications.Notification{
		Type:      "infra.alert",
		CreatedAt: time.Unix(1700000000, 0),
		Data: map[string]any{
			"server_id": "local", "rule": "disk_usage", "target": "/", "clear": true,
		},
	})
	time.Sleep(50 * time.Millisecond)
	if prop.Calls() != 0 {
		t.Fatalf("cleared alert should not trigger proposer, calls=%d", prop.Calls())
	}
}

func TestSessionHook_AttributesRunbookAndRecordsTrace(t *testing.T) {
	prop := &stubProposer{result: Proposal{
		Summary: "do thing", Risk: RiskL1,
		Steps: []Step{{Kind: aiproposal.KindServiceAction, Params: map[string]any{"name": "x.service", "action": "restart"}}},
	}}
	apm := aiproposal.New()
	var recordedPrompt, recordedResp string
	m, err := New(Config{
		AIProposals: apm,
		Proposer:    prop,
		Session: func(_ context.Context, _ Alert) (string, func(string, string)) {
			return "sess-1", func(p, r string) { recordedPrompt, recordedResp = p, r }
		},
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
		Throttle: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	rb := m.Handle(context.Background(), sampleAlert())
	if rb.SessionID != "sess-1" {
		t.Fatalf("runbook session_id=%q", rb.SessionID)
	}
	if recordedPrompt == "" || recordedResp != "do thing" {
		t.Fatalf("session hook not invoked with prompt/response: %q / %q", recordedPrompt, recordedResp)
	}
	// aiproposal should inherit the session id so audit attribution links.
	ap, _ := apm.Get(rb.ProposalIDs[0])
	if ap.SessionID != "sess-1" {
		t.Fatalf("aiproposal session_id=%q want sess-1", ap.SessionID)
	}
}
