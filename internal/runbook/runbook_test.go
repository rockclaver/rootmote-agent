package runbook

import (
	"reflect"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/steps"
)

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
		ProviderVersion: "v1",
		Title:           "Restart the API",
		Source:          SourceCatalog,
		Summary:         "restart api and rotate logs",
		RiskExplanation: "reversible service restart with a brief interruption",
		Risk:            RiskL1,
		RunAs:           "root",
		Steps: []Step{
			{
				Kind:        steps.ServiceRestartID,
				Params:      Params{"unit": "api.service"},
				Description: "restart api",
				Command:     "systemctl restart api.service",
				Verify:      "The service is active.",
				Undoable:    false,
			},
		},
		ManualSteps:      []ManualStep{{Text: "Check the last deploy", Command: "git log -1"}},
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
		c.Steps[i].Params = make(Params, len(s.Params))
		for k, v := range s.Params {
			c.Steps[i].Params[k] = v
		}
	}
	c.ManualSteps = append([]ManualStep(nil), rb.ManualSteps...)
	c.AffectedFiles = append([]string(nil), rb.AffectedFiles...)
	c.AffectedServices = append([]string(nil), rb.AffectedServices...)
	c.Rollback = append([]Command(nil), rb.Rollback...)
	c.Verification = append([]VerificationCheck(nil), rb.Verification...)
	c.ExternalMonitorIDs = append([]string(nil), rb.ExternalMonitorIDs...)
	return c
}

func hashOf(t *testing.T, rb Runbook) string {
	t.Helper()
	h, err := ContentHash(rb)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestContentHashChangesForEveryApprovalField(t *testing.T) {
	base := completeRunbookFixture()
	mutations := []func(*Runbook){
		func(r *Runbook) { r.Steps[0].Command = "systemctl stop api" },
		func(r *Runbook) { r.RunAs = "deploy" },
		func(r *Runbook) { r.AffectedFiles = append(r.AffectedFiles, "/etc/api.conf") },
		func(r *Runbook) { r.Rollback[0].Command = "systemctl restart api" },
		func(r *Runbook) { r.Verification[0].Target = "api.socket" },
		func(r *Runbook) { r.SchemaVersion++ },
		func(r *Runbook) { r.IncidentID = "inc-2" },
		func(r *Runbook) { r.ServerID = "srv-2" },
		func(r *Runbook) { r.DiagnosisID = "diag-2" },
		func(r *Runbook) { r.Risk = RiskL2 },
		func(r *Runbook) { r.Interruption = "extended outage" },
		func(r *Runbook) { r.AffectedServices = append(r.AffectedServices, "extra.service") },
		func(r *Runbook) { r.ExternalMonitorIDs = append(r.ExternalMonitorIDs, "mon-3") },
		func(r *Runbook) { r.Steps[0].Params["unit"] = "other.service" },
		func(r *Runbook) { r.Steps[0].Kind = steps.ServiceStopID },
		func(r *Runbook) { r.Steps[0].Undoable = true },
		func(r *Runbook) { r.Title = "Another title" },
		func(r *Runbook) { r.Source = SourceGenerated },
		func(r *Runbook) { r.ReviewCarefully = true },
		func(r *Runbook) { r.ManualSteps[0].Text = "Delete the database" },
		func(r *Runbook) { r.ManualSteps = nil },
	}
	for i, mutate := range mutations {
		c := cloneRunbook(base)
		mutate(&c)
		if hashOf(t, c) == base.ContentHash {
			t.Fatalf("mutation #%d did not change the content hash", i)
		}
	}
}

// Lifecycle fields and step prose are not approved content: changing them
// must never invalidate an approved runbook.
func TestContentHash_LifecycleFieldsExcluded(t *testing.T) {
	base := completeRunbookFixture()
	mutations := []func(*Runbook){
		func(r *Runbook) { r.ID = "rb-2" },
		func(r *Runbook) { r.CreatedAt = r.CreatedAt.Add(time.Hour) },
		func(r *Runbook) { r.Summary = "different human summary" },
		func(r *Runbook) { r.RiskExplanation = "different explanation" },
		func(r *Runbook) { r.ProviderVersion = "v2" },
		func(r *Runbook) { r.Steps[0].Verify = "A different check." },
		func(r *Runbook) { r.ContentHash = "stale" },
		func(r *Runbook) { r.Steps[0].Description = "prose changed after review" },
	}
	for i, mutate := range mutations {
		c := cloneRunbook(base)
		mutate(&c)
		if hashOf(t, c) != base.ContentHash {
			t.Fatalf("lifecycle mutation #%d changed the content hash", i)
		}
	}
}

func TestContentHash_AffectedSetsOrderIndependent(t *testing.T) {
	base := completeRunbookFixture()
	reordered := cloneRunbook(base)
	reordered.AffectedFiles = []string{"/var/log/api.log", "/etc/api.conf"}
	reordered.AffectedServices = []string{"log-rotate.service", "api.service"}
	if hashOf(t, base) != hashOf(t, reordered) {
		t.Fatal("reordering affected files/services changed the hash")
	}
}

func TestContentHash_OrderedListsAreOrderSensitive(t *testing.T) {
	base := completeRunbookFixture()
	base.Steps = append(base.Steps, Step{Kind: steps.ServiceRestartID, Params: Params{"unit": "log-rotate.service"}, Command: "systemctl restart log-rotate.service"})
	base.Rollback = append(base.Rollback, Command{Command: "systemctl stop log-rotate.service", RunAs: "root"})
	base.Verification = append(base.Verification, VerificationCheck{ID: "chk-2", Kind: "service_active", Target: "log-rotate.service"})
	base.ExternalMonitorIDs = append(base.ExternalMonitorIDs, "mon-3")
	want := hashOf(t, base)
	for name, swap := range map[string]func(*Runbook){
		"steps":        func(r *Runbook) { r.Steps[0], r.Steps[1] = r.Steps[1], r.Steps[0] },
		"rollback":     func(r *Runbook) { r.Rollback[0], r.Rollback[1] = r.Rollback[1], r.Rollback[0] },
		"verification": func(r *Runbook) { r.Verification[0], r.Verification[1] = r.Verification[1], r.Verification[0] },
		"monitors": func(r *Runbook) {
			r.ExternalMonitorIDs[0], r.ExternalMonitorIDs[1] = r.ExternalMonitorIDs[1], r.ExternalMonitorIDs[0]
		},
	} {
		c := cloneRunbook(base)
		swap(&c)
		if hashOf(t, c) == want {
			t.Errorf("reordering %s did not change the hash", name)
		}
	}
}

func TestContentHash_DeterministicAndDoesNotMutateInput(t *testing.T) {
	base := completeRunbookFixture()
	files := append([]string(nil), base.AffectedFiles...)
	if hashOf(t, base) != hashOf(t, base) {
		t.Fatal("ContentHash is not deterministic")
	}
	if !reflect.DeepEqual(base.AffectedFiles, files) {
		t.Fatal("ContentHash mutated AffectedFiles order")
	}
}

func TestContentHash_NonMarshalableParamsFailClosed(t *testing.T) {
	rb := completeRunbookFixture()
	rb.Steps[0].Params["bad"] = func() {}
	if _, err := ContentHash(rb); err == nil {
		t.Fatal("non-marshalable params must be rejected, not hashed")
	}
}
