package playbook

import (
	"fmt"
	"strings"

	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/steps"
)

// Describe is the plain-English line the app shows for one step.
func Describe(id steps.ID, p steps.Params) string {
	switch id {
	case steps.ServiceRestartID:
		return "Restart " + p.String("unit")
	case steps.ServiceStartID:
		return "Start " + p.String("unit")
	case steps.ServiceStopID:
		return "Stop " + p.String("unit")
	case steps.ServiceReloadID:
		return "Reload the settings of " + p.String("unit")
	case steps.ContainerRestartID:
		return "Restart the container " + p.String("container")
	case steps.ComposeUpID:
		return fmt.Sprintf("Start %s in the Compose project %s", p.String("service"), p.String("project"))
	case steps.PM2RestartID:
		return fmt.Sprintf("Restart the PM2 app %s (user %s)", p.String("app"), p.String("user"))
	case steps.NginxReloadID:
		return "Test the nginx settings, then reload nginx"
	case steps.PHPFPMRestartID:
		return "Restart PHP-FPM (" + p.String("unit") + ")"
	case steps.SupervisorRestartID:
		return "Restart the Supervisor program " + p.String("program")
	case steps.JournalVacuumID:
		return "Shrink the system logs to " + p.String("size")
	case steps.DockerPruneID:
		return "Remove unused Docker images and build cache"
	case steps.AptCleanID:
		return "Clear the downloaded package files"
	case steps.CertRenewID:
		return "Renew the certificate " + p.String("name")
	case steps.ProcessStopID:
		return "Stop the process"
	case steps.FirewallAllowID:
		port, _ := p.Int("port")
		return fmt.Sprintf("Open port %d/%s in the firewall", port, p.String("proto"))
	case steps.FirewallRemoveID:
		port, _ := p.Int("port")
		return fmt.Sprintf("Close port %d/%s in the firewall", port, p.String("proto"))
	case steps.CheckHTTPID:
		return "Check that " + p.String("url") + " answers"
	}
	if s, ok := steps.Lookup(id); ok {
		return s.Def().Title
	}
	return string(id)
}

// risk rates a playbook: L0 when nothing changes, L2 when it touches the
// firewall or stops a process, L1 otherwise.
func risk(list []Step) runbook.Risk {
	r := runbook.RiskL0
	for _, s := range list {
		switch s.Step {
		case steps.CheckHTTPID:
		case steps.FirewallAllowID, steps.FirewallRemoveID, steps.ProcessStopID:
			return runbook.RiskL2
		default:
			r = runbook.RiskL1
		}
	}
	return r
}

// affected names the services a playbook restarts or changes.
func affected(list []Step) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range list {
		switch s.Step {
		case steps.ServiceRestartID, steps.ServiceStartID, steps.ServiceStopID, steps.ServiceReloadID, steps.PHPFPMRestartID:
			add(s.Params.String("unit"))
		case steps.ContainerRestartID:
			add(s.Params.String("container"))
		case steps.ComposeUpID:
			add(s.Params.String("project") + "/" + s.Params.String("service"))
		case steps.PM2RestartID:
			add(s.Params.String("app"))
		case steps.SupervisorRestartID:
			add(s.Params.String("program"))
		case steps.NginxReloadID:
			add("nginx")
		}
	}
	return out
}

// interruption says how long the playbook makes something unavailable.
func interruption(list []Step) string {
	names := []string{}
	for _, s := range list {
		switch s.Step {
		case steps.ServiceRestartID, steps.PHPFPMRestartID, steps.ContainerRestartID, steps.PM2RestartID, steps.SupervisorRestartID, steps.ComposeUpID:
			names = append(names, affectedName(s))
		case steps.ServiceStopID:
			names = append(names, affectedName(s))
		}
	}
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, ", ") + " will be unavailable for a few seconds."
}

func affectedName(s Step) string {
	for _, k := range []string{"unit", "container", "app", "program", "service"} {
		if v := s.Params.String(k); v != "" {
			return v
		}
	}
	return string(s.Step)
}

// ToRunbook converts a playbook to the runbook the remediation manager
// stores, hashes and asks the user to approve. Descriptions, commands and
// verification text come from the step catalog, never from the playbook's
// author.
func ToRunbook(pb Playbook, id, incidentID, serverID string) runbook.Runbook {
	rb := runbook.Runbook{
		ID:               id,
		SchemaVersion:    runbook.SchemaVersion,
		IncidentID:       incidentID,
		ProviderVersion:  pb.Source,
		ServerID:         serverID,
		Title:            pb.Title,
		Source:           pb.Source,
		ReviewCarefully:  pb.ReviewCarefully,
		Summary:          pb.Summary,
		Risk:             risk(pb.Steps),
		Steps:            []runbook.Step{},
		ManualSteps:      []runbook.ManualStep{},
		AffectedServices: affected(pb.Steps),
		Interruption:     interruption(pb.Steps),
	}
	switch rb.Risk {
	case runbook.RiskL0:
		rb.RiskExplanation = "Nothing on the server changes."
	case runbook.RiskL1:
		rb.RiskExplanation = "Restarts or cleans up. Nothing is deleted except caches and old logs."
	case runbook.RiskL2:
		rb.RiskExplanation = "Changes the firewall or stops a process."
	}
	anyRoot := false
	for _, s := range pb.Steps {
		rs := runbook.Step{
			Kind:        s.Step,
			Params:      s.Params,
			Description: Describe(s.Step, s.Params),
			Command:     steps.Command(s.Step, s.Params),
		}
		if step, ok := steps.Lookup(s.Step); ok {
			def := step.Def()
			rs.Verify = def.Verify
			rs.Undoable = def.Undo != ""
			anyRoot = anyRoot || def.Root
		}
		rb.Steps = append(rb.Steps, rs)
		if undoID, undoParams, ok := steps.UndoOf(s.Step, s.Params); ok {
			rb.Rollback = append(rb.Rollback, runbook.Command{
				Command:     steps.Command(undoID, undoParams),
				RunAs:       "root",
				Description: "Undo: " + rs.Description,
			})
		}
	}
	if anyRoot {
		rb.RunAs = "root"
	}
	for _, m := range pb.Manual {
		rb.ManualSteps = append(rb.ManualSteps, runbook.ManualStep{Text: m.Text, Command: m.Command})
	}
	return rb
}
