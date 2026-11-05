package remediation

import (
	"testing"

	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/steps"
)

func TestInvertSteps_UsesCatalogUndo(t *testing.T) {
	list := []runbook.Step{
		{Kind: steps.ServiceStopID, Params: runbook.Params{"unit": "api.service"}, Description: "stop api"},
		{Kind: steps.FirewallAllowID, Params: runbook.Params{"port": float64(8080), "proto": "tcp"}, Description: "open 8080"},
	}
	got, skipped := invertSteps(list)
	if len(skipped) != 0 {
		t.Fatalf("skipped = %+v, want none", skipped)
	}
	if len(got) != 2 || got[0].Kind != steps.FirewallRemoveID || got[1].Kind != steps.ServiceStartID {
		t.Fatalf("inverted = %+v, want firewall.remove then service.start", got)
	}
	if got[1].Command != "systemctl start api.service" {
		t.Fatalf("command = %q", got[1].Command)
	}
	if got[1].Verify == "" || !got[1].Undoable {
		t.Fatalf("inverted step lost its verify text or undoable flag: %+v", got[1])
	}
}

func TestInvertSteps_ListsStepsWithoutUndoSeparately(t *testing.T) {
	list := []runbook.Step{
		{Kind: steps.ServiceRestartID, Params: runbook.Params{"unit": "api.service"}, Description: "restart api"},
		{Kind: steps.ServiceStopID, Params: runbook.Params{"unit": "worker.service"}, Description: "stop worker"},
		{Kind: steps.CertRenewID, Params: runbook.Params{"name": "shop"}, Description: "renew shop"},
	}
	inverted, irreversible := invertSteps(list)
	if len(inverted) != 1 || inverted[0].Kind != steps.ServiceStartID {
		t.Fatalf("inverted = %+v, want only service.start", inverted)
	}
	if len(irreversible) != 2 || irreversible[0].Kind != steps.ServiceRestartID || irreversible[1].Kind != steps.CertRenewID {
		t.Fatalf("irreversible = %+v, want restart then renew in original order", irreversible)
	}
}

func TestRollbackForcesL3_ClosingSSHPort(t *testing.T) {
	closeSSH := []runbook.Step{{Kind: steps.FirewallRemoveID, Params: runbook.Params{"port": float64(22), "proto": "tcp"}}}
	if !rollbackForcesL3(closeSSH) {
		t.Fatal("removing the port 22 rule must be blocked")
	}
	closeOther := []runbook.Step{{Kind: steps.FirewallRemoveID, Params: runbook.Params{"port": float64(8080), "proto": "tcp"}}}
	if rollbackForcesL3(closeOther) {
		t.Fatal("removing another rule must not be blocked")
	}
}
