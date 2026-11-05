package server

import (
	"strings"
	"testing"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
)

// A run_script security fix is advice for the operator; it must never yield a
// token binding or an executable request.
func TestProposalTokenBinding_RunScriptIsRefused(t *testing.T) {
	params := map[string]any{"kind": "run_script", "script": "chmod 640 /etc/shadow"}
	if _, err := securityFixRequestFromParams(params); err == nil || !strings.Contains(err.Error(), "run_script") {
		t.Fatalf("securityFixRequestFromParams err = %v, want run_script refusal", err)
	}
	if _, _, _, err := proposalTokenBinding(aiproposal.KindSecurityFix, params); err == nil {
		t.Fatal("proposalTokenBinding must refuse run_script")
	}
}
