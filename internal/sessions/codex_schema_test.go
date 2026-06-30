package sessions

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// codexSchemaPath is the committed `codex app-server generate-json-schema`
// output, pinned to the supported codex-cli version. codex_translate.go and
// codex_runtime.go are written against this exact protocol surface.
const codexSchemaPath = "fixtures/codex/app_server_schema.json"

// TestCodexSchema_DeclaresTranslatedSurface asserts the committed app-server
// schema still declares every method, decision value, and item type the
// runtime depends on. It runs in CI without codex installed, so a codex bump
// that regenerates the schema and renames/drops part of our surface fails here.
func TestCodexSchema_DeclaresTranslatedSurface(t *testing.T) {
	data, err := os.ReadFile(codexSchemaPath)
	if err != nil {
		t.Fatalf("read committed schema: %v", err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("committed schema is not valid JSON: %v", err)
	}
	s := string(data)
	required := []string{
		// server -> client notifications we translate
		codexMethodTurnStarted, codexMethodTurnCompleted, codexMethodTokenUsage,
		codexMethodPlanUpdated, codexMethodAgentMsgDelta, codexMethodItemStarted, codexMethodItemCompleted,
		// server -> client approval requests we answer
		codexMethodCmdApproval, codexMethodFileApproval, codexMethodExecApproval, codexMethodPatchApproval,
		// client -> server requests we send
		"thread/start", "thread/resume", "thread/fork", "turn/start", "turn/interrupt", "initialize",
		// decision values we send back
		"acceptForSession", "approved_for_session",
		// item types we switch on
		`"agentMessage"`, `"reasoning"`, `"commandExecution"`, `"fileChange"`, `"mcpToolCall"`,
		// approval policy + sandbox values we set on thread/start
		"on-request", "workspace-write", "danger-full-access",
	}
	for _, needle := range required {
		if !strings.Contains(s, needle) {
			t.Errorf("committed codex schema no longer declares %q; the runtime's assumptions have drifted", needle)
		}
	}
}

// TestCodexSchema_NoDrift regenerates the schema with the installed codex and
// byte-compares it to the committed file. It is skipped when codex is absent
// (e.g. CI), where the committed artifact and the surface check above stand in.
func TestCodexSchema_NoDrift(t *testing.T) {
	bin, err := exec.LookPath("codex")
	if err != nil {
		t.Skip("codex not installed; skipping schema regeneration diff")
	}
	dir := t.TempDir()
	if out, err := exec.Command(bin, "app-server", "generate-json-schema", "--out", dir).CombinedOutput(); err != nil {
		t.Skipf("codex schema generation unavailable: %v (%s)", err, out)
	}
	fresh, err := os.ReadFile(filepath.Join(dir, "codex_app_server_protocol.schemas.json"))
	if err != nil {
		t.Fatalf("read regenerated schema: %v", err)
	}
	committed, err := os.ReadFile(codexSchemaPath)
	if err != nil {
		t.Fatalf("read committed schema: %v", err)
	}
	if !bytes.Equal(fresh, committed) {
		t.Fatalf("codex app-server schema drifted from %s.\nRegenerate: codex app-server generate-json-schema --out <tmp> && cp <tmp>/codex_app_server_protocol.schemas.json %s\nThen re-verify the codex translator against the new surface.", codexSchemaPath, codexSchemaPath)
	}
}
