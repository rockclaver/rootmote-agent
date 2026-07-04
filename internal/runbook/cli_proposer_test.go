package runbook

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
)

func TestCLIProposer_ParsesClaudeEnvelope(t *testing.T) {
	// Real claude -p --output-format json wraps the assistant message in a
	// {"result": "<assistant text>", ...} envelope. Verify we unwrap it.
	body := `{"summary":"restart x","risk":"low","steps":[{"kind":"infra.service.action","params":{"name":"x.service","action":"restart"},"description":"d"}]}`
	envelope := `{"type":"result","result":"` + escapeJSON(body) + `"}`
	p := CLIProposer{
		Agent: "claude",
		Exec: func(_ context.Context, _ string, _ []string, _ []string, _ string) ([]byte, error) {
			return []byte(envelope), nil
		},
	}
	got, err := p.Propose(context.Background(), sampleAlert(), Grounding{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary != "restart x" || got.Risk != RiskLow || len(got.Steps) != 1 {
		t.Fatalf("bad parse: %+v", got)
	}
	if got.Steps[0].Kind != aiproposal.KindServiceAction {
		t.Fatalf("step kind=%q", got.Steps[0].Kind)
	}
}

func TestCLIProposer_ParsesDirectJSON(t *testing.T) {
	// codex exec returns raw assistant text, no envelope.
	body := `{"summary":"manual review","risk":"medium","steps":[]}`
	p := CLIProposer{
		Agent: "codex",
		Exec: func(_ context.Context, _ string, _ []string, _ []string, _ string) ([]byte, error) {
			return []byte(body), nil
		},
	}
	got, err := p.Propose(context.Background(), sampleAlert(), Grounding{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary != "manual review" || len(got.Steps) != 0 {
		t.Fatalf("bad parse: %+v", got)
	}
}

func TestCLICommand_CodexSkipsGitRepoCheck(t *testing.T) {
	name, args := cliCommand("codex")
	if name != "codex" {
		t.Fatalf("name=%q", name)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--skip-git-repo-check") {
		t.Fatalf("codex args missing git check skip: %#v", args)
	}
	if !strings.Contains(joined, "--ephemeral") {
		t.Fatalf("codex args missing ephemeral mode: %#v", args)
	}
}

func TestCLIProposer_DefaultExecResolvesFromBinDirPATH(t *testing.T) {
	binDir := t.TempDir()
	stub := filepath.Join(binDir, "codex")
	script := `#!/bin/sh
cat >/dev/null
printf '{"summary":"from managed bin","risk":"low","steps":[]}'
`
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	p := CLIProposer{
		Agent:  "codex",
		BinDir: binDir,
	}
	got, err := p.Propose(context.Background(), sampleAlert(), Grounding{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary != "from managed bin" {
		t.Fatalf("bad parse: %+v", got)
	}
}

func TestCLIProposer_ParsesJSONInsideCodeFence(t *testing.T) {
	body := "Here is the plan:\n```json\n{\"summary\":\"x\",\"risk\":\"low\",\"steps\":[]}\n```\nthat is all"
	p := CLIProposer{
		Agent: "codex",
		Exec: func(_ context.Context, _ string, _ []string, _ []string, _ string) ([]byte, error) {
			return []byte(body), nil
		},
	}
	got, err := p.Propose(context.Background(), sampleAlert(), Grounding{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary != "x" {
		t.Fatalf("bad parse: %+v", got)
	}
}

func TestCLIProposer_ParsesCodexJSONLStream(t *testing.T) {
	body := `{"summary":"deny exposed redis","risk":"high","steps":[{"kind":"infra.firewall.rule_add","params":{"action":"deny","protocol":"tcp","port":6379},"description":"block public redis"}]}`
	stdout := strings.Join([]string{
		`{"type":"session.started","session_id":"s1"}`,
		`{"msg":{"type":"agent_message","message":"` + escapeJSON(body) + `"}}`,
		`{"type":"session.completed","status":"ok"}`,
	}, "\n")
	p := CLIProposer{
		Agent: "codex",
		Exec: func(_ context.Context, _ string, _ []string, _ []string, _ string) ([]byte, error) {
			return []byte(stdout), nil
		},
	}
	got, err := p.Propose(context.Background(), sampleAlert(), Grounding{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary != "deny exposed redis" || got.Risk != RiskHigh || len(got.Steps) != 1 {
		t.Fatalf("bad parse: %+v", got)
	}
	if got.Steps[0].Kind != aiproposal.KindFirewallAdd {
		t.Fatalf("step kind=%q", got.Steps[0].Kind)
	}
}

func TestCLIProposer_ExecFailureReturnsError(t *testing.T) {
	p := CLIProposer{
		Exec: func(_ context.Context, _ string, _ []string, _ []string, _ string) ([]byte, error) {
			return []byte("auth failed"), errors.New("exit 1")
		},
	}
	if _, err := p.Propose(context.Background(), sampleAlert(), Grounding{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCLIProposer_UnparseableOutputReturnsError(t *testing.T) {
	p := CLIProposer{
		Exec: func(_ context.Context, _ string, _ []string, _ []string, _ string) ([]byte, error) {
			return []byte("I cannot help with that."), nil
		},
	}
	if _, err := p.Propose(context.Background(), sampleAlert(), Grounding{}); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCLIProposer_TimeoutEnforced(t *testing.T) {
	p := CLIProposer{
		Timeout: 5 * time.Millisecond,
		Exec: func(ctx context.Context, _ string, _ []string, _ []string, _ string) ([]byte, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
				return []byte("{}"), nil
			}
		},
	}
	start := time.Now()
	if _, err := p.Propose(context.Background(), sampleAlert(), Grounding{}); err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("timeout not respected: took %v", time.Since(start))
	}
}

func TestCLIProposer_PromptContainsAlertAndGrounding(t *testing.T) {
	var capturedPrompt string
	p := CLIProposer{
		Exec: func(_ context.Context, _ string, _ []string, _ []string, stdin string) ([]byte, error) {
			capturedPrompt = stdin
			return []byte(`{"summary":"ok","risk":"low","steps":[]}`), nil
		},
	}
	if _, err := p.Propose(context.Background(), sampleAlert(), Grounding{Metrics: "MX"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(capturedPrompt, "disk_usage") {
		t.Fatal("prompt missing alert rule")
	}
	if !strings.Contains(capturedPrompt, "MX") {
		t.Fatal("prompt missing grounding metrics")
	}
	if !strings.Contains(capturedPrompt, "infra.service.action") {
		t.Fatal("prompt missing kind whitelist")
	}
	if !strings.Contains(capturedPrompt, "security.fix") {
		t.Fatal("prompt missing security fix whitelist")
	}
}

// escapeJSON is a tiny helper to embed a JSON string inside another JSON
// string literal in tests.
func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
