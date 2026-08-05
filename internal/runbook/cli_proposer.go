package runbook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CLIProposer invokes the host-installed claude/codex CLI in non-interactive
// mode and parses the model's structured response into a Proposal. We deliberately
// reuse the same binary + credentials a human session would use so:
//   - no second auth surface (the CLI is already logged in via cliauth)
//   - no new API keys or HTTP-client dependency in the agent
//   - swapping models is a wiring change, not a code change
//
// Production wiring passes Agent="claude" or "codex"; tests inject Exec so the
// actual binary is never spawned.
type CLIProposer struct {
	// Agent picks the CLI: "claude" or "codex". Defaults to "claude".
	Agent string
	// BinDir is prepended to PATH so the tooling-managed CLI resolves
	// even on hosts where the system PATH does not include it. Matches
	// the same plumbing TmuxRuntime uses.
	BinDir string
	// HomeDir is the HOME the CLI sees; CLAUDE_CONFIG_DIR is derived
	// from it for the claude CLI.
	HomeDir string
	// Secrets returns env-var assignments (oauth tokens, api keys) to
	// inject into the CLI invocation. Mirrors cliauth.Manager.Secrets.
	Secrets func(agent string) map[string]string
	// Timeout bounds one Propose() call. Defaults to 60s. The throttle
	// in Manager guarantees no overlap, but a wedged claude must not
	// pin the proposer goroutine forever.
	Timeout time.Duration
	// Exec, when non-nil, replaces real CLI execution. Tests inject a
	// closure that returns canned JSON. The signature mirrors
	// (*exec.Cmd).CombinedOutput so the production path stays trivial.
	Exec func(ctx context.Context, name string, args []string, env []string, stdin string) ([]byte, error)
}

// Propose runs the CLI and parses its JSON output.
//
// On parse failure we return (zero, error) rather than degrading to a
// "no fix" Proposal — Manager treats an error as throttle-consuming so a
// genuinely broken proposer cannot tight-loop, while a successfully
// returned empty-Steps Proposal is the explicit "no fix recommended"
// signal a sane proposer emits.
func (p CLIProposer) Propose(ctx context.Context, alert Alert, g Grounding) (Proposal, error) {
	prompt, err := buildPrompt(alert, g)
	if err != nil {
		return Proposal{}, fmt.Errorf("build prompt: %w", err)
	}
	agent := p.Agent
	if agent == "" {
		agent = "claude"
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	name, args := cliCommand(agent)
	env := p.buildEnv(agent)

	exec := p.Exec
	if exec == nil {
		exec = defaultExec
	}
	out, err := exec(cctx, name, args, env, prompt)
	if err != nil {
		return Proposal{}, fmt.Errorf("%s exec: %w (stdout=%q)", agent, err, truncate(string(out), 256))
	}
	prop, err := parseProposal(out, agent)
	if err != nil {
		return Proposal{}, fmt.Errorf("parse %s output: %w", agent, err)
	}
	return prop, nil
}

// cliCommand returns the binary name + flags that put the CLI in
// non-interactive, JSON-emitting mode for one prompt.
//
// Both CLIs accept the prompt on stdin in their non-interactive modes, which
// keeps long alert grounding well clear of any shell-quoting hazard.
func cliCommand(agent string) (string, []string) {
	switch agent {
	case "codex":
		// `codex exec -` reads the prompt from stdin and prints the
		// final assistant message on stdout. Runbook generation is not
		// tied to a repository checkout, so explicitly allow the agent's
		// data directory/non-repo cwd and avoid persisting a duplicate
		// Codex session transcript for this one-shot draft.
		return "codex", []string{"exec", "--skip-git-repo-check", "--ephemeral", "-"}
	default:
		// `claude -p` is the non-interactive "print" mode;
		// --output-format json emits a single JSON envelope on stdout.
		return "claude", []string{"-p", "--output-format", "json"}
	}
}

// parseProposal extracts the structured runbook from the CLI's stdout. We
// accept three shapes, in order of preference, because the two CLIs and
// future versions vary in how they wrap content:
//
//  1. A top-level JSON object that already matches Proposal.
//  2. A claude-style envelope {"result": "<assistant text>", ...} where the
//     assistant text contains a JSON Proposal.
//  3. Raw assistant text with a JSON Proposal embedded somewhere.
//
// The model is instructed (see buildPrompt) to emit JSON only, but real
// transcripts often include a leading ```json fence; extractJSONObject
// handles that.
func parseProposal(stdout []byte, agent string) (Proposal, error) {
	stdout = bytes.TrimSpace(stdout)
	if len(stdout) == 0 {
		return Proposal{}, errors.New("empty stdout")
	}
	// Shape 1: direct Proposal JSON.
	if p, ok := tryParse(stdout); ok {
		return p, nil
	}
	// Shape 2: claude envelope.
	if agent == "claude" {
		var env struct {
			Result string `json:"result"`
		}
		if err := json.Unmarshal(stdout, &env); err == nil && env.Result != "" {
			if body := extractJSONObject([]byte(env.Result)); body != nil {
				if p, ok := tryParse(body); ok {
					return p, nil
				}
			}
		}
	}
	// Shape 3: JSONL/event streams whose final assistant text contains
	// the proposal. Some codex versions emit progress events rather than
	// only the final assistant message.
	if p, ok := parseProposalStream(stdout); ok {
		return p, nil
	}
	// Shape 4: raw text with embedded JSON.
	if body := extractJSONObject(stdout); body != nil {
		if p, ok := tryParse(body); ok {
			return p, nil
		}
	}
	return Proposal{}, fmt.Errorf("no parseable proposal in %d bytes of output", len(stdout))
}

func parseProposalStream(stdout []byte) (Proposal, bool) {
	var fragments []string
	for _, line := range bytes.Split(stdout, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if p, ok := tryParse(line); ok {
			return p, true
		}
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			continue
		}
		lineFragments := textFragments(v)
		for _, fragment := range lineFragments {
			if p, ok := parseProposalText(fragment); ok {
				return p, true
			}
		}
		fragments = append(fragments, lineFragments...)
	}
	if len(fragments) == 0 {
		return Proposal{}, false
	}
	if p, ok := parseProposalText(strings.Join(fragments, "")); ok {
		return p, true
	}
	if p, ok := parseProposalText(strings.Join(fragments, "\n")); ok {
		return p, true
	}
	return Proposal{}, false
}

func parseProposalText(s string) (Proposal, bool) {
	if body := extractJSONObject([]byte(s)); body != nil {
		return tryParse(body)
	}
	return Proposal{}, false
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

func tryParse(b []byte) (Proposal, bool) {
	var p Proposal
	if err := json.Unmarshal(b, &p); err != nil {
		return Proposal{}, false
	}
	// Reject an object that doesn't look like a Proposal at all
	// (every field zero-valued and no steps): the upstream parser
	// would then mistake e.g. {"foo":1} for a "no fix recommended"
	// runbook.
	if p.Summary == "" && len(p.Steps) == 0 && p.Risk == "" {
		return Proposal{}, false
	}
	// Strict new contract: a proposal with steps to execute must carry
	// a valid L0-L3 risk. There are no low/medium/high aliases and no
	// silent coercion — an invalid or missing risk on a non-empty-steps
	// proposal is malformed output, not a "no fix recommended" runbook.
	if len(p.Steps) > 0 && !p.Risk.valid() {
		return Proposal{}, false
	}
	return p, true
}

// extractJSONObject scans s for the first top-level {...} block and returns
// its bytes, or nil. Handles a leading ```json fence and trailing prose.
func extractJSONObject(s []byte) []byte {
	// Strip a leading code fence if present.
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

func (p CLIProposer) buildEnv(agent string) []string {
	env := []string{}
	if p.HomeDir != "" {
		env = append(env, "HOME="+p.HomeDir)
		env = append(env, "CLAUDE_CONFIG_DIR="+p.HomeDir+"/.claude")
	}
	if p.BinDir != "" {
		env = append(env, "PATH="+p.BinDir+":/usr/local/bin:/usr/bin:/bin")
	}
	if p.Secrets != nil {
		for k, v := range p.Secrets(agent) {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func defaultExec(ctx context.Context, name string, args []string, env []string, stdin string) ([]byte, error) {
	if resolved := lookPathWithEnv(name, env); resolved != "" {
		name = resolved
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.CombinedOutput()
}

func lookPathWithEnv(name string, env []string) string {
	if strings.ContainsRune(name, os.PathSeparator) {
		return name
	}
	path := ""
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], "PATH=") {
			path = strings.TrimPrefix(env[i], "PATH=")
			break
		}
	}
	if path == "" {
		if resolved, err := exec.LookPath(name); err == nil {
			return resolved
		}
		return ""
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, name)
		if isExecutable(candidate) {
			return candidate
		}
	}
	return ""
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

// buildPrompt is intentionally precise: it tells the model exactly which
// JSON shape to return and pins the allowed step Kinds + their params so
// the manager's tokenBindingForKind never rejects a structurally valid
// proposal as "unsupported kind".
func buildPrompt(alert Alert, g Grounding) (string, error) {
	groundingJSON, err := json.Marshal(map[string]any{
		"metrics":   g.Metrics,
		"services":  g.Services,
		"processes": g.Processes,
		"firewall":  g.Firewall,
	})
	if err != nil {
		return "", err
	}
	alertJSON, _ := json.Marshal(alert)
	var b strings.Builder
	b.WriteString("You are an on-call SRE assistant. An infrastructure alert just fired on a server. ")
	b.WriteString("Propose a remediation as a JSON object with exactly these keys:\n")
	b.WriteString("  summary:            one-sentence human description of the proposed fix\n")
	b.WriteString("  risk:               one of \"L0\" | \"L1\" | \"L2\" | \"L3\" (no other value is accepted)\n")
	b.WriteString("    L0 = read-only observation/verification, no mutation\n")
	b.WriteString("    L1 = low-risk, reversible mutation with narrow interruption\n")
	b.WriteString("    L2 = configuration or broader service change\n")
	b.WriteString("    L3 = destructive, irreversible, or high-blast-radius (blocked from auto-execution)\n")
	b.WriteString("  riskExplanation:    one sentence justifying the chosen risk level\n")
	b.WriteString("  runAs:              effective user the steps execute as (e.g. \"root\")\n")
	b.WriteString("  affectedFiles:      array of file paths touched by the fix (may be empty)\n")
	b.WriteString("  affectedServices:   array of service names touched by the fix (may be empty)\n")
	b.WriteString("  interruption:       one sentence describing expected user-visible interruption (may be empty)\n")
	b.WriteString("  rollback:           array of {command, runAs, description} steps that undo the fix (may be empty)\n")
	b.WriteString("  verification:       array of {id, kind, target, description} internal checks to confirm success (may be empty)\n")
	b.WriteString("  externalMonitorIds: array of external monitor IDs this fix should be verified against (may be empty)\n")
	b.WriteString("  steps:              array of step objects, each {kind, params, description}\n")
	b.WriteString("Allowed step kinds and required params:\n")
	b.WriteString("  - infra.service.action      params={name:string, action:\"start\"|\"stop\"|\"restart\"}\n")
	b.WriteString("  - infra.process.kill        params={pid:int, start_time_ticks:int, signal:\"TERM\"|\"KILL\"}\n")
	b.WriteString("  - infra.firewall.rule_add   params={backend:\"ufw\"|\"firewalld\", action:\"allow\"|\"deny\"|\"reject\", protocol,port,source,comment,zone}; backend and action are required; firewalld supports allow only\n")
	b.WriteString("  - infra.firewall.rule_remove params={backend:\"ufw\"|\"firewalld\", action:\"allow\"|\"deny\"|\"reject\", protocol,port,source,zone}; backend and action are required; firewalld supports allow only\n")
	b.WriteString("  - security.fix              params={kind:\"close_port\"|\"kill_process\"|\"enable_auditd\"|\"run_script\", backend:\"ufw\"|\"firewalld\", zone, port:int, protocol:string, pid:int, start_time_ticks:int, signal:string, script:string}; close_port requires backend\n")
	b.WriteString("    run_script is the ONLY way to propose a raw shell command; use it whenever the fix needs something none of the other typed kinds cover ")
	b.WriteString("(e.g. correcting ownership/permissions on a file such as /etc/shadow). script must be a POSIX sh script that does exactly what the finding ")
	b.WriteString("requires and nothing else, is idempotent, and contains no destructive side effects beyond the fix itself; it always runs as root, always ")
	b.WriteString("classifies as L3, and is always blocked from auto-execution — the operator must run it manually in a maintenance session. Prefer a typed ")
	b.WriteString("kind (L0-L2) over run_script whenever one covers the fix.\n")
	b.WriteString("If no safe automated remediation is possible even as a script, return steps=[] with a summary explaining why; ")
	b.WriteString("do NOT invent steps. Output JSON only — no prose, no code fences.\n\n")
	b.WriteString("ALERT:\n")
	b.Write(alertJSON)
	b.WriteString("\n\nGROUNDING (current host snapshot):\n")
	b.Write(groundingJSON)
	b.WriteString("\n")
	return b.String(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
