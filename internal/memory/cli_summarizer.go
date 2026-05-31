package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CLISummarizer invokes the host-installed claude/codex CLI in non-interactive
// mode to summarize a finished session and propose memory entries. It reuses
// the same binary + credentials a human session uses (see runbook.CLIProposer
// for the same rationale): no second auth surface, no new API dependency.
//
// Production wiring passes Agent + BinDir + HomeDir + Secrets exactly like the
// runbook proposer; tests inject Exec so no binary is spawned.
type CLISummarizer struct {
	Agent   string
	BinDir  string
	HomeDir string
	Secrets func(agent string) map[string]string
	// Timeout bounds one Summarize call. Defaults to 60s.
	Timeout time.Duration
	// MaxTranscript caps how much of the (potentially huge) transcript is fed
	// to the model. We keep the tail, where the session's conclusions live.
	// Zero uses 32 KiB.
	MaxTranscript int
	// Exec, when non-nil, replaces real CLI execution (mirrors
	// runbook.CLIProposer.Exec).
	Exec func(ctx context.Context, name string, args []string, env []string, stdin string) ([]byte, error)
}

// Summarize runs the CLI and parses its JSON SessionSummary.
func (c CLISummarizer) Summarize(ctx context.Context, projectID, sessionID, transcript string) (SessionSummary, error) {
	agent := c.Agent
	if agent == "" {
		agent = "claude"
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	prompt := buildSummaryPrompt(c.tail(transcript))
	name, args := summaryCommand(agent)
	env := c.buildEnv(agent)

	run := c.Exec
	if run == nil {
		run = defaultExec
	}
	out, err := run(cctx, name, args, env, prompt)
	if err != nil {
		return SessionSummary{}, fmt.Errorf("%s exec: %w (stdout=%q)", agent, err, truncate(string(out), 256))
	}
	s, err := parseSummary(out, agent)
	if err != nil {
		return SessionSummary{}, fmt.Errorf("parse %s output: %w", agent, err)
	}
	return s, nil
}

func (c CLISummarizer) tail(s string) string {
	max := c.MaxTranscript
	if max <= 0 {
		max = 32 * 1024
	}
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}

func summaryCommand(agent string) (string, []string) {
	switch agent {
	case "codex":
		return "codex", []string{"exec", "-"}
	default:
		return "claude", []string{"-p", "--output-format", "json"}
	}
}

func buildSummaryPrompt(transcript string) string {
	var b strings.Builder
	b.WriteString("You are summarizing a finished AI coding session for a project journal. ")
	b.WriteString("Return a single JSON object with exactly these keys:\n")
	b.WriteString("  bullets: array of 1-3 short strings, each one thing that happened this session\n")
	b.WriteString("  proposed_memory: array (possibly empty) of {kind, title, body} entries worth\n")
	b.WriteString("    remembering for future sessions on this repo. kind is one of:\n")
	b.WriteString("    \"convention\" | \"gotcha\" | \"decision\" | \"file_note\".\n")
	b.WriteString("Only propose memory for durable facts (a convention to follow, a gotcha that ")
	b.WriteString("broke something, a decision made, a file-level note). Do not propose transient ")
	b.WriteString("chatter. If nothing is worth remembering, return proposed_memory: [].\n")
	b.WriteString("Output JSON only — no prose, no code fences.\n\n")
	b.WriteString("SESSION TRANSCRIPT:\n")
	b.WriteString(transcript)
	b.WriteString("\n")
	return b.String()
}

// parseSummary accepts the same three output shapes runbook.parseProposal does:
// direct JSON, a claude {"result": "..."} envelope, or raw text with embedded
// JSON.
func parseSummary(stdout []byte, agent string) (SessionSummary, error) {
	stdout = bytes.TrimSpace(stdout)
	if len(stdout) == 0 {
		return SessionSummary{}, errors.New("empty stdout")
	}
	if s, ok := trySummary(stdout); ok {
		return s, nil
	}
	if agent == "claude" {
		var env struct {
			Result string `json:"result"`
		}
		if err := json.Unmarshal(stdout, &env); err == nil && env.Result != "" {
			if body := extractJSONObject([]byte(env.Result)); body != nil {
				if s, ok := trySummary(body); ok {
					return s, nil
				}
			}
		}
	}
	if body := extractJSONObject(stdout); body != nil {
		if s, ok := trySummary(body); ok {
			return s, nil
		}
	}
	return SessionSummary{}, fmt.Errorf("no parseable summary in %d bytes of output", len(stdout))
}

func trySummary(b []byte) (SessionSummary, bool) {
	var s SessionSummary
	if err := json.Unmarshal(b, &s); err != nil {
		return SessionSummary{}, false
	}
	if len(s.Bullets) == 0 && len(s.Proposed) == 0 {
		return SessionSummary{}, false
	}
	return s, true
}

func (c CLISummarizer) buildEnv(agent string) []string {
	env := []string{}
	if c.HomeDir != "" {
		env = append(env, "HOME="+c.HomeDir)
		env = append(env, "CLAUDE_CONFIG_DIR="+c.HomeDir+"/.claude")
	}
	if c.BinDir != "" {
		env = append(env, "PATH="+c.BinDir+":/usr/local/bin:/usr/bin:/bin")
	}
	if c.Secrets != nil {
		for k, v := range c.Secrets(agent) {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func defaultExec(ctx context.Context, name string, args []string, env []string, stdin string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.CombinedOutput()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// extractJSONObject scans s for the first balanced top-level {...} block,
// tolerating a leading ```json fence and trailing prose. (Same logic as
// runbook.extractJSONObject; duplicated to keep the packages decoupled.)
func extractJSONObject(s []byte) []byte {
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
