package memory

import (
	"context"
	"testing"
)

func TestCLISummarizerParsesClaudeEnvelope(t *testing.T) {
	s := CLISummarizer{
		Agent: "claude",
		Exec: func(_ context.Context, _ string, _ []string, _ []string, _ string) ([]byte, error) {
			// claude -p --output-format json wraps the assistant text in
			// {"result": "..."}; the text itself is a fenced JSON block.
			return []byte(`{"result":"` + "```json\\n{\\\"bullets\\\":[\\\"Did X\\\"],\\\"proposed_memory\\\":[{\\\"kind\\\":\\\"gotcha\\\",\\\"title\\\":\\\"T\\\",\\\"body\\\":\\\"B\\\"}]}\\n```" + `"}`), nil
		},
	}
	out, err := s.Summarize(context.Background(), "p1", "s1", "transcript")
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if len(out.Bullets) != 1 || out.Bullets[0] != "Did X" {
		t.Fatalf("bullets = %+v", out.Bullets)
	}
	if len(out.Proposed) != 1 || out.Proposed[0].Kind != "gotcha" {
		t.Fatalf("proposed = %+v", out.Proposed)
	}
}

func TestCLISummarizerParsesDirectJSON(t *testing.T) {
	s := CLISummarizer{
		Agent: "codex",
		Exec: func(_ context.Context, _ string, _ []string, _ []string, _ string) ([]byte, error) {
			return []byte(`prefix chatter {"bullets":["Fixed Y"],"proposed_memory":[]} trailing`), nil
		},
	}
	out, err := s.Summarize(context.Background(), "p1", "s1", "t")
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if len(out.Bullets) != 1 || out.Bullets[0] != "Fixed Y" {
		t.Fatalf("bullets = %+v", out.Bullets)
	}
}

func TestCLISummarizerRejectsGarbage(t *testing.T) {
	s := CLISummarizer{
		Exec: func(_ context.Context, _ string, _ []string, _ []string, _ string) ([]byte, error) {
			return []byte("not json at all"), nil
		},
	}
	if _, err := s.Summarize(context.Background(), "p1", "s1", "t"); err == nil {
		t.Fatal("expected parse error")
	}
}
