package sessions

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/store"
)

// usagePollInterval is how often we re-read a claude transcript for fresh token
// totals. The interactive CLIs never print usage to stdout, so the transcript
// JSONL is the only authoritative source.
const usagePollInterval = 4 * time.Second

// claudeUsage holds cumulative token counts summed across a session's turns.
type claudeUsage struct {
	input  int
	output int
	cache  int
}

func (u claudeUsage) total() int { return u.input + u.output }

// transcriptLine is the subset of a claude transcript JSONL record we need.
// Each assistant turn carries a usage block reported by the model.
type transcriptLine struct {
	Type    string `json:"type"`
	Message struct {
		Usage struct {
			InputTokens              int `json:"input_tokens"`
			OutputTokens             int `json:"output_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	} `json:"message"`
}

// startUsagePoll launches a background reader that mirrors a claude session's
// transcript token usage into the store and fans a structured "usage" event to
// live subscribers. It is a no-op without a configured transcript root.
func (m *Manager) startUsagePoll(sessionID, claudeSessionID string) {
	if m.ClaudeProjectsDir == "" || claudeSessionID == "" {
		return
	}
	stop := make(chan struct{})
	m.mu.Lock()
	// A prior poller for this id (e.g. rapid restart) is abandoned; close it.
	if prev, ok := m.usageStops[sessionID]; ok {
		close(prev)
	}
	m.usageStops[sessionID] = stop
	m.mu.Unlock()
	go m.pollUsage(sessionID, claudeSessionID, stop)
}

// stopUsagePoll signals a session's poller to exit. Idempotent.
func (m *Manager) stopUsagePoll(sessionID string) {
	m.mu.Lock()
	if stop, ok := m.usageStops[sessionID]; ok {
		close(stop)
		delete(m.usageStops, sessionID)
	}
	m.mu.Unlock()
}

func (m *Manager) pollUsage(sessionID, claudeSessionID string, stop <-chan struct{}) {
	t := time.NewTicker(usagePollInterval)
	defer t.Stop()
	last := -1
	tick := func() {
		u, ok := readClaudeTranscriptUsage(m.ClaudeProjectsDir, claudeSessionID)
		if !ok || u.total() == last {
			return
		}
		last = u.total()
		_ = m.Store.UpdateSessionUsage(sessionID, u.input, u.output, u.cache)
		_, _ = m.Publish(store.SessionEvent{
			SessionID: sessionID,
			Type:      "usage",
			Data: fmt.Sprintf(
				`{"input_tokens":%d,"output_tokens":%d,"cache_tokens":%d,"total_tokens":%d}`,
				u.input, u.output, u.cache, u.total(),
			),
		})
	}
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			tick()
		}
	}
}

// readClaudeTranscriptUsage locates <claudeSessionID>.jsonl under projectsDir
// and sums the per-turn usage blocks. ok is false when no transcript exists yet
// (the CLI writes it lazily on the first turn).
func readClaudeTranscriptUsage(projectsDir, claudeSessionID string) (claudeUsage, bool) {
	var u claudeUsage
	if projectsDir == "" || claudeSessionID == "" {
		return u, false
	}
	path, ok := findTranscript(projectsDir, claudeSessionID)
	if !ok {
		return u, false
	}
	f, err := os.Open(path)
	if err != nil {
		return u, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// Transcript lines embed full message content and can be large.
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	any := false
	for sc.Scan() {
		var tl transcriptLine
		if json.Unmarshal(sc.Bytes(), &tl) != nil || tl.Type != "assistant" {
			continue
		}
		us := tl.Message.Usage
		u.input += us.InputTokens + us.CacheCreationInputTokens
		u.output += us.OutputTokens
		u.cache += us.CacheReadInputTokens
		any = true
	}
	return u, any
}

// findTranscript resolves the transcript path for a claude session UUID. Claude
// nests transcripts one level deep under a cwd-encoded directory, so we glob a
// single level before falling back to the flat layout.
func findTranscript(projectsDir, claudeSessionID string) (string, bool) {
	name := claudeSessionID + ".jsonl"
	if matches, _ := filepath.Glob(filepath.Join(projectsDir, "*", name)); len(matches) > 0 {
		return matches[0], true
	}
	flat := filepath.Join(projectsDir, name)
	if _, err := os.Stat(flat); err == nil {
		return flat, true
	}
	return "", false
}
