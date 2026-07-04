package sessions

// structured.go holds the agent-neutral infrastructure shared by every
// structured runtime (Claude, Codex). Each runtime translates its native CLI
// protocol into the normalized events of normalize.go and publishes them
// through a structuredSink; the translate step produces []translated, which the
// sink fans out to the Manager's persisted/ephemeral publish paths.

import (
	"bufio"
	"io"
	"log"
	"strings"

	"github.com/rockclaver/rootmote-agent/internal/store"
)

// translated is one normalized event a runtime will publish. Ephemeral events
// (streaming deltas) are delivered live-only; the rest are persisted.
type translated struct {
	Type      string
	Payload   any
	Ephemeral bool
}

// structuredSink publishes normalized events for one session back to the
// Manager. It is shared by the Claude and Codex structured runtimes.
type structuredSink struct {
	sessionID string
	emit      func(store.SessionEvent) // persisted
	ephemeral func(store.SessionEvent) // live-only
	warn      func(string, ...any)     // operator log for dropped/unknown lines; nil ⇒ stderr
}

// warnf logs a dropped or unknown protocol line. It never tears the session
// down: the runtime read loop logs and skips so one bad frame cannot kill an
// otherwise healthy stream. Defaults to the standard logger (stderr) when no
// sink-specific hook is set (tests inject one to assert the log fired).
func (s structuredSink) warnf(format string, args ...any) {
	if s.warn != nil {
		s.warn(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (s structuredSink) publish(tr translated) {
	ev, err := normalizedEvent(s.sessionID, tr.Type, tr.Payload)
	if err != nil {
		return
	}
	if tr.Ephemeral {
		if s.ephemeral != nil {
			s.ephemeral(ev)
		}
		return
	}
	if s.emit != nil {
		s.emit(ev)
	}
}

func (s structuredSink) publishError(msg string, fatal bool) {
	if s.emit == nil {
		return
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	ev, err := normalizedEvent(s.sessionID, EvError, ErrorEvent{Message: msg, Fatal: fatal})
	if err == nil {
		s.emit(ev)
	}
}

func (s structuredSink) publishStderr(r io.Reader, prefix string) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if prefix != "" {
			line = prefix + ": " + line
		}
		s.publishError(line, false)
	}
	if err := scanner.Err(); err != nil {
		s.warnf("structured stderr scan failed: %v", err)
	}
}

// truncateLine bounds a raw protocol line so a malformed-frame log entry cannot
// dump a megabyte of payload into the operator log. It trims the trailing
// newline and caps the body, marking truncation.
func truncateLine(line []byte) string {
	const max = 256
	s := strings.TrimRight(string(line), "\r\n")
	if len(s) > max {
		return s[:max] + "…(truncated)"
	}
	return s
}
