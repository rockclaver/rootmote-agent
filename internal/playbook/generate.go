package playbook

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/rockclaver/rootmote-agent/internal/diagnose"
	"github.com/rockclaver/rootmote-agent/internal/diagnose/redact"
	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/steps"
	"github.com/rockclaver/rootmote-agent/internal/watchtower"
)

// Limits on the evidence sent with a request (contract C4).
const (
	maxLogLines     = 100
	maxLogBytes     = 8 * 1024
	maxLogLineBytes = 1024
	maxSignatures   = 20
)

// Messages shown to the user. They are plain English and mention no
// technology the user did not choose.
const (
	MsgTurnOnMonitoring = "Turn on monitoring to generate playbooks."
	msgUnreachable      = "Could not reach the playbook service. Try again in a minute."
	msgBadPlaybook      = "The playbook service returned a fix that did not pass the safety check, so it was not used."
	msgNoPlaybook       = "No playbook could be generated."
)

// Statuses carried by Error. They are the playbook service's own words and
// become the error codes of the incident.playbook.generate RPC.
const (
	StatusConsentRequired = watchtower.PlaybookConsentRequired
	StatusLimitReached    = watchtower.PlaybookLimitReached
	StatusNoPlaybook      = watchtower.PlaybookNone
	StatusUnavailable     = watchtower.PlaybookUnavailable
)

// Finding is one thing the agent already knows about the problem, shown when
// no playbook can be built.
type Finding struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// Error is why Generate returned no playbook.
type Error struct {
	Status   string
	Message  string
	Findings []Finding
}

func (e *Error) Error() string { return e.Message }

// Incident names the incident a playbook is for.
type Incident struct {
	ID       string
	Kind     string
	Target   string
	Severity string
	// UserRequested is true when the user asked for the playbook, false for
	// the automatic request on a critical incident.
	UserRequested bool
}

// Client is the signed Watchtower client.
type Client interface {
	RequestPlaybook(ctx context.Context, in watchtower.PlaybookRequest) (watchtower.PlaybookResponse, error)
}

// Generator asks the playbook service for a fix. Nothing leaves the server
// except the redacted request BuildRequest produces.
type Generator struct {
	Client Client
	// Redactor applies the shared redaction rules. Required.
	Redactor *redact.Redactor
	// Hostnames are this machine's names; they are replaced by placeholders
	// before anything is sent.
	Hostnames []string
	// Validator checks each returned step against the live host. May be nil.
	Validator StepValidator
}

// BuildRequest builds the redacted request for an incident (contract C4):
// the signatures, names only from the inventory, a metrics snapshot, the OS,
// and at most 100 log lines and 8 KB of log text. Hostnames and public IP
// addresses become placeholders, and every string passes the shared rules.
// A string the rules would still change after one pass is left out, so a
// second pass over the request changes nothing.
func (g *Generator) BuildRequest(inc Incident, f Facts) watchtower.PlaybookRequest {
	ph := redact.NewPlaceholders(g.Hostnames...)
	hostRe := hostnamePattern(g.Hostnames)
	sanitize := func(s string) (string, bool) {
		out, _ := g.Redactor.ForRequest(ph, s)
		if hostRe != nil {
			// A host name inside a longer word is not caught by the
			// placeholders; replace it wherever it appears.
			out = hostRe.ReplaceAllString(out, "host-1")
		}
		return out, out != "" && g.Redactor.Clean(out)
	}
	// clean reports whether a name can be sent exactly as it is. A name that
	// redaction or a placeholder would change is left out, because the
	// changed name would not match anything on the server.
	clean := func(s string) bool {
		out, _ := g.Redactor.ForRequest(ph, s)
		return out == s && (hostRe == nil || !hostRe.MatchString(s))
	}

	req := watchtower.PlaybookRequest{
		IncidentID:     inc.ID,
		Kind:           inc.Kind,
		Severity:       inc.Severity,
		Signatures:     []watchtower.PlaybookSignature{},
		Inventory:      f.Inventory.wire(clean),
		Metrics:        metricsOf(f.Bundle),
		OS:             watchtower.PlaybookOS{Distro: f.OS.Distro, Version: f.OS.Version},
		Logs:           []string{},
		CatalogVersion: steps.CatalogVersion,
		UserRequested:  inc.UserRequested,
	}
	sigs := f.Signatures
	if sigs == nil {
		sigs = diagnose.Match(f.Bundle)
	}
	for _, s := range sigs {
		if len(req.Signatures) >= maxSignatures {
			break
		}
		title, ok := sanitize(s.Title)
		if !ok {
			continue
		}
		detail, _ := sanitize(s.Detail)
		req.Signatures = append(req.Signatures, watchtower.PlaybookSignature{ID: s.ID, Title: title, Detail: detail})
	}
	req.Logs = g.logLines(f.Bundle, sanitize)
	return req
}

// logLines returns the newest log lines that fit the line and byte limits,
// oldest first.
func (g *Generator) logLines(b diagnose.Bundle, sanitize func(string) (string, bool)) []string {
	var all []string
	for _, l := range b.Logs {
		for _, line := range strings.Split(l.Content, "\n") {
			line = strings.TrimRight(line, "\r ")
			if strings.TrimSpace(line) == "" {
				continue
			}
			if len(line) > maxLogLineBytes {
				line = cutBytes(line, maxLogLineBytes)
			}
			if out, ok := sanitize(line); ok {
				all = append(all, out)
			}
		}
	}
	var picked []string
	total := 0
	for i := len(all) - 1; i >= 0 && len(picked) < maxLogLines; i-- {
		if total+len(all[i]) > maxLogBytes {
			break
		}
		total += len(all[i])
		picked = append(picked, all[i])
	}
	for i, j := 0, len(picked)-1; i < j; i, j = i+1, j-1 {
		picked[i], picked[j] = picked[j], picked[i]
	}
	if picked == nil {
		picked = []string{}
	}
	return picked
}

// hostnamePattern matches any of the host names, in any case, anywhere in a
// string. It returns nil when there are none.
func hostnamePattern(names []string) *regexp.Regexp {
	var parts []string
	for _, n := range names {
		if n = strings.TrimSpace(n); len(n) >= 3 {
			parts = append(parts, regexp.QuoteMeta(n))
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return regexp.MustCompile(`(?i)` + strings.Join(parts, "|"))
}

func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func metricsOf(b diagnose.Bundle) watchtower.PlaybookMetrics {
	m := watchtower.PlaybookMetrics{}
	m.CPUPercent, _ = metricValue(b, "cpu_percent")
	m.MemPercent, _ = metricValue(b, "memory_used_percent")
	m.Load1, _ = metricValue(b, "load_one")
	m.MemTotalMB, _ = metricValue(b, "memory_total_mb")
	m.SwapTotalMB, _ = metricValue(b, "swap_total_mb")
	m.DiskPercent = worstDisk(b, "disk_used_percent")
	m.InodePercent = worstDisk(b, "inode_used_percent")
	return m
}

// worstDisk returns the root filesystem's value for a disk metric, or the
// highest value over all mounts when the root filesystem is not reported.
func worstDisk(b diagnose.Bundle, name string) float64 {
	worst := 0.0
	for _, x := range b.Metrics {
		if x.Name != name {
			continue
		}
		if x.Subject == "/" {
			return x.Value
		}
		if x.Value > worst {
			worst = x.Value
		}
	}
	return worst
}

// findings turns the deterministic signatures into plain findings.
func findings(f Facts) []Finding {
	sigs := f.Signatures
	if sigs == nil {
		sigs = diagnose.Match(f.Bundle)
	}
	out := make([]Finding, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, Finding{Title: s.Title, Detail: s.Detail})
	}
	return out
}

// Generate asks the playbook service for a fix and checks the answer locally
// before returning it. The answer is untrusted: it must use catalog steps
// only, with parameters of the right shape, naming things that exist in this
// server's inventory (and, with a Validator, on the host right now).
//
// The returned error is an *Error when the service refused, had nothing to
// offer, or sent something that failed the local check.
func (g *Generator) Generate(ctx context.Context, inc Incident, f Facts) (Playbook, error) {
	if g.Client == nil {
		return Playbook{}, &Error{Status: StatusUnavailable, Message: MsgTurnOnMonitoring}
	}
	resp, err := g.Client.RequestPlaybook(ctx, g.BuildRequest(inc, f))
	if err != nil {
		if errors.Is(err, watchtower.ErrNotEnrolled) {
			return Playbook{}, &Error{Status: StatusUnavailable, Message: MsgTurnOnMonitoring}
		}
		return Playbook{}, &Error{Status: StatusUnavailable, Message: msgUnreachable}
	}
	switch resp.Status {
	case watchtower.PlaybookOK:
	case watchtower.PlaybookConsentRequired, watchtower.PlaybookLimitReached, watchtower.PlaybookUnavailable:
		return Playbook{}, &Error{Status: resp.Status, Message: orDefault(resp.Message, msgUnreachable)}
	case watchtower.PlaybookNone:
		return Playbook{}, &Error{Status: StatusNoPlaybook, Message: orDefault(resp.Message, msgNoPlaybook), Findings: findings(f)}
	default:
		return Playbook{}, &Error{Status: StatusUnavailable, Message: msgUnreachable}
	}
	if resp.Playbook == nil {
		return Playbook{}, &Error{Status: StatusUnavailable, Message: msgUnreachable}
	}
	pb := fromDraft(*resp.Playbook)
	dropWrongDisk(&pb, f)
	if err := Check(ctx, &pb, f.Inventory, g.Validator); err != nil {
		return Playbook{}, &Error{Status: StatusNoPlaybook, Message: fmt.Sprintf("%s (%v)", msgBadPlaybook, err), Findings: findings(f)}
	}
	return pb, nil
}

func fromDraft(d watchtower.PlaybookDraft) Playbook {
	pb := Playbook{Title: d.Title, Summary: d.Summary, Source: runbook.SourceGenerated, ReviewCarefully: d.ReviewCarefully}
	for _, s := range d.Steps {
		params := steps.Params{}
		for k, v := range s.Params {
			params[k] = v
		}
		pb.Steps = append(pb.Steps, Step{Step: steps.ID(s.Step), Params: params})
	}
	for _, m := range d.Manual {
		pb.Manual = append(pb.Manual, Manual{Text: m.Text, Command: m.Command})
	}
	return pb
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// dropWrongDisk removes disk clean-up steps that free space on a different
// disk than the one that ran out, and says so in a manual step. It does
// nothing when the incident is not about a full disk.
func dropWrongDisk(pb *Playbook, f Facts) {
	mounts := map[string]bool{}
	for _, sig := range f.Signatures {
		if sig.Type == "disk_exhausted" || sig.Type == "inode_exhausted" {
			m := sig.Subject
			if m == "" {
				m = "/"
			}
			mounts[m] = true
		}
	}
	if len(mounts) == 0 {
		return
	}
	kept := pb.Steps[:0]
	dropped := false
	for _, s := range pb.Steps {
		switch s.Step {
		case steps.JournalVacuumID, steps.DockerPruneID, steps.AptCleanID:
			if !mounts[f.DiskMounts[s.Step]] {
				dropped = true
				continue
			}
		}
		kept = append(kept, s)
	}
	pb.Steps = kept
	if dropped {
		pb.Manual = append(pb.Manual, Manual{Text: "Some automatic clean-ups were left out because they free space on a different disk than the one that is full."})
	}
}
