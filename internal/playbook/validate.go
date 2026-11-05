package playbook

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"

	"github.com/rockclaver/rootmote-agent/internal/runbook"
	"github.com/rockclaver/rootmote-agent/internal/steps"
)

// Limits on the manual part of a playbook.
const (
	maxManualSteps   = 10
	maxManualText    = 600
	maxManualCommand = 300
)

// integerMax is the largest value an integer parameter may have. A process
// start time counts clock ticks since boot, so it needs the full int64 range;
// the others have real limits.
func integerMax(name string) int64 {
	switch name {
	case "start_time":
		return math.MaxInt64
	case "port":
		return 65535
	case "pid":
		return 1 << 22 // the largest pid_max on Linux
	}
	return math.MaxInt32
}

// StepValidator checks that a step's target exists on this host right now.
// *steps.Runner satisfies it.
type StepValidator interface {
	Validate(ctx context.Context, id steps.ID, p steps.Params) error
}

// suspiciousManual flags manual commands that fetch and run code, delete
// recursively or hide what they do. They are shown to the user but never
// run, and the playbook is marked "review carefully".
var suspiciousManual = regexp.MustCompile(`(?i)(\|\s*(sh|bash|zsh)\b|\bcurl\b|\bwget\b|\bbase64\b|\brm\s+-[a-z]*r|\bmkfs\b|\bdd\s+if=|>\s*/dev/sd|\bchmod\s+-R\b|\beval\b)`)

// Check validates a playbook against the step catalog and this server's
// inventory. It is the check that makes a playbook safe to show for approval,
// whoever wrote it: every step must be a catalog step, its parameters must be
// exactly the ones the catalog defines with values of the right shape, and
// every name must exist in the inventory. When v is not nil each step is also
// checked against the live host.
//
// Check cleans the manual steps in place (control characters removed, long
// text cut) and sets ReviewCarefully when a manual command looks risky or
// when a generated playbook has any manual command.
func Check(ctx context.Context, pb *Playbook, inv Inventory, v StepValidator) error {
	if len(pb.Steps) > MaxSteps {
		return fmt.Errorf("playbook has %d steps; at most %d are allowed", len(pb.Steps), MaxSteps)
	}
	if len(pb.Steps) == 0 && len(pb.Manual) == 0 {
		return errors.New("playbook has no steps")
	}
	for i, s := range pb.Steps {
		if err := checkStep(ctx, s, inv, v); err != nil {
			return fmt.Errorf("step %d (%s): %w", i+1, s.Step, err)
		}
	}
	if len(pb.Manual) > maxManualSteps {
		pb.Manual = pb.Manual[:maxManualSteps]
	}
	clean := pb.Manual[:0]
	for _, m := range pb.Manual {
		m.Text = cleanText(m.Text, maxManualText)
		m.Command = cleanText(m.Command, maxManualCommand)
		if m.Text == "" {
			continue
		}
		if m.Command != "" && (pb.Source == runbook.SourceGenerated || suspiciousManual.MatchString(m.Command)) {
			// Commands written by a model are always shown with a warning.
			pb.ReviewCarefully = true
		}
		clean = append(clean, m)
	}
	pb.Manual = clean
	pb.Title = cleanText(pb.Title, 120)
	pb.Summary = cleanText(pb.Summary, 600)
	return nil
}

// cleanText removes control characters (newlines become spaces) and cuts the
// text to max bytes without splitting a character.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t' || r == '\r' || r == '\u2028' || r == '\u2029':
			return ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			// Control and format characters (right-to-left overrides,
			// zero-width spaces) can make shown text differ from what is copied.
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut])
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

func checkStep(ctx context.Context, s Step, inv Inventory, v StepValidator) error {
	step, ok := steps.Lookup(s.Step)
	if !ok {
		return errors.New("not a step this agent can run")
	}
	def := step.Def()
	want := map[string]steps.Param{}
	for _, p := range def.Params {
		want[p.Name] = p
	}
	for name := range s.Params {
		if _, ok := want[name]; !ok {
			return fmt.Errorf("unexpected parameter %q", name)
		}
	}
	for _, p := range def.Params {
		raw, ok := s.Params[p.Name]
		if !ok {
			return fmt.Errorf("missing parameter %q", p.Name)
		}
		if err := checkParam(p, s.Params, raw); err != nil {
			return fmt.Errorf("parameter %q: %w", p.Name, err)
		}
	}
	if err := checkSource(def, s.Params, inv); err != nil {
		return err
	}
	if v != nil {
		return v.Validate(ctx, s.Step, s.Params)
	}
	return nil
}

func checkParam(p steps.Param, all steps.Params, raw any) error {
	switch p.Type {
	case "integer":
		n, ok := all.Int(p.Name)
		if !ok {
			return errors.New("must be a whole number")
		}
		if _, isString := raw.(string); isString {
			return errors.New("must be a number, not text")
		}
		if n < 1 || n > integerMax(p.Name) {
			return errors.New("out of range")
		}
		return nil
	default:
		str, ok := raw.(string)
		if !ok {
			return errors.New("must be text")
		}
		if len(p.Enum) > 0 && !contains(p.Enum, str) {
			return fmt.Errorf("must be one of %s", strings.Join(p.Enum, ", "))
		}
		if p.Pattern != "" {
			re, err := regexp.Compile(p.Pattern)
			if err != nil || !re.MatchString(str) {
				return errors.New("has an invalid format")
			}
		}
		return nil
	}
}

// checkSource requires every value that names something on the server to be
// in the inventory. Two-part names (a Compose project and service, a PM2 app
// and its user) must exist together.
func checkSource(def steps.Def, p steps.Params, inv Inventory) error {
	for _, param := range def.Params {
		switch param.Source {
		case "units":
			if !inv.hasUnit(p.String(param.Name)) {
				return fmt.Errorf("%q is not a service on this server", p.String(param.Name))
			}
		case "containers":
			if !inv.hasContainer(p.String(param.Name)) {
				return fmt.Errorf("%q is not a container on this server", p.String(param.Name))
			}
		case "supervisor_programs":
			if !contains(inv.SupervisorPrograms, p.String(param.Name)) {
				return fmt.Errorf("%q is not a Supervisor program on this server", p.String(param.Name))
			}
		case "certs":
			if !contains(inv.Certs, p.String(param.Name)) {
				return fmt.Errorf("%q is not a certificate on this server", p.String(param.Name))
			}
		case "urls":
			if !contains(inv.URLs, p.String(param.Name)) {
				return fmt.Errorf("%q is not a web address on this server", p.String(param.Name))
			}
		case "ports":
			n, _ := p.Int(param.Name)
			if !containsInt(inv.Ports, int(n)) {
				return fmt.Errorf("nothing listens on port %d", n)
			}
		}
	}
	switch def.ID {
	case steps.ComposeUpID:
		if !hasCompose(inv, p.String("project"), p.String("service")) {
			return fmt.Errorf("%q is not a Compose service of project %q on this server", p.String("service"), p.String("project"))
		}
	case steps.PM2RestartID:
		for _, a := range inv.PM2Apps {
			if a.App == p.String("app") && a.User == p.String("user") {
				return nil
			}
		}
		return fmt.Errorf("%q is not a PM2 app of user %q on this server", p.String("app"), p.String("user"))
	}
	return nil
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}
