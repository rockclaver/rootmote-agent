// Package redact implements the redaction rules used by the agent's
// diagnostic pipeline. Raw evidence never leaves the server: everything the
// agent collects passes through a Redactor before it is shown to the AI or
// summarized for the relay.
//
// The rule set lives in rules.json, a byte-identical copy of the Watchtower
// playbook's redact_rules.json, and is embedded at build time.
package redact

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Rule names, stable and used in Report.Rules. They match the names in
// rules.json; RuleUserPattern is the only rule that is not in that file.
const (
	RuleEnvValue    = "env_value"
	RuleAuthHeader  = "auth_header"
	RuleCookie      = "cookie"
	RulePrivateKey  = "private_key"
	RuleDatabaseURL = "database_url"
	RuleAPIKey      = "provider_api_key"
	RuleUserPattern = "user_pattern"
)

// Placeholder replaces every user-pattern match and every value known to be
// secret (see Value).
const Placeholder = "[REDACTED]"

//go:embed rules.json
var rulesJSON []byte

const (
	kindRegex   = "regex"
	kindEntropy = "entropy"
)

// ruleFile is the on-disk shape of rules.json.
type ruleFile struct {
	Version int        `json:"version"`
	Rules   []ruleSpec `json:"rules"`
}

type ruleSpec struct {
	Name           string  `json:"name"`
	Kind           string  `json:"kind"`
	Pattern        string  `json:"pattern"`
	Replacement    string  `json:"replacement"`
	MinLength      int     `json:"minLength"`
	MinBitsPerChar float64 `json:"minBitsPerChar"`
	// HexMinLength and HexMinBitsPerChar replace the two limits above for
	// tokens made only of hex digits (hex has at most 4 bits per character).
	HexMinLength      int     `json:"hexMinLength"`
	HexMinBitsPerChar float64 `json:"hexMinBitsPerChar"`
}

// compiledRule is a validated ruleSpec; re is nil for entropy rules.
type compiledRule struct {
	ruleSpec
	re *regexp.Regexp
}

var (
	loadOnce  sync.Once
	loaded    []compiledRule
	loadError error
)

// loadRules parses and compiles the embedded rules exactly once.
func loadRules() ([]compiledRule, error) {
	loadOnce.Do(func() {
		loaded, loadError = parseRules(rulesJSON)
	})
	return loaded, loadError
}

func parseRules(data []byte) ([]compiledRule, error) {
	var f ruleFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("redact: parse rules.json: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("redact: unsupported rules.json version %d", f.Version)
	}
	seen := make(map[string]struct{}, len(f.Rules))
	out := make([]compiledRule, 0, len(f.Rules))
	for i, spec := range f.Rules {
		if spec.Name == "" {
			return nil, fmt.Errorf("redact: rule %d has no name", i)
		}
		if _, dup := seen[spec.Name]; dup {
			return nil, fmt.Errorf("redact: duplicate rule name %q", spec.Name)
		}
		seen[spec.Name] = struct{}{}
		cr := compiledRule{ruleSpec: spec}
		switch spec.Kind {
		case kindRegex:
			re, err := regexp.Compile(spec.Pattern)
			if err != nil {
				return nil, fmt.Errorf("redact: rule %q: %w", spec.Name, err)
			}
			cr.re = re
		case kindEntropy:
			if spec.MinLength <= 0 || spec.MinBitsPerChar <= 0 {
				return nil, fmt.Errorf("redact: entropy rule %q needs positive minLength and minBitsPerChar", spec.Name)
			}
			if (spec.HexMinLength > 0) != (spec.HexMinBitsPerChar > 0) || spec.HexMinLength < 0 || spec.HexMinBitsPerChar < 0 {
				return nil, fmt.Errorf("redact: entropy rule %q needs both hexMinLength and hexMinBitsPerChar, or neither", spec.Name)
			}
		default:
			return nil, fmt.Errorf("redact: rule %q has unknown kind %q", spec.Name, spec.Kind)
		}
		out = append(out, cr)
	}
	return out, nil
}

// Report records what a redaction pass changed.
type Report struct {
	Applied bool     `json:"applied"`
	Rules   []string `json:"rules"` // sorted, deduped
}

// Merge folds other into r, unioning the fired rules and sorting/deduping.
func (r *Report) Merge(other Report) {
	r.Rules = sortDedup(append(append([]string{}, r.Rules...), other.Rules...))
	r.Applied = r.Applied || other.Applied
}

// reSecretKey matches a field/header *name* that looks secret-bearing,
// independent of the value's shape. Used by Map to decide by key first.
var reSecretKey = regexp.MustCompile(`(?i)(?:pass(?:word|wd)?|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credential|auth)`)

// sortDedup returns rules sorted and deduplicated. A nil/empty input yields
// nil so Report.Rules serializes as [] rather than accumulating garbage.
func sortDedup(rules []string) []string {
	if len(rules) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(rules))
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// shannonBits returns the Shannon entropy of s in bits per rune and the
// rune count.
func shannonBits(s string) (float64, int) {
	counts := make(map[rune]int)
	n := 0
	for _, c := range s {
		counts[c]++
		n++
	}
	if n == 0 {
		return 0, 0
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h, n
}

// trimEdges are quoting and punctuation characters kept outside a redacted
// token (same set as the Watchtower playbook redactor).
const trimEdges = "\"'`()<>[]{},;"

// isHex reports whether s is non-empty and made only of hex digits.
func isHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return s != ""
}

// applyEntropy replaces every whitespace-delimited token that is at least
// minLength runes long and has at least minBitsPerChar bits of entropy per
// character, keeping surrounding quotes/brackets. Tokens already holding a
// [REDACTED marker are skipped. Whitespace between tokens is preserved.
func applyEntropy(rule compiledRule, s string) string {
	var b strings.Builder
	changed := false
	start := -1 // byte offset of the current token, -1 between tokens
	flush := func(end int) {
		tok := s[start:end]
		start = -1
		if !strings.Contains(tok, "[REDACTED") {
			core := strings.Trim(tok, trimEdges)
			minLen, minBits := rule.MinLength, rule.MinBitsPerChar
			if rule.HexMinLength > 0 && isHex(core) {
				minLen, minBits = rule.HexMinLength, rule.HexMinBitsPerChar
			}
			if utf8.RuneCountInString(core) >= minLen {
				if bits, _ := shannonBits(core); bits >= minBits {
					i := strings.Index(tok, core)
					b.WriteString(tok[:i])
					b.WriteString(rule.Replacement)
					b.WriteString(tok[i+len(core):])
					changed = true
					return
				}
			}
		}
		b.WriteString(tok)
	}
	for i, c := range s {
		if unicode.IsSpace(c) {
			if start >= 0 {
				flush(i)
			}
			b.WriteRune(c)
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		flush(len(s))
	}
	if !changed {
		return s
	}
	return b.String()
}

// Redactor applies the embedded rule set plus user-supplied patterns.
type Redactor struct {
	rules        []compiledRule
	userPatterns []*regexp.Regexp
}

// New builds a Redactor. userPatterns are Go regexps; an invalid pattern is
// reported in err and the Redactor is still usable with the built-in rules.
// If the embedded rules cannot be loaded New returns a nil Redactor.
func New(userPatterns []string) (*Redactor, error) {
	rules, err := loadRules()
	if err != nil {
		return nil, err
	}
	r := &Redactor{rules: rules}
	var bad []string
	for _, p := range userPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%q: %v", p, err))
			continue
		}
		r.userPatterns = append(r.userPatterns, re)
	}
	if len(bad) > 0 {
		return r, fmt.Errorf("redact: invalid user pattern(s): %s", strings.Join(bad, "; "))
	}
	return r, nil
}

// Text redacts a blob and reports which rules fired. It never panics on
// malformed input.
func (r *Redactor) Text(s string) (string, Report) {
	var fired []string
	out := s
	for _, rule := range r.rules {
		var next string
		if rule.re != nil {
			next = rule.re.ReplaceAllString(out, rule.Replacement)
		} else {
			next = applyEntropy(rule, out)
		}
		if next != out {
			fired = append(fired, rule.Name)
			out = next
		}
	}
	for _, re := range r.userPatterns {
		replaced := re.ReplaceAllLiteralString(out, Placeholder)
		if replaced != out {
			fired = append(fired, RuleUserPattern)
		}
		out = replaced
	}
	rep := Report{Rules: sortDedup(fired)}
	rep.Applied = len(rep.Rules) > 0
	return out, rep
}

// ForRequest applies the request placeholders p (hostnames and public IPs)
// and then the redaction rules.
func (r *Redactor) ForRequest(p *Placeholders, s string) (string, Report) {
	return r.Text(p.Apply(s))
}

// Clean reports whether running the rules over s changes nothing, i.e. no
// sensitive material is left in it.
func (r *Redactor) Clean(s string) bool {
	out, _ := r.Text(s)
	return out == s
}

// Value redacts a single value that is known to be a secret-bearing field
// (an env value, a header value). It always redacts non-empty input.
func (r *Redactor) Value(s string) (string, Report) {
	if s == "" {
		return "", Report{}
	}
	return Placeholder, Report{Applied: true, Rules: []string{RuleEnvValue}}
}

// Map redacts a key/value map, using the KEY to decide whether the whole
// value is a secret, then running Text over survivors.
func (r *Redactor) Map(m map[string]string) (map[string]string, Report) {
	out := make(map[string]string, len(m))
	var rep Report
	for k, v := range m {
		var (
			redacted string
			sub      Report
		)
		if reSecretKey.MatchString(k) {
			redacted, sub = r.Value(v)
		} else {
			redacted, sub = r.Text(v)
		}
		out[k] = redacted
		rep.Merge(sub)
	}
	return out, rep
}
