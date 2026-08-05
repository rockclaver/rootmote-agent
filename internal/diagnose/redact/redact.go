// Package redact implements the PRD 12.3 redaction rules used by the agent's
// diagnostic pipeline. Raw evidence never leaves the server: everything the
// agent collects passes through a Redactor before it is shown to the AI or
// summarized for the relay.
package redact

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Rule names, stable and used in Report.Rules.
const (
	RuleEnvValue    = "env_value"
	RuleAuthHeader  = "auth_header"
	RuleCookie      = "cookie"
	RulePrivateKey  = "private_key"
	RuleDatabaseURL = "database_url"
	RuleAPIKey      = "api_key"
	RuleUserPattern = "user_pattern"
)

// Placeholder replaces every redacted value.
const Placeholder = "[REDACTED]"

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

// secretKeyword matches the field-name vocabulary the PRD treats as
// secret-bearing: passwords, tokens, API/access/private keys, credentials
// and auth material of any kind.
const secretKeyword = `pass(?:word|wd)?|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credential|auth`

var (
	// reSecretKey matches a field/header *name* that looks secret-bearing,
	// independent of the value's shape. Used by Map to decide by key first.
	reSecretKey = regexp.MustCompile(`(?i)(?:` + secretKeyword + `)`)

	// RuleEnvValue: "KEY=value" / "KEY: value" lines where KEY matches the
	// secret vocabulary. The whole remainder of the line is the value.
	reEnvValueLine = regexp.MustCompile(`(?im)^([ \t]*[\w.-]*(?:` + secretKeyword + `)[\w.-]*)([ \t]*[:=][ \t]*)([^\r\n]+)$`)

	// RuleAuthHeader: "Authorization: ..." / "Proxy-Authorization: ..."
	// header lines, plus bare "Bearer <token>" / "Basic <token>" tokens
	// that are not part of such a header line.
	reAuthHeaderLine = regexp.MustCompile(`(?im)^([ \t]*(?:Proxy-)?Authorization)([ \t]*:[ \t]*)([^\r\n]+)$`)
	reBareAuthToken  = regexp.MustCompile(`(?i)\b(Bearer|Basic)[ \t]+([A-Za-z0-9._~+/=-]+)`)

	// RuleCookie: "Cookie:" / "Set-Cookie:" header lines.
	reCookieLine = regexp.MustCompile(`(?im)^([ \t]*(?:Set-Cookie|Cookie))([ \t]*:[ \t]*)([^\r\n]+)$`)

	// RulePrivateKey: a PEM private key block, terminated or running to the
	// end of input when the closing marker is missing (truncated logs).
	rePrivateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)

	// RuleDatabaseURL: scheme://user:password@host... connection strings.
	// Only the password component is replaced.
	reDatabaseURL = regexp.MustCompile(`(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://([^:@/\s]*):([^@\s]*)@`)

	// RuleAPIKey: recognizable API-key/token shapes. Ordered so the more
	// specific "sk-ant-" prefix wins over the generic "sk-" prefix.
	reAPIKey = regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9_-]{16,}|oauth_[A-Za-z0-9_-]+|github_pat_[A-Za-z0-9_-]+|ghp_[A-Za-z0-9_-]+|xox[baprs]-[A-Za-z0-9_-]+|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
)

// builtinRule pairs a rule name with the function that applies it. apply
// returns the (possibly unchanged) string and whether it changed the input.
type builtinRule struct {
	name  string
	apply func(string) (string, bool)
}

// builtinRules runs in a fixed order. The more specific header/cookie forms
// run before the generic KEY=value scan so a line like
// "Authorization: Bearer xyz" is reported as auth_header, not env_value; by
// the time the generic scan runs, the value has already become Placeholder
// and the generic regex is a no-op (change-detected, so it is not
// double-reported). Private keys run first so their base64 body is never
// mistaken for an API key.
var builtinRules = []builtinRule{
	{RulePrivateKey, applyLiteral(rePrivateKey)},
	{RuleAuthHeader, applyAuthHeader},
	{RuleCookie, applyTemplate(reCookieLine, "${1}${2}"+Placeholder)},
	{RuleDatabaseURL, applyTemplate(reDatabaseURL, "${1}://${2}:"+Placeholder+"@")},
	{RuleAPIKey, applyLiteral(reAPIKey)},
	{RuleEnvValue, applyTemplate(reEnvValueLine, "${1}${2}"+Placeholder)},
}

// applyTemplate replaces every match of re with a $-template replacement
// (may reference capture groups) and reports whether anything changed.
func applyTemplate(re *regexp.Regexp, tmpl string) func(string) (string, bool) {
	return func(s string) (string, bool) {
		out := re.ReplaceAllString(s, tmpl)
		return out, out != s
	}
}

// applyLiteral replaces every match of re with the literal Placeholder
// (no group substitution) and reports whether anything changed.
func applyLiteral(re *regexp.Regexp) func(string) (string, bool) {
	return func(s string) (string, bool) {
		out := re.ReplaceAllLiteralString(s, Placeholder)
		return out, out != s
	}
}

// applyAuthHeader handles both the "Authorization: ..." header-line form and
// bare "Bearer <token>" / "Basic <token>" tokens that appear on their own.
func applyAuthHeader(s string) (string, bool) {
	out := reAuthHeaderLine.ReplaceAllString(s, "${1}${2}"+Placeholder)
	headerChanged := out != s
	out2 := reBareAuthToken.ReplaceAllString(out, "${1} "+Placeholder)
	tokenChanged := out2 != out
	return out2, headerChanged || tokenChanged
}

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

// Redactor applies the PRD 12.3 rule set plus user-supplied patterns.
type Redactor struct {
	userPatterns []*regexp.Regexp
}

// New builds a Redactor. userPatterns are Go regexps; an invalid pattern is
// reported in err and the Redactor is still usable with the built-in rules.
func New(userPatterns []string) (*Redactor, error) {
	r := &Redactor{}
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
// malformed input and never grows the output.
func (r *Redactor) Text(s string) (string, Report) {
	var rep Report
	out := s
	for _, rule := range builtinRules {
		var changed bool
		out, changed = rule.apply(out)
		if changed {
			rep.Rules = append(rep.Rules, rule.name)
		}
	}
	for _, re := range r.userPatterns {
		replaced := re.ReplaceAllLiteralString(out, Placeholder)
		if replaced != out {
			rep.Rules = append(rep.Rules, RuleUserPattern)
		}
		out = replaced
	}
	rep.Rules = sortDedup(rep.Rules)
	rep.Applied = len(rep.Rules) > 0
	return out, rep
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
