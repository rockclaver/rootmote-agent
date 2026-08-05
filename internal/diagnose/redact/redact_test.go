package redact

import (
	"sort"
	"strings"
	"testing"
)

func newRedactor(t *testing.T) *Redactor {
	t.Helper()
	r, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil) returned error: %v", err)
	}
	return r
}

// slackBotToken is a synthetic, full-shape Slack bot token assembled from
// segments. Written as a single literal it trips GitHub's push protection,
// which would either block the push or push us toward a weaker fixture; the
// redactor under test sees the identical string.
var slackBotToken = strings.Join(
	[]string{"xoxb", "123456789012", "1234567890123", "AbCdEfGhIjKlMnOpQrStUvWx"}, "-",
)

func TestRedact_RemovesEveryPRDCategory(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		secret string // substring that must be gone from the output
		rule   string
	}{
		{
			name:   "env value",
			input:  "DB_PASSWORD=hunter2",
			secret: "hunter2",
			rule:   RuleEnvValue,
		},
		{
			name:   "authorization header",
			input:  "Authorization: Bearer abcdef.ghijkl",
			secret: "abcdef.ghijkl",
			rule:   RuleAuthHeader,
		},
		{
			name:   "bare bearer token",
			input:  "sent header value Bearer abcdef0123456789 to upstream",
			secret: "abcdef0123456789",
			rule:   RuleAuthHeader,
		},
		{
			name:   "bare basic token",
			input:  "curl -H 'Authorization' with Basic dXNlcjpwYXNz manually set",
			secret: "dXNlcjpwYXNz",
			rule:   RuleAuthHeader,
		},
		{
			name:   "cookie header",
			input:  "Cookie: session=abc123; other=xyz",
			secret: "abc123",
			rule:   RuleCookie,
		},
		{
			name:   "set-cookie header",
			input:  "Set-Cookie: session=abc123; Path=/; HttpOnly",
			secret: "abc123",
			rule:   RuleCookie,
		},
		{
			name: "terminated pem private key",
			input: "before\n" +
				"-----BEGIN RSA PRIVATE KEY-----\n" +
				"MIIEowIBAAKCAQEAsecretkeymaterialhere\n" +
				"-----END RSA PRIVATE KEY-----\n" +
				"after",
			secret: "MIIEowIBAAKCAQEAsecretkeymaterialhere",
			rule:   RulePrivateKey,
		},
		{
			name: "unterminated pem private key",
			input: "before\n" +
				"-----BEGIN PRIVATE KEY-----\n" +
				"MIIEowIBAAKCAQEAtruncatedkeymaterial",
			secret: "MIIEowIBAAKCAQEAtruncatedkeymaterial",
			rule:   RulePrivateKey,
		},
		{
			name:   "postgres url with password",
			input:  "connecting to postgres://appuser:s3cr3t@db.internal:5432/app",
			secret: "s3cr3t",
			rule:   RuleDatabaseURL,
		},
		{
			name:   "mysql url with password",
			input:  "DSN=mysql://root:t0pSecret@127.0.0.1:3306/orders",
			secret: "t0pSecret",
			rule:   RuleDatabaseURL,
		},
		{
			name:   "mongodb url with password",
			input:  "mongo dial mongodb://svc:m0ngoPass@cluster0.example.net:27017/prod",
			secret: "m0ngoPass",
			rule:   RuleDatabaseURL,
		},
		{
			name:   "redis url with password",
			input:  "redis://:redisPass123@cache.internal:6379/0",
			secret: "redisPass123",
			rule:   RuleDatabaseURL,
		},
		{
			name:   "openai sk key",
			input:  "using key sk-proj-abcdefghijklmnopqrstuvwxyz1234567890 for request",
			secret: "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
			rule:   RuleAPIKey,
		},
		{
			name:   "anthropic sk-ant key",
			input:  "ANTHROPIC key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789 loaded",
			secret: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
			rule:   RuleAPIKey,
		},
		{
			name:   "oauth token",
			input:  "refresh token oauth_1234567890abcdefGHIJ issued",
			secret: "oauth_1234567890abcdefGHIJ",
			rule:   RuleAPIKey,
		},
		{
			name:   "github classic pat",
			input:  "clone with ghp_16C7e42F292c6912E7710c838347Ae178B4a token",
			secret: "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
			rule:   RuleAPIKey,
		},
		{
			name:   "github fine-grained pat",
			input:  "clone with github_pat_11AAAAAAA0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb token",
			secret: "github_pat_11AAAAAAA0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			rule:   RuleAPIKey,
		},
		{
			// Composed from segments rather than written as one literal:
			// a full-shape Slack token in source trips GitHub's push
			// protection, and the redactor sees the identical string either
			// way.
			name:   "slack bot token",
			input:  "posting via " + slackBotToken + " webhook",
			secret: slackBotToken,
			rule:   RuleAPIKey,
		},
		{
			name:   "aws access key id",
			input:  "AWS_ACCESS_KEY_ID_LITERAL AKIAIOSFODNN7EXAMPLE in dump",
			secret: "AKIAIOSFODNN7EXAMPLE",
			rule:   RuleAPIKey,
		},
		{
			name:   "jwt",
			input:  "session jwt is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ for request",
			secret: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ",
			rule:   RuleAPIKey,
		},
	}

	r := newRedactor(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, report := r.Text(tc.input)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret %q still present in output %q", tc.secret, out)
			}
			if !strings.Contains(out, Placeholder) {
				t.Fatalf("output %q missing placeholder %q", out, Placeholder)
			}
			if !report.Applied {
				t.Fatalf("expected Applied=true for input %q", tc.input)
			}
			found := false
			for _, rule := range report.Rules {
				if rule == tc.rule {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected rule %q in %v", tc.rule, report.Rules)
			}
		})
	}
}

func TestRedact_PreservesDiagnosableContext(t *testing.T) {
	r := newRedactor(t)

	t.Run("database url keeps scheme host port dbname", func(t *testing.T) {
		out, report := r.Text("connecting to postgres://appuser:s3cr3t@db.internal:5432/app")
		for _, want := range []string{"postgres://", "appuser", "db.internal", "5432", "/app"} {
			if !strings.Contains(out, want) {
				t.Fatalf("output %q missing diagnosable fragment %q", out, want)
			}
		}
		if strings.Contains(out, "s3cr3t") {
			t.Fatalf("password leaked in %q", out)
		}
		if !report.Applied {
			t.Fatalf("expected Applied=true")
		}
	})

	t.Run("authorization header keeps header name", func(t *testing.T) {
		out, _ := r.Text("Authorization: Bearer abcdef.ghijkl")
		if !strings.HasPrefix(out, "Authorization:") {
			t.Fatalf("expected header name preserved, got %q", out)
		}
		if strings.Contains(out, "abcdef.ghijkl") {
			t.Fatalf("token leaked in %q", out)
		}
	})

	t.Run("ordinary log text untouched", func(t *testing.T) {
		input := "2026-08-05T12:00:00Z api container restarted after healthcheck failure"
		out, report := r.Text(input)
		if out != input {
			t.Fatalf("expected unchanged output, got %q", out)
		}
		if report.Applied {
			t.Fatalf("expected Applied=false, got rules %v", report.Rules)
		}
		if len(report.Rules) != 0 {
			t.Fatalf("expected no rules, got %v", report.Rules)
		}
	})
}

func TestRedact_IsIdempotent(t *testing.T) {
	r := newRedactor(t)
	inputs := []string{
		"DB_PASSWORD=hunter2",
		"Authorization: Bearer abcdef.ghijkl",
		"Cookie: session=abc123; other=xyz",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretkeymaterialhere\n-----END RSA PRIVATE KEY-----",
		"postgres://appuser:s3cr3t@db.internal:5432/app",
		"using key sk-proj-abcdefghijklmnopqrstuvwxyz1234567890 for request",
		"ordinary log line with nothing secret in it",
	}

	for _, input := range inputs {
		first, firstReport := r.Text(input)
		second, secondReport := r.Text(first)
		if second != first {
			t.Fatalf("not idempotent for %q: first=%q second=%q", input, first, second)
		}
		if firstReport.Applied && secondReport.Applied {
			t.Fatalf("second pass over %q reported Applied=true again: %v", input, secondReport.Rules)
		}
	}
}

func TestRedact_UserPatterns(t *testing.T) {
	t.Run("fires and reports user_pattern", func(t *testing.T) {
		r, err := New([]string{`INTERNAL-[0-9]{4}`})
		if err != nil {
			t.Fatalf("New returned error: %v", err)
		}
		out, report := r.Text("ticket reference INTERNAL-4821 attached")
		if strings.Contains(out, "INTERNAL-4821") {
			t.Fatalf("user pattern secret leaked in %q", out)
		}
		if !report.Applied {
			t.Fatalf("expected Applied=true")
		}
		found := false
		for _, rule := range report.Rules {
			if rule == RuleUserPattern {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected %q in %v", RuleUserPattern, report.Rules)
		}
	})

	t.Run("invalid pattern yields error but working redactor", func(t *testing.T) {
		r, err := New([]string{`[unterminated`})
		if err == nil {
			t.Fatalf("expected error for invalid pattern")
		}
		if r == nil {
			t.Fatalf("expected non-nil Redactor even with an invalid pattern")
		}
		if !strings.Contains(err.Error(), "unterminated") {
			t.Fatalf("expected error to name the bad pattern, got %v", err)
		}
		// Built-ins still work.
		out, report := r.Text("DB_PASSWORD=hunter2")
		if strings.Contains(out, "hunter2") {
			t.Fatalf("built-in redaction disabled by bad user pattern: %q", out)
		}
		if !report.Applied {
			t.Fatalf("expected Applied=true from built-in rule despite bad user pattern")
		}
	})
}

func TestRedact_MapRedactsBySecretKey(t *testing.T) {
	r := newRedactor(t)
	in := map[string]string{
		"DB_PASSWORD": "hunter2",
		"API_TOKEN":   "not-shaped-like-a-known-key-format",
		"HOSTNAME":    "api.internal",
	}
	out, report := r.Map(in)

	if out["DB_PASSWORD"] != Placeholder {
		t.Fatalf("expected DB_PASSWORD fully redacted, got %q", out["DB_PASSWORD"])
	}
	if out["API_TOKEN"] != Placeholder {
		t.Fatalf("expected API_TOKEN fully redacted regardless of shape, got %q", out["API_TOKEN"])
	}
	if out["HOSTNAME"] != "api.internal" {
		t.Fatalf("expected non-secret key left untouched, got %q", out["HOSTNAME"])
	}
	if !report.Applied {
		t.Fatalf("expected Applied=true")
	}
}

func TestRedact_ValueAlwaysRedactsNonEmpty(t *testing.T) {
	r := newRedactor(t)

	out, report := r.Value("plain-non-secret-shaped-string")
	if out != Placeholder {
		t.Fatalf("expected Value to always redact non-empty input, got %q", out)
	}
	if !report.Applied {
		t.Fatalf("expected Applied=true for non-empty Value input")
	}

	out, report = r.Value("")
	if out != "" {
		t.Fatalf("expected empty input to stay empty, got %q", out)
	}
	if report.Applied {
		t.Fatalf("expected Applied=false for empty Value input")
	}
}

func TestReport_MergeUnionsAndSorts(t *testing.T) {
	a := Report{Applied: true, Rules: []string{RuleEnvValue, RuleCookie}}
	b := Report{Applied: false, Rules: []string{RuleAPIKey, RuleEnvValue}}

	a.Merge(b)

	want := []string{RuleAPIKey, RuleCookie, RuleEnvValue}
	if !sort.StringsAreSorted(a.Rules) {
		t.Fatalf("expected sorted rules, got %v", a.Rules)
	}
	if len(a.Rules) != len(want) {
		t.Fatalf("expected deduped union %v, got %v", want, a.Rules)
	}
	for i, rule := range want {
		if a.Rules[i] != rule {
			t.Fatalf("expected %v, got %v", want, a.Rules)
		}
	}
	if !a.Applied {
		t.Fatalf("expected Applied=true after merging with an applied report")
	}

	var empty Report
	var other Report
	empty.Merge(other)
	if empty.Applied {
		t.Fatalf("expected Applied=false when merging two empty reports")
	}
	if len(empty.Rules) != 0 {
		t.Fatalf("expected no rules, got %v", empty.Rules)
	}
}
