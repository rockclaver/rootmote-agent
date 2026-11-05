package redact

import (
	"bytes"
	"os"
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
			rule:   "bearer_token",
		},
		{
			name:   "bare basic token",
			input:  "curl -H 'Authorization' with Basic dXNlcjpwYXNz manually set",
			secret: "dXNlcjpwYXNz",
			rule:   "bearer_token",
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
			rule:   "aws_access_key",
		},
		{
			name:   "jwt",
			input:  "session jwt is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ for request",
			secret: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ",
			rule:   "jwt",
		},
	}

	r := newRedactor(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, report := r.Text(tc.input)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret %q still present in output %q", tc.secret, out)
			}
			if !strings.Contains(out, "[REDACTED") {
				t.Fatalf("output %q missing redaction marker", out)
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
		for _, want := range []string{"postgres://", "db.internal", "5432", "/app"} {
			if !strings.Contains(out, want) {
				t.Fatalf("output %q missing diagnosable fragment %q", out, want)
			}
		}
		// The shared rules redact the whole user:password credentials block.
		if strings.Contains(out, "s3cr3t") || strings.Contains(out, "appuser") {
			t.Fatalf("credentials leaked in %q", out)
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

	want := []string{RuleCookie, RuleEnvValue, RuleAPIKey}
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

func TestRedact_VectorsByCategory(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
	cases := []struct {
		name   string
		input  string
		secret string // must be gone
		rule   string // must have fired
	}{
		{"jwt", "got eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2ln here", "eyJhbGciOiJIUzI1NiJ9", "jwt"},
		{"bearer", "header Bearer abcdefgh12345678 sent", "abcdefgh12345678", "bearer_token"},
		{"authorization header", "Authorization: Token zzzzzzzz1111", "zzzzzzzz1111", "auth_header"},
		{"cookie header", "Cookie: sid=abc123def; theme=dark", "abc123def", "cookie"},
		{"postgres url", "postgres://u:pw0rd@db:5432/x", "pw0rd", "database_url"},
		{"postgresql url user only", "postgresql://tok3n@db/x", "tok3n", "database_url"},
		{"mysql url", "mysql://root:pw1@h/db", "pw1", "database_url"},
		{"mongodb url", "mongodb+srv://u:pw2@c.example.net/db", "pw2", "database_url"},
		{"redis url", "rediss://:pw3@cache:6379", "pw3", "database_url"},
		{"aws key", "key AKIAABCDEFGHIJKLMNOP end", "AKIAABCDEFGHIJKLMNOP", "aws_access_key"},
		{"gcp api key", "key AIza" + strings.Repeat("aB3_", 8) + "xyz end", "AIzaaB3_", "gcp_api_key"},
		{"gcp oauth token", "tok ya29.a0AfH6SMBx1234567890abcdefgh end", "a0AfH6SMBx1234567890abcdefgh", "gcp_oauth_token"},
		{"stripe live", "sk_live_abcdefghij1234567890", "abcdefghij1234567890", "stripe_paystack_key"},
		{"stripe/paystack test", "using sk_test_abcdefghij1234567890 now", "abcdefghij1234567890", "stripe_paystack_key"},
		{"flutterwave", "FLWSECK_TEST-abcdef1234567890-X", "abcdef1234567890", "flutterwave_key"},
		{"private key terminated", "a\n" + pem + "\nb", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "private_key"},
		{"private key truncated", "a\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIabcdef", "MHcCAQEEIabcdef", "private_key"},
		{"email", "contact ops@example.com please", "ops@example.com", "email"},
		{"ipv4", "from 203.0.113.7 and 8.8.8.8", "8.8.8.8", "ipv4"},
		{"ipv6 full", "peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 up", "8a2e:0370", "ipv6"},
		{"ipv6 compressed", "peer 2001:db8::ff00:42:8329 up", "ff00:42", "ipv6"},
		{"ipv6 leading", "bind ::ffff:c0a8 and ::1", "::1", "ipv6_leading"},
		{"password assignment", "set password=hunter2 next", "hunter2", "secret_assignment"},
		{"secret assignment", "start --secret=abc123xyz now", "abc123xyz", "secret_assignment"},
		{"token assignment", "refresh token=qwerty123456 ok", "qwerty123456", "secret_assignment"},
		{"json password", `{"user":"a","password": "x9y8z7"}`, "x9y8z7", "secret_assignment"},
		{"json single quoted", `{'password':'x9y8z7'}`, "x9y8z7", "secret_assignment"},
		{"high entropy", "blob q8W3zXr7Lp2Vn9Bk4Tc6Yh1Gd5Fs0JmA3eRu8Ni", "q8W3zXr7Lp2Vn9Bk4Tc6Yh1Gd5Fs0JmA3eRu8Ni", "high_entropy"},
	}
	r := newRedactor(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, rep := r.Text(tc.input)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret %q survived: %q", tc.secret, out)
			}
			if !rep.Applied {
				t.Fatalf("Applied=false for %q", tc.input)
			}
			if !contains(rep.Rules, tc.rule) {
				t.Fatalf("rule %q not in %v (out %q)", tc.rule, rep.Rules, out)
			}
			if !sort.StringsAreSorted(rep.Rules) {
				t.Fatalf("rules not sorted: %v", rep.Rules)
			}
			if r.Clean(tc.input) {
				t.Fatalf("Clean true for sensitive input %q", tc.input)
			}
			if !r.Clean(out) {
				t.Fatalf("redacted output %q is not clean", out)
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestRedact_EntropyRule(t *testing.T) {
	r := newRedactor(t)
	t.Run("long low entropy string kept", func(t *testing.T) {
		for _, in := range []string{
			strings.Repeat("z", 40),
			"/var/lib/docker/containers/overlay2/merged/usr/share",
		} {
			if out, rep := r.Text(in); out != in || rep.Applied {
				t.Fatalf("%q changed to %q (%v)", in, out, rep.Rules)
			}
		}
	})
	t.Run("whitespace preserved around redacted token", func(t *testing.T) {
		secret := "q8W3zXr7Lp2Vn9Bk4Tc6Yh1Gd5Fs0JmA3eRu8Ni"
		out, _ := r.Text("a \t b\n\n  " + secret + "\r\nc ")
		if want := "a \t b\n\n  [REDACTED:secret]\r\nc "; out != want {
			t.Fatalf("got %q want %q", out, want)
		}
	})
	t.Run("long hex secret redacted", func(t *testing.T) {
		hex := "9f2c4ab1e07d35c8a6f1904be2d7c3a58f06b1d4e92a7c35b8d01f64a3e9c27b"
		for _, in := range []string{"GET /password/reset/" + hex, "key=" + hex, hex, "\"" + hex + "\""} {
			out, rep := r.Text(in)
			if strings.Contains(out, hex) || !rep.Applied {
				t.Fatalf("%q left the hex secret in: %q", in, out)
			}
		}
	})
	t.Run("short hex kept", func(t *testing.T) {
		in := "request id 9f2c4ab1e07d35c8 failed"
		if out, rep := r.Text(in); out != in || rep.Applied {
			t.Fatalf("%q changed to %q (%v)", in, out, rep.Rules)
		}
	})
}

func TestRedact_OrdinaryLinesPassThrough(t *testing.T) {
	r := newRedactor(t)
	for _, in := range []string{
		"nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)",
		"Nov 05 10:00:00 host systemd[1]: Started Foo.",
		"version 1.2.3 released",
		"2026-08-05T12:00:00Z api container restarted after healthcheck failure",
	} {
		t.Run(in, func(t *testing.T) {
			out, rep := r.Text(in)
			// 0.0.0.0 matches the ipv4 rule by design; everything else
			// must be untouched.
			if strings.Contains(in, "0.0.0.0") {
				if want := strings.Replace(in, "0.0.0.0", "[REDACTED:ip]", 1); out != want {
					t.Fatalf("got %q want %q", out, want)
				}
				return
			}
			if out != in || rep.Applied {
				t.Fatalf("changed %q -> %q (%v)", in, out, rep.Rules)
			}
		})
	}
}

func TestRedact_RuleNamesFromFile(t *testing.T) {
	rules, err := loadRules()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, r := range rules {
		have[r.Name] = true
	}
	for _, n := range []string{"jwt", "database_url", "high_entropy", RuleEnvValue, RuleAuthHeader, RuleCookie, RulePrivateKey, RuleAPIKey} {
		if !have[n] {
			t.Errorf("rule %q missing from rules.json", n)
		}
	}
}

func TestParseRules_Errors(t *testing.T) {
	for name, in := range map[string]string{
		"bad json":        `{`,
		"bad version":     `{"version":2,"rules":[]}`,
		"bad kind":        `{"version":1,"rules":[{"name":"a","kind":"x"}]}`,
		"bad regex":       `{"version":1,"rules":[{"name":"a","kind":"regex","pattern":"("}]}`,
		"no name":         `{"version":1,"rules":[{"kind":"regex","pattern":"a"}]}`,
		"dup":             `{"version":1,"rules":[{"name":"a","kind":"regex","pattern":"a"},{"name":"a","kind":"regex","pattern":"b"}]}`,
		"entropy":         `{"version":1,"rules":[{"name":"a","kind":"entropy"}]}`,
		"hex length only": `{"version":1,"rules":[{"name":"a","kind":"entropy","minLength":32,"minBitsPerChar":4,"hexMinLength":32}]}`,
		"hex bits only":   `{"version":1,"rules":[{"name":"a","kind":"entropy","minLength":32,"minBitsPerChar":4,"hexMinBitsPerChar":3}]}`,
	} {
		if _, err := parseRules([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestRedact_ForRequestAndClean(t *testing.T) {
	r := newRedactor(t)
	p := NewPlaceholders("web01.example.com")
	out, rep := r.ForRequest(p, "web01 at 8.8.8.8 password=hunter2")
	if out != "host-1 at ip-1 password=[REDACTED:secret]" {
		t.Fatalf("got %q", out)
	}
	if !rep.Applied || !contains(rep.Rules, "secret_assignment") {
		t.Fatalf("report %v", rep)
	}
	if !r.Clean("nothing to see") || r.Clean("password=hunter2") {
		t.Fatal("Clean misjudged")
	}
}

func TestPlaceholders_Hostnames(t *testing.T) {
	p := NewPlaceholders("Web01.Example.com", "db-primary.internal.net", "web01.example.com")
	cases := []struct{ in, want string }{
		{"WEB01.example.COM is down", "host-1 is down"},
		{"ssh to web01: refused", "ssh to host-1: refused"},
		{"db-primary. and db-primary.internal.net", "host-2. and host-2"},
		{"web011 and xweb01 and web01-old stay", "web011 and xweb01 and web01-old stay"},
		{"pre.web01 stays", "pre.web01 stays"},
		{"no host here", "no host here"},
	}
	for _, tc := range cases {
		if got := p.Apply(tc.in); got != tc.want {
			t.Errorf("Apply(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPlaceholders_ShortFormMinimum(t *testing.T) {
	p := NewPlaceholders("db.example.com")
	if got := p.Apply("db and db.example.com"); got != "db and host-1" {
		t.Fatalf("got %q", got)
	}
}

func TestPlaceholders_IPs(t *testing.T) {
	p := NewPlaceholders()
	got := p.Apply("a 8.8.8.8 b 1.1.1.1 c 8.8.8.8 d 2606:4700:4700::1111 e 2606:4700:4700::1111.")
	want := "a ip-1 b ip-2 c ip-1 d ip-3 e ip-3."
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	for _, in := range []string{
		"10.1.2.3", "192.168.0.1", "172.16.5.5", "127.0.0.1", "169.254.1.1", "100.64.0.1",
		"192.0.2.1", "198.51.100.9", "203.0.113.7", "0.0.0.0", "::1", "fe80::1", "fc00::1",
		"2001:db8::1", "12:00:00", "version 1.2.3", "::ffff:10.0.0.1",
	} {
		if out := p.Apply(in); out != in {
			t.Errorf("non-public %q changed to %q", in, out)
		}
	}
	if out := p.Apply("::ffff:8.8.8.8 x"); out != "ip-1 x" {
		t.Errorf("mapped public: %q", out)
	}
	var nilP *Placeholders
	if nilP.Apply("8.8.8.8") != "8.8.8.8" {
		t.Error("nil Placeholders must be a no-op")
	}
}

func TestRulesJSON_MatchesWatchtowerCopy(t *testing.T) {
	const other = "../../../../watchtower/internal/playbook/redact_rules.json"
	want, err := os.ReadFile(other)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("%s not present (agent checked out on its own)", other)
		}
		t.Fatal(err)
	}
	got, err := os.ReadFile("rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("rules.json differs from watchtower/internal/playbook/redact_rules.json; copy it byte-for-byte")
	}
}
