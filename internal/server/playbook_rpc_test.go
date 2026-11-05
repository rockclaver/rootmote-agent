package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rockclaver/rootmote-agent/internal/watchtower"
)

// playbookRelay is a fake relay that enrolls an agent and answers every
// playbook request with reply.
func playbookRelay(t *testing.T, reply watchtower.PlaybookResponse, hits *int) *watchtower.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/agents/register", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"agentId": "agt_1", "serverId": "srv_1", "secret": "abcdef0123456789"})
	})
	mux.HandleFunc("/v1/agents/playbooks", func(w http.ResponseWriter, r *http.Request) {
		*hits++
		_ = json.NewEncoder(w).Encode(reply)
	})
	relay := httptest.NewServer(mux)
	t.Cleanup(relay.Close)
	c, err := watchtower.NewClient(t.TempDir(), "test", relay.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.PlaybookHTTP = relay.Client()
	if _, err := c.Enroll(t.Context(), relay.URL, "code"); err != nil {
		t.Fatal(err)
	}
	return c
}

func playbookCfg(t *testing.T, client *watchtower.Client) Config {
	t.Helper()
	env := newRemediationTestEnv(t)
	cfg := env.cfg
	cfg.Store = env.st
	cfg.Watchtower = client
	return cfg
}

func generatePayload(t *testing.T) []byte {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"incidentId": "inc-web", "monitorKind": "external_http", "target": "https://shop.example.com/", "severity": "warning"})
	return b
}

func TestIncidentPlaybookGenerate_MapsServiceStatusesToErrorCodes(t *testing.T) {
	cases := []struct {
		status   string
		wantKind string
		findings bool
	}{
		{"consent_required", "error.consent_required", false},
		{"limit_reached", "error.limit_reached", false},
		{"no_playbook", "error.no_playbook", true},
		{"unavailable", "error.unavailable", false},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			hits := 0
			client := playbookRelay(t, watchtower.PlaybookResponse{Status: tc.status, Message: "Plain words for " + tc.status}, &hits)
			resp := remediationRoundTrip(t, playbookCfg(t, client), "incident.playbook.generate", generatePayload(t))
			if resp.Kind != tc.wantKind {
				t.Fatalf("kind = %q payload = %s, want %s", resp.Kind, resp.Payload, tc.wantKind)
			}
			var body struct {
				Error    string           `json:"error"`
				Findings *json.RawMessage `json:"findings"`
			}
			if err := json.Unmarshal(resp.Payload, &body); err != nil {
				t.Fatal(err)
			}
			if body.Error != "Plain words for "+tc.status {
				t.Fatalf("message = %q, want the service's own words", body.Error)
			}
			if tc.findings != (body.Findings != nil) {
				t.Fatalf("findings present = %v, want %v (payload %s)", body.Findings != nil, tc.findings, resp.Payload)
			}
			if hits != 1 {
				t.Fatalf("service was asked %d times, want 1", hits)
			}
		})
	}
}

func TestIncidentPlaybookGenerate_MonitoringOffIsUnavailable(t *testing.T) {
	cfg := playbookCfg(t, nil)
	resp := remediationRoundTrip(t, cfg, "incident.playbook.generate", generatePayload(t))
	if resp.Kind != "error.unavailable" || !strings.Contains(string(resp.Payload), "Turn on monitoring to generate playbooks.") {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
}

func TestIncidentPlaybookGenerate_BadPayload(t *testing.T) {
	resp := remediationRoundTrip(t, playbookCfg(t, nil), "incident.playbook.generate", []byte(`{}`))
	if resp.Kind != "error.bad_payload" {
		t.Fatalf("kind = %q", resp.Kind)
	}
}

func TestIncidentPlaybookGenerate_ReturnsExecutionTheAppCanOpen(t *testing.T) {
	hits := 0
	client := playbookRelay(t, watchtower.PlaybookResponse{Status: "ok", Playbook: &watchtower.PlaybookDraft{
		Title: "Check the proxy by hand", Summary: "The proxy cannot reach its backend.",
		Manual: []watchtower.PlaybookManual{{Text: "Read the proxy error log.", Command: "tail -50 /var/log/nginx/error.log"}},
	}}, &hits)
	cfg := playbookCfg(t, client)
	resp := remediationRoundTrip(t, cfg, "incident.playbook.generate", generatePayload(t))
	if resp.Kind != "incident.playbook.generate" {
		t.Fatalf("kind = %q payload = %s", resp.Kind, resp.Payload)
	}
	var out struct {
		ExecutionID string `json:"executionId"`
	}
	if err := json.Unmarshal(resp.Payload, &out); err != nil || out.ExecutionID == "" {
		t.Fatalf("payload = %s err = %v", resp.Payload, err)
	}

	get, _ := json.Marshal(map[string]any{"execution_id": out.ExecutionID})
	got := remediationRoundTrip(t, cfg, "incident.runbook.get", get)
	if got.Kind != "incident.runbook.get" {
		t.Fatalf("kind = %q payload = %s", got.Kind, got.Payload)
	}
	var body struct {
		Execution struct {
			IncidentID string `json:"incident_id"`
			Status     string `json:"status"`
		} `json:"execution"`
		Runbook struct {
			Title       string `json:"title"`
			Source      string `json:"source"`
			ManualSteps []struct {
				Text    string `json:"text"`
				Command string `json:"command"`
			} `json:"manualSteps"`
			ReviewCarefully bool `json:"reviewCarefully"`
		} `json:"runbook"`
	}
	if err := json.Unmarshal(got.Payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.Execution.IncidentID != "inc-web" || body.Execution.Status != "proposed" {
		t.Fatalf("execution = %+v, want proposed under the relay incident id", body.Execution)
	}
	if body.Runbook.Title != "Check the proxy by hand" || body.Runbook.Source != "generated" || len(body.Runbook.ManualSteps) != 1 || body.Runbook.ManualSteps[0].Command == "" {
		t.Fatalf("runbook = %+v", body.Runbook)
	}

	// Asking again returns the same execution without another service call.
	again := remediationRoundTrip(t, cfg, "incident.playbook.generate", generatePayload(t))
	var out2 struct {
		ExecutionID string `json:"executionId"`
	}
	_ = json.Unmarshal(again.Payload, &out2)
	if out2.ExecutionID != out.ExecutionID || hits != 1 {
		t.Fatalf("second execution = %q (first %q), service hits = %d", out2.ExecutionID, out.ExecutionID, hits)
	}
}

// --- host sources ---

func TestParseDu_KeepsTheBiggestLeafDirectories(t *testing.T) {
	out := []byte("100\t/var/cache\n5242880\t/var/lib/docker\n300\t/var/lib/misc\n5243180\t/var/lib\n921600\t/var/log\n6165780\t/var\n40\t/etc\n6166000\t/\n")
	dirs := parseDu(out, "/", 3)
	if len(dirs) != 3 {
		t.Fatalf("dirs = %+v", dirs)
	}
	if dirs[0].Path != "/var/lib/docker" || dirs[0].SizeMB != 5120 || dirs[1].Path != "/var/log" || dirs[1].SizeMB != 900 {
		t.Fatalf("dirs = %+v, want docker 5120 MB then log 900 MB (parents like /var/lib left out)", dirs)
	}
	for _, d := range dirs {
		if d.Path == "/" || d.Path == "/var" || d.Path == "/var/lib" {
			t.Fatalf("parent directory %q listed", d.Path)
		}
	}
}

const nginxConf = `
http {
    # comment with proxy_pass http://127.0.0.1:1111;
    upstream api { server 127.0.0.1:3000; server 127.0.0.1:3001 weight=2; }
    server {
        listen 80;
        server_name shop.example.com www.shop.example.com;
        location /api { proxy_pass http://api; }
        location / { proxy_pass http://127.0.0.1:8080/; }
    }
    server {
        server_name other.example.com;
        location / { proxy_pass http://127.0.0.1:9090; }
    }
}
`

func TestNginxBackends_FindsBackendsForOneHost(t *testing.T) {
	got := nginxBackends([][]byte{[]byte(nginxConf)}, "shop.example.com")
	want := []string{"127.0.0.1:3000", "127.0.0.1:3001", "127.0.0.1:8080"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("backends = %v, want %v", got, want)
	}
	if got := nginxBackends([][]byte{[]byte(nginxConf)}, "unknown.example.com"); len(got) != 0 {
		t.Fatalf("backends for an unknown host = %v, want none", got)
	}
}

func TestUnitFromCgroup(t *testing.T) {
	cases := map[string]string{
		"0::/system.slice/demo-api.service\n":                    "demo-api.service",
		"0::/system.slice/docker-abc.scope\n":                    "",
		"1:name=systemd:/system.slice/nginx.service\n0::/x\n":    "nginx.service",
		"0::/user.slice/user-1000.slice/session-3.scope\n":       "",
		"0::/system.slice/system-getty.slice/getty@tty1.service": "getty@tty1.service",
	}
	for in, want := range cases {
		if got := unitFromCgroup(in); got != want {
			t.Errorf("unitFromCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}

type webErrorsPriv struct {
	out []byte
	err error
	got []string
}

func (p *webErrorsPriv) Call(_ context.Context, action string, args ...string) ([]byte, error) {
	p.got = append([]string{action}, args...)
	return p.out, p.err
}

// The error log comes from the read-only web-errors helper action, trimmed to
// the lines asked for; no helper, a failure or an empty answer is an error.
func TestProxyErrorLog_ComesFromTheHelperAndIsTrimmed(t *testing.T) {
	priv := &webErrorsPriv{out: []byte(`[{"path":"/var/log/nginx/error.log","text":"a\nb\nc"},{"path":"/var/log/apache2/error.log","text":"d\nlast line"}]`)}
	got, err := proxySource{s: &Server{cfg: Config{Priv: priv}}}.ErrorLog(t.Context(), 3)
	if err != nil || got != "c\nd\nlast line" {
		t.Fatalf("tail = %q err = %v", got, err)
	}
	if len(priv.got) != 1 || priv.got[0] != "web-errors" {
		t.Fatalf("helper call = %v, want only web-errors", priv.got)
	}
	for name, p := range map[string]proxySource{
		"no helper":  {s: &Server{}},
		"no logs":    {s: &Server{cfg: Config{Priv: &webErrorsPriv{out: []byte(`[]`)}}}},
		"failure":    {s: &Server{cfg: Config{Priv: &webErrorsPriv{err: errors.New("boom")}}}},
		"bad answer": {s: &Server{cfg: Config{Priv: &webErrorsPriv{out: []byte(`nope`)}}}},
	} {
		if _, err := p.ErrorLog(t.Context(), 3); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// The AI-provider surface is gone: sign-in, token and tooling kinds are
// unknown, while auth.confirm (the approval token) stays.
func TestRetiredKindsAreUnknown(t *testing.T) {
	for _, kind := range []string{"auth.status", "auth.login_start", "auth.set_token", "auth.logout", "tooling.check", "tooling.install"} {
		resp := dockerRoundTripConfig(t, Config{Addr: "127.0.0.1:0"}, kind, []byte(`{}`))
		if resp.Kind != "error.unknown_kind" {
			t.Errorf("%s answered %q, want error.unknown_kind", kind, resp.Kind)
		}
	}
}
