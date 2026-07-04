package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/security"
	"github.com/rockclaver/rootmote-agent/internal/tooling"
)

func TestSecurityAIFix_ReturnsToolMissingWhenCLIIsNotInstalled(t *testing.T) {
	sec, err := security.New(security.Config{
		ReadFile: func(string) ([]byte, error) { return nil, errors.New("missing") },
		Glob:     func(string) ([]string, error) { return nil, nil },
		Run: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "sshd" {
				return []byte("passwordauthentication yes\npermitrootlogin no\npermitemptypasswords no\n"), nil
			}
			return nil, errors.New("unavailable")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty-path")
	if err := os.MkdirAll(emptyPath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", emptyPath)
	tools, err := tooling.New(tooling.Config{
		BinDir:    filepath.Join(dir, "bin"),
		NpmPrefix: filepath.Join(dir, "npm"),
	})
	if err != nil {
		t.Fatal(err)
	}
	wsURL, stop := startTestServerWith(t, Config{
		Addr:     "127.0.0.1:0",
		Security: sec,
		Tooling:  tools,
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	payload, _ := json.Marshal(map[string]string{
		"finding_id": "ssh_password_auth_enabled",
		"agent":      "codex",
		"server_id":  "local",
	})
	req, _ := json.Marshal(Frame{ID: "ai-fix", Kind: "security.ai_fix", Payload: payload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Kind != "error.tool_missing" {
		t.Fatalf("kind = %s payload=%s", resp.Kind, string(resp.Payload))
	}
	if !strings.Contains(string(resp.Payload), "codex CLI is not installed") {
		t.Fatalf("payload = %s", string(resp.Payload))
	}
}

func TestSecurityFindingRunbookBody_NoTypedFixOffersRunScript(t *testing.T) {
	finding := security.Finding{
		ID:             "world_readable_etc_shadow",
		Severity:       security.SeverityHigh,
		Category:       "files",
		Title:          "/etc/shadow is world-readable",
		Summary:        "/etc/shadow has mode 0644, exposing password hashes to any local user.",
		Recommendation: "Set /etc/shadow to mode 0640 or stricter, owned by root and the shadow group.",
	}
	body := securityFindingRunbookBody(finding)
	if !strings.Contains(body, "run_script") {
		t.Fatalf("body must offer run_script when no typed fix exists: %s", body)
	}
	if strings.Contains(body, "Do not propose raw shell execution") {
		t.Fatalf("body must not blanket-ban raw shell now that run_script exists: %s", body)
	}
}

func TestSecurityFindingRunbookBody_TypedFixStillPreferredOverScript(t *testing.T) {
	finding := security.Finding{
		ID:       "auditd_inactive",
		Severity: security.SeverityMedium,
		Category: "logging",
		Title:    "auditd is not active",
		Fix: &security.Fix{
			Kind:   security.FixEnableAuditd,
			Label:  "Install and enable auditd",
			Target: "auditd",
		},
	}
	body := securityFindingRunbookBody(finding)
	if !strings.Contains(body, `kind=security.fix params={"kind":"enable_auditd"`) {
		t.Fatalf("body must still surface the typed fix: %s", body)
	}
	if !strings.Contains(body, "Prefer this typed fix over a raw script") {
		t.Fatalf("body must steer the model away from scripting when a typed fix exists: %s", body)
	}
}
