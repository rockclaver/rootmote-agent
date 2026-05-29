package cliauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rockclaver/claver/agent/internal/github"
	"github.com/rockclaver/claver/agent/internal/store"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	vault := github.NewTokenVault(
		filepath.Join(dir, "key"),
		filepath.Join(dir, "blobs"),
	)
	m, err := New(Config{
		BinDir:  filepath.Join(dir, "bin"),
		HomeDir: dir,
		Vault:   vault,
		Store:   st,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return m
}

func TestStatusUnauthenticated(t *testing.T) {
	m := newTestManager(t)
	st, err := m.Status(context.Background(), KindClaude)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.LoggedIn {
		t.Errorf("expected LoggedIn=false, got %+v", st)
	}
	if st.Method != MethodNone {
		t.Errorf("method = %q want none", st.Method)
	}
}

func TestSetTokenRoundtrip(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.SetToken(context.Background(), KindClaude, ModeToken, "sk-ant-secret-XYZ"); err != nil {
		t.Fatalf("set_token: %v", err)
	}
	st, _ := m.Status(context.Background(), KindClaude)
	if !st.LoggedIn || st.Method != MethodToken {
		t.Errorf("post-set status = %+v", st)
	}
	secrets := m.Secrets(KindClaude)
	if got := secrets["CLAUDE_CODE_OAUTH_TOKEN"]; got != "sk-ant-secret-XYZ" {
		t.Errorf("env = %q want sk-ant-secret-XYZ", got)
	}
}

func TestSetClaudeAPIKeyRoundtrip(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.SetToken(context.Background(), KindClaude, ModeAPIKey, "sk-ant-api-secret-XYZ"); err != nil {
		t.Fatalf("set_token: %v", err)
	}
	st, _ := m.Status(context.Background(), KindClaude)
	if !st.LoggedIn || st.Method != MethodAPIKey {
		t.Errorf("post-set status = %+v", st)
	}
	secrets := m.Secrets(KindClaude)
	if got := secrets["ANTHROPIC_API_KEY"]; got != "sk-ant-api-secret-XYZ" {
		t.Errorf("env = %q want sk-ant-api-secret-XYZ", got)
	}
	if got := secrets["CLAUDE_CODE_OAUTH_TOKEN"]; got != "" {
		t.Errorf("oauth env = %q want empty", got)
	}
}

func TestClaudeSubscriptionDoesNotInjectOAuthToken(t *testing.T) {
	m := newTestManager(t)
	path, err := m.cfg.Vault.Seal(KindClaude, "short-lived-access-token")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := m.cfg.Store.PutCliToken(store.CliToken{
		Kind: KindClaude, Method: MethodSubscription, CiphertextPath: path,
	}); err != nil {
		t.Fatalf("put cli token: %v", err)
	}
	if got := m.Secrets(KindClaude); len(got) != 0 {
		t.Errorf("Secrets = %+v want no env injection", got)
	}
}

func TestSetTokenCodexAPIKey(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.SetToken(context.Background(), KindCodex, ModeAPIKey, "sk-openai-XYZ"); err != nil {
		t.Fatalf("set_token: %v", err)
	}
	secrets := m.Secrets(KindCodex)
	if got := secrets["OPENAI_API_KEY"]; got != "sk-openai-XYZ" {
		t.Errorf("env = %q want sk-openai-XYZ", got)
	}
}

func TestSetTokenRejectsBadKind(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.SetToken(context.Background(), "nope", ModeToken, "x"); !errors.Is(err, ErrBadKind) {
		t.Errorf("err = %v want ErrBadKind", err)
	}
}

func TestStatusGitHubFromCLI(t *testing.T) {
	m := newTestManager(t)
	if err := os.MkdirAll(m.cfg.BinDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ghBin := filepath.Join(m.cfg.BinDir, "gh")
	if err := os.WriteFile(ghBin, []byte(`#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "gh version 2.0.0"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  echo '{"hosts":{"github.com":[{"active":true,"user":"octo"}]}}'
  exit 0
fi
exit 1
`), 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := m.Status(context.Background(), KindGitHub)
	if err != nil {
		t.Fatal(err)
	}
	if !st.LoggedIn || st.Method != MethodSubscription || st.Account != "octo" {
		t.Fatalf("status = %+v", st)
	}
}

func TestStartLoginUnsupportedMode(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.StartLogin(context.Background(), KindClaude, "nonsense"); !errors.Is(err, ErrBadMode) {
		t.Errorf("err = %v want ErrBadMode", err)
	}
}

func TestStartLoginSingleFlight(t *testing.T) {
	m := newTestManager(t)
	// Reserve the slot manually to simulate a running login without
	// shelling out to tmux.
	m.mu.Lock()
	m.running[KindClaude] = &Login{ID: "x", Kind: KindClaude}
	m.mu.Unlock()
	if _, err := m.StartLogin(context.Background(), KindClaude, ModeInteractive); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("err = %v want ErrAlreadyRunning", err)
	}
}

func TestScrubSecrets(t *testing.T) {
	cases := []struct{ in, want string }{
		{"prefix sk-1234567890abcdefghijklmnop end", "prefix sk-[REDACTED] end"},
		{"oauth_aaaaaaaaaaaaaaaaaaaaaaa more", "oauth_[REDACTED] more"},
		{"nothing here", "nothing here"},
	}
	for _, tc := range cases {
		if got := scrubSecrets(tc.in); got != tc.want {
			t.Errorf("scrubSecrets(%q) = %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestStripANSI(t *testing.T) {
	in := "\x1b[31mhello\x1b[0m world"
	if got := stripANSI(in); got != "hello world" {
		t.Errorf("stripANSI = %q want %q", got, "hello world")
	}
}

func TestCleanTerminalLineDropsControlBytes(t *testing.T) {
	in := "\x1b[?7lWelcome\x00 to\x1f Claude\x7f Code\n"
	if got := cleanTerminalLine(in); got != "Welcome to Claude Code\n" {
		t.Errorf("cleanTerminalLine = %q", got)
	}
}

func TestIsClaudeFirstRunSetup(t *testing.T) {
	cases := []string{
		"Let's get started.\nChoose the text style that looks best with your terminal",
		"Syntax theme: Monokai Extended (ctrl+t to disable)",
		"WelcometoClaudeCodev2.1.156 Let'sgetstarted",
	}
	for _, tc := range cases {
		if !isClaudeFirstRunSetup(tc) {
			t.Errorf("expected setup prompt for %q", tc)
		}
	}
	if isClaudeFirstRunSetup("Open https://claude.ai/oauth to continue") {
		t.Error("oauth URL should not be treated as setup")
	}
}

// Mirrors of the regexes used in driveLogin so we can sanity-check them
// without spinning up tmux. If these drift apart we'll see it in real use,
// but at least the patterns themselves are pinned by name.
var (
	urlReTest  = regexp.MustCompile(`https?://[^\s)>"']+`)
	codeReTest = regexp.MustCompile(`(?i)code[: ]+([A-Z0-9-]{6,})`)
)

func TestURLAndCodeExtraction(t *testing.T) {
	cases := []struct {
		line, url, code string
	}{
		{"open https://claude.ai/oauth/authorize?code=abc to continue", "https://claude.ai/oauth/authorize?code=abc", ""},
		{"Go to https://chatgpt.com/login and enter code: ABCD-1234", "https://chatgpt.com/login", "ABCD-1234"},
	}
	for _, tc := range cases {
		u := urlReTest.FindString(tc.line)
		if u != tc.url {
			t.Errorf("url(%q) = %q want %q", tc.line, u, tc.url)
		}
		var code string
		if m := codeReTest.FindStringSubmatch(tc.line); len(m) > 1 {
			code = m[1]
		}
		if code != tc.code {
			t.Errorf("code(%q) = %q want %q", tc.line, code, tc.code)
		}
	}
}

func TestParseAccountEmail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(p, []byte(`{"oauth":{"email":"a@b.co","access_token":"t"}}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := parseAccount(KindClaude, p); got != "a@b.co" {
		t.Errorf("parseAccount = %q", got)
	}
}

func TestIsPublicURL(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"https://chatgpt.com/oauth/login?x=1", true},
		{"https://claude.ai/oauth?code=abc", true},
		{"http://localhost:1455/callback", false},
		{"http://127.0.0.1:1455/callback", false},
		{"http://192.168.1.5/", false},
		{"http://10.0.0.1/", false},
		{"http://172.16.5.5/", false},
		{"ftp://example.com/", false},
		{"https://", false},
	}
	for _, tc := range cases {
		if got := isPublicURL(tc.in); got != tc.want {
			t.Errorf("isPublicURL(%q) = %v want %v", tc.in, got, tc.want)
		}
	}
}

func TestExtractCallbackTarget(t *testing.T) {
	oauth := "https://chatgpt.com/oauth/authorize?client_id=x&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fcallback&state=abc"
	host, port, path, ok := extractCallbackTarget(oauth)
	if !ok {
		t.Fatal("expected ok")
	}
	if host != "localhost" || port != 1455 || path != "/callback" {
		t.Errorf("got host=%q port=%d path=%q", host, port, path)
	}
}

func TestExtractCallbackTargetDefaultPort(t *testing.T) {
	oauth := "https://x/oauth?redirect_uri=https%3A%2F%2Fapi.example.com%2Fcb"
	_, port, _, ok := extractCallbackTarget(oauth)
	if !ok {
		t.Fatal("expected ok")
	}
	if port != 443 {
		t.Errorf("port = %d want 443", port)
	}
}

func TestExtractCallbackTargetMissing(t *testing.T) {
	if _, _, _, ok := extractCallbackTarget("https://nope/?x=1"); ok {
		t.Error("expected !ok when redirect_uri absent")
	}
}

func TestExtractTokenClaudeOAuth(t *testing.T) {
	body := []byte(`{"oauth":{"access_token":"abc123"}}`)
	if got := extractToken(KindClaude, body); got != "abc123" {
		t.Errorf("extractToken = %q want abc123", got)
	}
}

func TestLoginCommandArgs(t *testing.T) {
	if got := loginCommandArgs(KindClaude, "/bin/claude"); got[0] != "/bin/claude" || got[1] != "auth" || got[2] != "login" {
		t.Errorf("claude args = %#v", got)
	}
	if got := loginCommandArgs(KindCodex, "/bin/codex"); got[0] != "/bin/codex" || got[1] != "login" {
		t.Errorf("codex args = %#v", got)
	}
	if got := strings.Join(loginCommandArgs(KindGitHub, "/bin/gh"), " "); got != "/bin/gh auth login --hostname github.com --git-protocol https --scopes repo,read:org,workflow --web" {
		t.Errorf("github args = %q", got)
	}
}
