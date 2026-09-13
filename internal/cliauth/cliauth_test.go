package cliauth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rockclaver/rootmote-agent/internal/github"
	"github.com/rockclaver/rootmote-agent/internal/store"
)

// TestMain pins PATH to an empty directory so resolveBin can only find the
// stub CLIs a test explicitly installs in BinDir. Without it, whichever real
// claude/codex/gh happens to be installed on the machine running the tests
// leaks into Status() — making results depend on the developer's own login
// state and paying seconds of Node startup per probe, which under a loaded
// `go test ./...` blows the probes' internal timeouts.
func TestMain(m *testing.M) {
	empty, err := os.MkdirTemp("", "cliauth-empty-path")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("PATH", empty); err != nil {
		panic(err)
	}
	// Pay the process's one-time fork/exec warm-up cost here rather than
	// inside a test: the CLI probes in Status bound themselves with a few
	// seconds, and under a loaded `go test ./...` the very first subprocess a
	// test binary spawns can take longer than that to come up.
	_ = exec.Command("/bin/sh", "-c", "exit 0").Run()
	code := m.Run()
	_ = os.RemoveAll(empty)
	os.Exit(code)
}

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

func TestStatusClaudeUsesCLIAuthStatusWithConfiguredHome(t *testing.T) {
	m := newTestManager(t)
	installStub(t, m, "claude", `if [ "$1" = "--version" ]; then
  echo "claude-stub 1.0.0"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  : > "$HOME/home-marker"
  printf '{"loggedIn":true,"authMethod":"claude.ai","email":"dev@example.com","subscriptionType":"pro"}'
  exit 0
fi
exit 1
`)
	marker := filepath.Join(m.cfg.HomeDir, "home-marker")
	st, err := m.Status(context.Background(), KindClaude)
	if err != nil {
		t.Fatal(err)
	}
	if !st.LoggedIn || st.Method != MethodSubscription || st.Account != "dev@example.com" {
		t.Fatalf("status = %+v", st)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("configured HOME was not used: %v", err)
	}
}

func TestTmuxEnvFlagsCarryConfiguredHomeAndPath(t *testing.T) {
	m := newTestManager(t)
	flags := strings.Join(m.tmuxEnvFlags(), "\n")
	if !strings.Contains(flags, "HOME="+m.cfg.HomeDir) {
		t.Fatalf("flags missing HOME: %q", flags)
	}
	if !strings.Contains(flags, "CLAUDE_CONFIG_DIR="+filepath.Join(m.cfg.HomeDir, ".claude")) {
		t.Fatalf("flags missing CLAUDE_CONFIG_DIR: %q", flags)
	}
	if !strings.Contains(flags, "CODEX_HOME="+filepath.Join(m.cfg.HomeDir, ".codex")) {
		t.Fatalf("flags missing CODEX_HOME: %q", flags)
	}
	if !strings.Contains(flags, "PATH="+m.cfg.BinDir) {
		t.Fatalf("flags missing BinDir PATH prefix: %q", flags)
	}
}

func TestEnvForCaptiveStripsAmbientAnthropicCredentials(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "bad")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "bad")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "bad")
	t.Setenv("CODEX_HOME", "/tmp/wrong-codex-home")
	m := newTestManager(t)
	env := strings.Join(m.envForCaptive(), "\n")
	for _, forbidden := range []string{
		"ANTHROPIC_API_KEY=bad",
		"ANTHROPIC_AUTH_TOKEN=bad",
		"CLAUDE_CODE_OAUTH_TOKEN=bad",
		"CODEX_HOME=/tmp/wrong-codex-home",
	} {
		if strings.Contains(env, forbidden) {
			t.Fatalf("env leaked %s: %q", forbidden, env)
		}
	}
	if !strings.Contains(env, "CLAUDE_CONFIG_DIR="+filepath.Join(m.cfg.HomeDir, ".claude")) {
		t.Fatalf("env missing CLAUDE_CONFIG_DIR: %q", env)
	}
	if !strings.Contains(env, "CODEX_HOME="+filepath.Join(m.cfg.HomeDir, ".codex")) {
		t.Fatalf("env missing CODEX_HOME: %q", env)
	}
}

func TestNewSeedsClaudeOnboarding(t *testing.T) {
	m := newTestManager(t)
	path := filepath.Join(m.claudeConfigDir(), ".claude.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded config: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal seeded config: %v", err)
	}
	if done, _ := doc["hasCompletedOnboarding"].(bool); !done {
		t.Fatalf("hasCompletedOnboarding not set: %v", doc)
	}
}

func TestEnsureClaudeOnboardedPreservesExistingState(t *testing.T) {
	m := newTestManager(t)
	path := filepath.Join(m.claudeConfigDir(), ".claude.json")
	// Simulate Claude having written its own state with onboarding not yet done.
	seed := []byte(`{"firstStartTime":"2026-01-01T00:00:00Z","migrationVersion":13}`)
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	m.ensureClaudeOnboarded()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if done, _ := doc["hasCompletedOnboarding"].(bool); !done {
		t.Fatalf("onboarding flag not merged: %v", doc)
	}
	if doc["migrationVersion"] == nil || doc["firstStartTime"] == nil {
		t.Fatalf("existing Claude state was clobbered: %v", doc)
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

func TestLogoutClearsLocalCredentialFilesAndVaultPointers(t *testing.T) {
	m := newTestManager(t)
	cases := []struct {
		kind string
		path string
		body string
	}{
		{
			kind: KindClaude,
			path: filepath.Join(m.cfg.HomeDir, ".claude", ".credentials.json"),
			body: `{"oauth":{"access_token":"stale"}}`,
		},
		{
			kind: KindCodex,
			path: filepath.Join(m.cfg.HomeDir, ".codex", "auth.json"),
			body: `{"tokens":{"access_token":"stale"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			if err := os.MkdirAll(filepath.Dir(tc.path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tc.path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			sealed, err := m.cfg.Vault.Seal(tc.kind, "stale")
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			if err := m.cfg.Store.PutCliToken(store.CliToken{
				Kind: tc.kind, Method: MethodSubscription, CiphertextPath: sealed,
			}); err != nil {
				t.Fatalf("put cli token: %v", err)
			}
			if err := m.Logout(context.Background(), tc.kind); err != nil {
				t.Fatalf("logout: %v", err)
			}
			if _, err := os.Stat(tc.path); !os.IsNotExist(err) {
				t.Fatalf("credential file still exists: %v", err)
			}
			if _, err := m.cfg.Store.GetCliToken(tc.kind); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("cli token still exists: %v", err)
			}
		})
	}
}

func TestStatusCodexAuthJSONMissingAfterCliLogoutClearsStalePointer(t *testing.T) {
	m := newTestManager(t)
	sealed, err := m.cfg.Vault.Seal(KindCodex, `{"tokens":{"access_token":"stale"}}`)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := m.cfg.Store.PutCliToken(store.CliToken{
		Kind: KindCodex, Method: MethodAuthJSON, CiphertextPath: sealed,
	}); err != nil {
		t.Fatalf("put cli token: %v", err)
	}

	st, err := m.Status(context.Background(), KindCodex)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.LoggedIn {
		t.Fatalf("status = %+v, want logged out when auth.json is gone", st)
	}
	if _, err := m.cfg.Store.GetCliToken(KindCodex); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stale cli token still exists: %v", err)
	}
}

func TestStatusCodexAPIKeySurvivesMissingAuthJSON(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.SetToken(context.Background(), KindCodex, ModeAPIKey, "sk-openai-XYZ"); err != nil {
		t.Fatalf("set_token: %v", err)
	}
	st, err := m.Status(context.Background(), KindCodex)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.LoggedIn || st.Method != MethodAPIKey {
		t.Fatalf("status = %+v, want api-key login independent of auth.json", st)
	}
}

func TestSetTokenCodexFileRejectsInvalidAuthJSON(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.SetToken(context.Background(), KindCodex, ModeFile, "not-json"); err == nil {
		t.Fatal("expected invalid auth.json to be rejected")
	}
	if _, err := os.Stat(filepath.Join(m.cfg.HomeDir, ".codex", "auth.json")); !os.IsNotExist(err) {
		t.Fatalf("auth.json should not be written after invalid paste: %v", err)
	}
}

func TestLogoutCancelsRunningLogin(t *testing.T) {
	m := newTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	login := &Login{ID: "login-1", Kind: KindCodex, cancel: cancel}
	m.mu.Lock()
	m.running[KindCodex] = login
	m.byID[login.ID] = login
	m.mu.Unlock()

	if err := m.Logout(context.Background(), KindCodex); err != nil {
		t.Fatalf("logout: %v", err)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("running login was not cancelled")
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
	installStub(t, m, "gh", `if [ "$1" = "--version" ]; then
  echo "gh version 2.0.0"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "token" ]; then
  echo "gho_test"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  echo "Logged in to github.com account octo (/tmp/hosts.yml)"
  exit 0
fi
exit 1
`)
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
		"Select login method:\n1. Claude account with subscription\n2. Anthropic Console account",
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

func TestGitHubPrompts(t *testing.T) {
	if !isGitHubGitCredentialPrompt("? Authenticate Git with your GitHub credentials? (Y/n)") {
		t.Fatal("expected GitHub git credential prompt")
	}
	if !isGitHubBrowserPrompt("Press Enter to open github.com in your browser...") {
		t.Fatal("expected GitHub browser prompt")
	}
	if isGitHubBrowserPrompt("Open https://github.com/login/device") {
		t.Fatal("plain URL should not be treated as browser prompt")
	}
	if !isGitHubLoginSuccess("✓ Logged in as rockclaver") {
		t.Fatal("expected GitHub login success")
	}
	if got := parseGitHubLoginSuccessAccount("✓ Logged in as rockclaver"); got != "rockclaver" {
		t.Fatalf("account = %q", got)
	}
	if got := parseGitHubStatusAccount("Logged in to github.com account rockclaver (/var/lib/rootmote/.config/gh/hosts.yml)"); got != "rockclaver" {
		t.Fatalf("status account = %q", got)
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
	if got := strings.Join(loginCommandArgs(KindCodex, "/bin/codex"), " "); got != "/bin/codex login --device-auth" {
		t.Errorf("codex args = %#v", got)
	}
	if got := strings.Join(loginCommandArgs(KindGitHub, "/bin/gh"), " "); got != "/bin/gh auth login --hostname github.com --git-protocol https --scopes repo,read:org,workflow --web" {
		t.Errorf("github args = %q", got)
	}
}

func TestAuthCodeFromLineRecognizesCodexDeviceCode(t *testing.T) {
	codeRE := regexp.MustCompile(`(?i)\bcode\s*:\s*([A-Z0-9-]{6,})\b`)
	deviceCodeRE := regexp.MustCompile(`\b[A-Z0-9]{4}-[A-Z0-9]{4,8}\b`)
	cases := map[string]string{
		"Code: ABCD-1234": "ABCD-1234",
		"   X2QN-J9SFT":   "X2QN-J9SFT",
		"Follow these steps to sign in with ChatGPT using device code authorization:":                                               "",
		"Follow these steps to sign in with ChatGPT using device code authorization:\n\n2. Enter this one-time code\n   X2QN-J9SFT": "X2QN-J9SFT",
		"Enter this one-time code ABC123": "",
		"no code here":                    "",
	}
	for line, want := range cases {
		if got := authCodeFromLine(line, codeRE, deviceCodeRE); got != want {
			t.Errorf("authCodeFromLine(%q) = %q want %q", line, got, want)
		}
	}
}

// installStub writes an executable `#!/bin/sh` stub named after a CLI into the
// Manager's BinDir, where resolveBin finds it ahead of anything on PATH, and
// then runs it once with no arguments.
//
// That warm-up run is load-bearing on macOS: the first exec of a newly created
// executable pays a code-signing/quarantine scan that costs hundreds of
// milliseconds idle and seconds on a saturated machine. The probes in Status
// bound themselves to a few seconds, so paying that cost here — untimed —
// keeps the tests measuring the auth logic instead of the host's spawn latency.
func installStub(t *testing.T, m *Manager, name, script string) {
	t.Helper()
	if err := os.MkdirAll(m.cfg.BinDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(m.cfg.BinDir, name)
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(bin).Run(); err == nil {
		t.Fatalf("%s stub should exit non-zero when called with no arguments", name)
	}
}

func seedClaudeSubscription(t *testing.T, m *Manager) {
	t.Helper()
	credPath := filepath.Join(m.cfg.HomeDir, ".claude", ".credentials.json")
	if err := os.MkdirAll(filepath.Dir(credPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credPath, []byte(`{"oauth":{"access_token":"stale"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sealed, err := m.cfg.Vault.Seal(KindClaude, "stale")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := m.cfg.Store.PutCliToken(store.CliToken{
		Kind: KindClaude, Method: MethodSubscription, CiphertextPath: sealed,
	}); err != nil {
		t.Fatalf("put cli token: %v", err)
	}
}

// TestStatusClaudeSubscriptionVetoedByExpiredCLIStatus proves that a stale
// vault pointer plus an on-disk credential file (which alone would report
// LoggedIn=true) is overridden by an authoritative "loggedIn:false" from
// `claude auth status --json`: a refresh token can expire without the
// credential file disappearing, so the file-existence check alone is not
// enough to catch it.
func TestStatusClaudeSubscriptionVetoedByExpiredCLIStatus(t *testing.T) {
	m := newTestManager(t)
	seedClaudeSubscription(t, m)
	installStub(t, m, "claude", `if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  printf '{"loggedIn":false}'
  exit 0
fi
exit 1
`)
	st, err := m.Status(context.Background(), KindClaude)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.LoggedIn {
		t.Fatalf("status = %+v, want LoggedIn=false when CLI reports expired credential", st)
	}
	if _, err := m.cfg.Store.GetCliToken(KindClaude); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stale cli token still exists: %v", err)
	}
}

// TestStatusClaudeSubscriptionSurvivesUnanswerableCLI proves the same setup
// keeps LoggedIn=true when the `claude` binary is unavailable or errors: no
// answer from the CLI must not be treated as logged out, or a box without the
// CLI on PATH would force a pointless re-login.
func TestStatusClaudeSubscriptionSurvivesUnanswerableCLI(t *testing.T) {
	for _, tc := range []struct {
		name string
		stub string // empty ⇒ install no binary at all
	}{
		{name: "binary absent"},
		{name: "binary errors", stub: "exit 1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			seedClaudeSubscription(t, m)
			if tc.stub != "" {
				installStub(t, m, "claude", tc.stub)
			}
			st, err := m.Status(context.Background(), KindClaude)
			if err != nil {
				t.Fatalf("status: %v", err)
			}
			if !st.LoggedIn || st.Method != MethodSubscription {
				t.Fatalf("status = %+v, want LoggedIn=true (CLI gave no answer)", st)
			}
			if _, err := m.cfg.Store.GetCliToken(KindClaude); err != nil {
				t.Fatalf("vault pointer was dropped without an authoritative answer: %v", err)
			}
		})
	}
}

// TestStatusClaudeTokenNeverVetoedByCLI proves a MethodToken credential is
// never re-checked against the CLI: token/api_key credentials are injected as
// env vars that envForCaptive() doesn't necessarily carry, so `claude auth
// status` could otherwise misreport a perfectly good token credential as
// logged out.
func TestStatusClaudeTokenNeverVetoedByCLI(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.SetToken(context.Background(), KindClaude, ModeToken, "sk-ant-secret-XYZ"); err != nil {
		t.Fatalf("set_token: %v", err)
	}
	installStub(t, m, "claude", `if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  printf '{"loggedIn":false}'
  exit 0
fi
exit 1
`)
	st, err := m.Status(context.Background(), KindClaude)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.LoggedIn || st.Method != MethodToken {
		t.Fatalf("status = %+v, want LoggedIn=true (token credential never vetoed by CLI)", st)
	}
}
