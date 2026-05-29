// Package cliauth drives the interactive login flows of the Claude Code,
// Codex, and GitHub CLIs on a headless VPS, so the mobile app can authenticate a
// user's subscription without an on-server browser.
//
// Strategy: spawn the CLI inside a captive tmux pane, tail its output via
// `tmux pipe-pane`, scrape the auth URL the CLI prints, and signal completion
// when the CLI writes its credential file or the GitHub CLI reports an active
// login. Claude/Codex tokens are persisted in the agent's AES-GCM vault; on
// subsequent session.start the agent injects them via `tmux new-session -e` so
// the CLI inherits them.
package cliauth

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rockclaver/claver/agent/internal/github"
	"github.com/rockclaver/claver/agent/internal/store"
)

// Kinds.
const (
	KindClaude = "claude"
	KindCodex  = "codex"
	KindGitHub = "github"
)

// Modes.
const (
	ModeInteractive = "interactive"
	ModeToken       = "token"   // long-lived CLAUDE_CODE_OAUTH_TOKEN or OPENAI_API_KEY
	ModeFile        = "file"    // raw auth.json paste (Codex)
	ModeAPIKey      = "api_key" // raw API key paste
)

// Methods (how a stored credential was obtained).
const (
	MethodSubscription = "subscription"
	MethodToken        = "token"
	MethodAPIKey       = "api_key"
	MethodAuthJSON     = "auth_json"
	MethodNone         = "none"
)

// Errors surfaced to the WS layer.
var (
	ErrAlreadyRunning = errors.New("cliauth: login already running for this kind")
	ErrUnknownLogin   = errors.New("cliauth: unknown login id")
	ErrBadKind        = errors.New("cliauth: unsupported kind")
	ErrBadMode        = errors.New("cliauth: unsupported mode")
	ErrTimeout        = errors.New("cliauth: login timed out")
	ErrCancelled      = errors.New("cliauth: login cancelled")
)

// Status reports auth state for one CLI.
type Status struct {
	Kind     string `json:"kind"`
	LoggedIn bool   `json:"logged_in"`
	Method   string `json:"method"`
	Account  string `json:"account,omitempty"`
	Version  string `json:"version,omitempty"`
}

// EventType enumerates emitted event kinds during a login.
type EventType string

const (
	EvtProgress       EventType = "progress"
	EvtURL            EventType = "url"
	EvtPromptPaste    EventType = "prompt_paste"
	EvtCallbackTarget EventType = "callback_target"
	EvtDone           EventType = "done"
)

// Event is one update from a running login.
type Event struct {
	Type     EventType
	Stream   string // "stdout" | "system" (progress only)
	Line     string // progress only
	URL      string // url only
	UserCode string // url only (may be empty)
	// callback_target only — tells the mobile webview which redirect to
	// intercept and how to surface the captured query back to the agent.
	CallbackHost string
	CallbackPort int
	CallbackPath string
	OK           bool   // done only
	Error        string // done only (when !OK)
	Status       Status // done only (final state)
}

// Login is a handle on an in-flight interactive login.
type Login struct {
	ID     string
	Kind   string
	Events <-chan Event

	// callbackTarget is set after we parse the OAuth URL's redirect_uri so
	// later auth.relay_callback calls can be validated against the
	// in-flight login.
	callbackHost string
	callbackPort int
	callbackPath string

	// internal
	events      chan Event
	sessionName string
	fifo        string
	cancel      context.CancelFunc
	closeOnce   sync.Once
}

// Config configures the Manager.
type Config struct {
	// BinDir is prepended to PATH for the captive CLI process so the
	// freshly-installed `claude`/`codex` resolves.
	BinDir string
	// HomeDir is the agent user's home (e.g. /var/lib/claver). Used to
	// locate the CLIs' credential files.
	HomeDir string
	// Vault encrypts stored credentials.
	Vault *github.TokenVault
	// Store holds the cli_tokens pointer rows.
	Store *store.Store
	// Timeout is the hard cap on a single interactive login. Default 5m.
	Timeout time.Duration
}

// Manager owns the captive processes and credential store.
type Manager struct {
	cfg Config

	mu      sync.Mutex
	running map[string]*Login // kind -> Login (single-flight per kind)
	byID    map[string]*Login // id -> Login (lookup for Send/Cancel)
}

// New constructs a Manager. The caller is expected to have already created
// HomeDir; Manager does not chown or chmod it.
func New(cfg Config) (*Manager, error) {
	if cfg.HomeDir == "" {
		return nil, errors.New("cliauth: HomeDir required")
	}
	if cfg.Vault == nil {
		return nil, errors.New("cliauth: Vault required")
	}
	if cfg.Store == nil {
		return nil, errors.New("cliauth: Store required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Minute
	}
	return &Manager{
		cfg:     cfg,
		running: make(map[string]*Login),
		byID:    make(map[string]*Login),
	}, nil
}

// credPath returns the on-disk credential path for one kind.
func (m *Manager) credPath(kind string) string {
	switch kind {
	case KindClaude:
		return filepath.Join(m.cfg.HomeDir, ".claude", ".credentials.json")
	case KindCodex:
		return filepath.Join(m.cfg.HomeDir, ".codex", "auth.json")
	}
	return ""
}

// Status reports whether the named CLI is logged in. It checks the vault
// first (explicit token/api_key) and falls back to the CLI's credential file.
func (m *Manager) Status(ctx context.Context, kind string) (Status, error) {
	if kind != KindClaude && kind != KindCodex && kind != KindGitHub {
		return Status{}, ErrBadKind
	}
	out := Status{Kind: kind, Method: MethodNone}
	if kind == KindGitHub {
		return m.githubStatus(ctx)
	}

	if row, err := m.cfg.Store.GetCliToken(kind); err == nil {
		out.LoggedIn = true
		out.Method = row.Method
		out.Account = row.Account
	}

	if !out.LoggedIn {
		if p := m.credPath(kind); p != "" {
			if _, err := os.Stat(p); err == nil {
				out.LoggedIn = true
				out.Method = MethodSubscription
				if acct := parseAccount(kind, p); acct != "" {
					out.Account = acct
				}
			}
		}
	}

	if v := m.probeVersion(ctx, kind); v != "" {
		out.Version = v
	}
	return out, nil
}

func (m *Manager) probeVersion(ctx context.Context, kind string) string {
	bin := m.resolveBin(kind)
	if bin == "" {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	return line
}

func (m *Manager) resolveBin(kind string) string {
	binName := kind
	if kind == KindGitHub {
		binName = "gh"
	}
	candidate := filepath.Join(m.cfg.BinDir, binName)
	if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
		return candidate
	}
	if p, err := exec.LookPath(binName); err == nil {
		return p
	}
	return ""
}

func (m *Manager) githubStatus(ctx context.Context) (Status, error) {
	out := Status{Kind: KindGitHub, Method: MethodNone}
	if v := m.probeVersion(ctx, KindGitHub); v != "" {
		out.Version = v
	}
	bin := m.resolveBin(KindGitHub)
	if bin == "" {
		return out, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(cctx, bin, "auth", "status", "--active", "--hostname", "github.com", "--json", "hosts").CombinedOutput()
	if err != nil {
		return out, nil
	}
	account := activeGitHubAccount(raw)
	if account == "" {
		return out, nil
	}
	out.LoggedIn = true
	out.Method = MethodSubscription
	out.Account = account
	return out, nil
}

func activeGitHubAccount(raw []byte) string {
	var doc struct {
		Hosts map[string]json.RawMessage `json:"hosts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	host := doc.Hosts["github.com"]
	if len(host) == 0 {
		return ""
	}
	var decoded any
	if err := json.Unmarshal(host, &decoded); err != nil {
		return ""
	}
	return findGitHubAccount(decoded)
}

func findGitHubAccount(v any) string {
	switch x := v.(type) {
	case map[string]any:
		if active, ok := x["active"].(bool); ok && !active {
			return ""
		}
		for _, key := range []string{"user", "username", "login"} {
			if s, ok := x[key].(string); ok && s != "" {
				return s
			}
		}
		for _, child := range x {
			if account := findGitHubAccount(child); account != "" {
				return account
			}
		}
	case []any:
		for _, child := range x {
			if account := findGitHubAccount(child); account != "" {
				return account
			}
		}
	}
	return ""
}

// parseAccount makes a best-effort extraction of the logged-in account from
// the CLI's credential file. Returns "" on any failure.
func parseAccount(kind, path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return ""
	}
	// Common keys we've observed; tolerate any of them.
	for _, k := range []string{"email", "account", "login", "user", "username"} {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	if oauth, ok := m["oauth"].(map[string]any); ok {
		for _, k := range []string{"email", "account", "user", "username"} {
			if v, ok := oauth[k].(string); ok && v != "" {
				return v
			}
		}
	}
	_ = kind
	return ""
}

// StartLogin spawns a captive CLI login process and returns a handle.
// The Events channel closes after EvtDone.
func (m *Manager) StartLogin(parent context.Context, kind, mode string) (*Login, error) {
	if kind != KindClaude && kind != KindCodex && kind != KindGitHub {
		return nil, ErrBadKind
	}
	if mode != ModeInteractive {
		return nil, ErrBadMode
	}
	m.mu.Lock()
	if m.running[kind] != nil {
		m.mu.Unlock()
		return nil, ErrAlreadyRunning
	}
	bin := m.resolveBin(kind)
	if bin == "" {
		m.mu.Unlock()
		return nil, fmt.Errorf("cliauth: %s not installed", kind)
	}
	id := randID()
	ctx, cancel := context.WithTimeout(parent, m.cfg.Timeout)
	ev := make(chan Event, 64)
	login := &Login{
		ID:          id,
		Kind:        kind,
		Events:      ev,
		events:      ev,
		sessionName: "claver-auth-" + kind + "-" + id,
		fifo:        filepath.Join(os.TempDir(), "claver-auth-"+id+".pipe"),
		cancel:      cancel,
	}
	m.running[kind] = login
	m.byID[id] = login
	m.mu.Unlock()

	go m.driveLogin(ctx, login, bin)
	return login, nil
}

// Send forwards text into the captive pane. Used to feed the paste-back
// code in the Claude flow.
func (m *Manager) Send(ctx context.Context, loginID, text string, enter bool) error {
	m.mu.Lock()
	login := m.byID[loginID]
	m.mu.Unlock()
	if login == nil {
		return ErrUnknownLogin
	}
	target := login.sessionName + ":0.0"
	if text != "" {
		if out, err := exec.CommandContext(ctx, "tmux", "send-keys", "-t", target, "-l", text).CombinedOutput(); err != nil {
			return fmt.Errorf("tmux send-keys: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if enter {
		if out, err := exec.CommandContext(ctx, "tmux", "send-keys", "-t", target, "Enter").CombinedOutput(); err != nil {
			return fmt.Errorf("tmux send-keys Enter: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Cancel aborts an in-flight login.
func (m *Manager) Cancel(loginID string) error {
	m.mu.Lock()
	login := m.byID[loginID]
	m.mu.Unlock()
	if login == nil {
		return ErrUnknownLogin
	}
	login.cancel()
	return nil
}

// SetToken stores an opaque credential the user pasted into the app.
// For Codex `file` mode, value is the verbatim auth.json contents and is
// also written to ~/.codex/auth.json so the CLI itself picks it up.
func (m *Manager) SetToken(ctx context.Context, kind, mode, value string) (Status, error) {
	if kind != KindClaude && kind != KindCodex {
		return Status{}, ErrBadKind
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return Status{}, errors.New("cliauth: empty value")
	}
	method := MethodToken
	switch mode {
	case ModeToken:
		method = MethodToken
	case ModeAPIKey:
		method = MethodAPIKey
	case ModeFile:
		method = MethodAuthJSON
	default:
		return Status{}, ErrBadMode
	}

	if mode == ModeFile {
		if kind != KindCodex {
			return Status{}, errors.New("cliauth: file mode only supported for codex")
		}
		dir := filepath.Join(m.cfg.HomeDir, ".codex")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return Status{}, fmt.Errorf("cliauth: mkdir codex home: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "auth.json"), []byte(value), 0o600); err != nil {
			return Status{}, fmt.Errorf("cliauth: write auth.json: %w", err)
		}
	}
	if kind == KindClaude && mode != ModeToken && mode != ModeAPIKey {
		return Status{}, errors.New("cliauth: claude supports token or api_key mode")
	}

	path, err := m.cfg.Vault.Seal(kind, value)
	if err != nil {
		return Status{}, fmt.Errorf("cliauth: seal: %w", err)
	}
	if err := m.cfg.Store.PutCliToken(store.CliToken{
		Kind: kind, Method: method, CiphertextPath: path,
	}); err != nil {
		return Status{}, fmt.Errorf("cliauth: store: %w", err)
	}
	return m.Status(ctx, kind)
}

// Logout removes stored credentials and asks the CLI to forget its session.
func (m *Manager) Logout(ctx context.Context, kind string) error {
	if kind != KindClaude && kind != KindCodex && kind != KindGitHub {
		return ErrBadKind
	}
	if kind == KindGitHub {
		if bin := m.resolveBin(kind); bin != "" {
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_ = exec.CommandContext(cctx, bin, "auth", "logout", "--hostname", "github.com").Run()
		}
		return nil
	}
	if kind == KindCodex {
		if bin := m.resolveBin(kind); bin != "" {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_ = exec.CommandContext(cctx, bin, "logout").Run()
		}
	} else if kind == KindClaude {
		if bin := m.resolveBin(kind); bin != "" {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_ = exec.CommandContext(cctx, bin, "auth", "logout").Run()
		}
	}
	if p := m.credPath(kind); p != "" {
		_ = os.Remove(p)
	}
	_ = m.cfg.Store.DeleteCliToken(kind)
	return nil
}

// Secrets returns env-var assignments to inject into a tmux session for a
// given agent kind. Used by sessions.TmuxRuntime at session.start.
func (m *Manager) Secrets(kind string) map[string]string {
	row, err := m.cfg.Store.GetCliToken(kind)
	if err != nil {
		return nil
	}
	plain, err := m.cfg.Vault.Open(kind, row.CiphertextPath)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	switch kind {
	case KindClaude:
		switch row.Method {
		case MethodToken:
			out["CLAUDE_CODE_OAUTH_TOKEN"] = plain
		case MethodAPIKey:
			out["ANTHROPIC_API_KEY"] = plain
		}
	case KindCodex:
		switch row.Method {
		case MethodAPIKey:
			out["OPENAI_API_KEY"] = plain
			// auth_json and subscription: the file on disk is canonical;
			// no env injection.
		}
	}
	return out
}

// driveLogin runs the captive process to completion and emits events.
func (m *Manager) driveLogin(ctx context.Context, login *Login, bin string) {
	defer m.cleanupLogin(login)

	args := []string{"new-session", "-d", "-s", login.sessionName, "-c", m.cfg.HomeDir}
	args = append(args, loginCommandArgs(login.Kind, bin)...)
	cmd := exec.CommandContext(ctx, "tmux", args...)
	cmd.Env = m.envForCaptive()
	if out, err := cmd.CombinedOutput(); err != nil {
		login.emitDone(false, fmt.Errorf("start: %w: %s", err, strings.TrimSpace(string(out))).Error(), Status{Kind: login.Kind})
		return
	}

	// Wire pipe-pane.
	_ = os.Remove(login.fifo)
	if err := syscall.Mkfifo(login.fifo, 0o600); err != nil {
		login.emitDone(false, "mkfifo: "+err.Error(), Status{Kind: login.Kind})
		_ = killTmux(login.sessionName)
		return
	}
	pipeCmd := "cat > " + shellQuote(login.fifo)
	if out, err := exec.CommandContext(ctx, "tmux", "pipe-pane", "-t", login.sessionName+":0.0", "-o", pipeCmd).CombinedOutput(); err != nil {
		login.emitDone(false, fmt.Sprintf("pipe-pane: %s: %s", err, strings.TrimSpace(string(out))), Status{Kind: login.Kind})
		_ = killTmux(login.sessionName)
		return
	}

	// Track the credential file mtime so we can detect completion even when
	// scraping output fails to surface a sentinel line.
	credBaseline := mtime(m.credPath(login.Kind))

	// Reader goroutine for pipe output.
	urlSeen := false
	pasteSeen := false
	claudeSetupAdvanced := false
	lines := make(chan string, 256)
	go func() {
		defer close(lines)
		f, err := os.OpenFile(login.fifo, os.O_RDONLY, 0)
		if err != nil {
			return
		}
		defer f.Close()
		br := bufio.NewReader(f)
		for {
			raw, err := br.ReadString('\n')
			if raw != "" {
				lines <- raw
			}
			if err != nil {
				return
			}
		}
	}()

	// Exclude control bytes and common bracket/quote terminators so an OSC 8
	// hyperlink (which we mostly strip above, but be belt-and-braces) or a
	// markdown-style "(...)" wrapping doesn't end up baked into the URL.
	urlRE := regexp.MustCompile(`https?://[^\s)\]>"'\x00-\x1f\x7f]+`)
	pasteRE := regexp.MustCompile(`(?i)(paste.{0,20}code|enter the code|paste it here)`)
	codeRE := regexp.MustCompile(`(?i)code[: ]+([A-Z0-9-]{6,})`)

	poll := time.NewTicker(1 * time.Second)
	defer poll.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = killTmux(login.sessionName)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				login.emitDone(false, ErrTimeout.Error(), Status{Kind: login.Kind})
			} else {
				login.emitDone(false, ErrCancelled.Error(), Status{Kind: login.Kind})
			}
			return
		case raw, ok := <-lines:
			if !ok {
				// Pipe closed (tmux session ended). Check credential file.
				if login.Kind == KindGitHub {
					if st, err := m.Status(ctx, login.Kind); err == nil && st.LoggedIn {
						login.emitDone(true, "", st)
						return
					}
				}
				if mtimeNewer(m.credPath(login.Kind), credBaseline) {
					m.finishOK(ctx, login)
					return
				}
				login.emitDone(false, "captive process exited without credentials", Status{Kind: login.Kind})
				return
			}
			clean := strings.TrimRight(cleanTerminalLine(raw), "\r\n")
			if clean == "" {
				continue
			}
			scrubbed := scrubSecrets(clean)
			login.emit(Event{Type: EvtProgress, Stream: "stdout", Line: scrubbed})
			if login.Kind == KindClaude && !claudeSetupAdvanced && isClaudeFirstRunSetup(clean) {
				claudeSetupAdvanced = true
				if err := sendEnter(ctx, login.sessionName); err != nil {
					login.emit(Event{Type: EvtProgress, Stream: "system", Line: "Could not advance Claude setup: " + err.Error()})
				} else {
					login.emit(Event{Type: EvtProgress, Stream: "system", Line: "Selected the default Claude Code theme to continue sign-in."})
				}
			}
			if !urlSeen {
				for _, candidate := range urlRE.FindAllString(clean, -1) {
					candidate = strings.TrimRight(candidate, ".,;:!?")
					if !isPublicURL(candidate) {
						continue
					}
					urlSeen = true
					if host, port, path, ok := extractCallbackTarget(candidate); ok {
						login.callbackHost = host
						login.callbackPort = port
						login.callbackPath = path
						login.emit(Event{
							Type:         EvtCallbackTarget,
							CallbackHost: host, CallbackPort: port, CallbackPath: path,
						})
					}
					code := ""
					if m := codeRE.FindStringSubmatch(clean); len(m) > 1 {
						code = m[1]
					}
					login.emit(Event{Type: EvtURL, URL: candidate, UserCode: code})
					break
				}
			}
			if !pasteSeen && pasteRE.MatchString(clean) {
				pasteSeen = true
				login.emit(Event{Type: EvtPromptPaste})
			}
		case <-poll.C:
			if login.Kind == KindGitHub {
				if st, err := m.Status(ctx, login.Kind); err == nil && st.LoggedIn {
					_ = killTmux(login.sessionName)
					login.emitDone(true, "", st)
					return
				}
			}
			if mtimeNewer(m.credPath(login.Kind), credBaseline) {
				m.finishOK(ctx, login)
				return
			}
			if !tmuxSessionAlive(login.sessionName) {
				if login.Kind == KindGitHub {
					if st, err := m.Status(ctx, login.Kind); err == nil && st.LoggedIn {
						login.emitDone(true, "", st)
						return
					}
				}
				if mtimeNewer(m.credPath(login.Kind), credBaseline) {
					m.finishOK(ctx, login)
					return
				}
				login.emitDone(false, "captive process exited without credentials", Status{Kind: login.Kind})
				return
			}
		}
	}
}

func (m *Manager) finishOK(ctx context.Context, login *Login) {
	if login.Kind == KindGitHub {
		_ = killTmux(login.sessionName)
		st, _ := m.Status(ctx, login.Kind)
		login.emitDone(st.LoggedIn, "", st)
		return
	}
	// Claude's interactive /login credential file is the canonical state.
	// Do not extract its access token and inject it as CLAUDE_CODE_OAUTH_TOKEN:
	// that env var is for tokens generated by `claude setup-token` and has
	// higher precedence than subscription credentials.
	if login.Kind == KindClaude {
		_ = m.cfg.Store.DeleteCliToken(login.Kind)
		_ = killTmux(login.sessionName)
		st, _ := m.Status(ctx, login.Kind)
		login.emitDone(true, "", st)
		return
	}

	// For Codex, preserve the auth.json in the vault as an opaque backup while
	// keeping the file on disk as the credential the CLI actually consumes.
	credPath := m.credPath(login.Kind)
	if b, err := os.ReadFile(credPath); err == nil {
		token := extractToken(login.Kind, b)
		method := MethodSubscription
		if token == "" {
			token = string(b)
			if login.Kind == KindCodex {
				method = MethodAuthJSON
			}
		}
		if token != "" {
			if path, err := m.cfg.Vault.Seal(login.Kind, token); err == nil {
				_ = m.cfg.Store.PutCliToken(store.CliToken{
					Kind: login.Kind, Method: method,
					Account:        parseAccount(login.Kind, credPath),
					CiphertextPath: path,
				})
			}
		}
	}
	_ = killTmux(login.sessionName)
	st, _ := m.Status(ctx, login.Kind)
	login.emitDone(true, "", st)
}

func loginCommandArgs(kind, bin string) []string {
	switch kind {
	case KindClaude:
		return []string{bin, "auth", "login"}
	case KindCodex:
		return []string{bin, "login"}
	case KindGitHub:
		return []string{bin, "auth", "login", "--hostname", "github.com", "--git-protocol", "https", "--scopes", "repo,read:org,workflow", "--web"}
	default:
		return []string{bin}
	}
}

func (m *Manager) cleanupLogin(login *Login) {
	login.closeOnce.Do(func() {
		_ = killTmux(login.sessionName)
		_ = os.Remove(login.fifo)
		m.mu.Lock()
		if m.running[login.Kind] == login {
			delete(m.running, login.Kind)
		}
		delete(m.byID, login.ID)
		m.mu.Unlock()
		close(login.events)
	})
}

func (l *Login) emit(ev Event) {
	select {
	case l.events <- ev:
	default:
	}
}

func (l *Login) emitDone(ok bool, errMsg string, st Status) {
	l.emit(Event{Type: EvtDone, OK: ok, Error: errMsg, Status: st})
}

// envForCaptive returns the env we hand to the captive tmux process so the
// CLI it spawns can resolve binaries under BinDir.
func (m *Manager) envForCaptive() []string {
	env := os.Environ()
	cur := os.Getenv("PATH")
	newPath := m.cfg.BinDir
	if cur != "" {
		newPath = m.cfg.BinDir + ":" + cur
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "PATH="+newPath)
}

// extractToken pulls a usable token out of a credential file, when possible.
// Returns "" if the file shape is unrecognised — caller decides whether to
// fall back to storing the whole blob.
func extractToken(kind string, body []byte) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if kind == KindClaude {
		if oauth, ok := m["oauth"].(map[string]any); ok {
			if t, ok := oauth["access_token"].(string); ok && t != "" {
				return t
			}
		}
		if t, ok := m["access_token"].(string); ok && t != "" {
			return t
		}
	}
	// Codex's auth.json is opaque; treat as a whole file.
	return ""
}

// isPublicURL returns true iff u parses to an http(s) URL whose host is not
// loopback, private RFC1918, link-local, or a numeric host on the agent box.
// We use this to skip codex's "Starting server on http://localhost:NNNN"
// line and only surface the real OAuth URL to the mobile.
func isPublicURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	if p.Scheme != "http" && p.Scheme != "https" {
		return false
	}
	h := p.Hostname()
	if h == "" || h == "localhost" {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return false
		}
	}
	return true
}

// extractCallbackTarget pulls the redirect_uri query param off an OAuth URL
// and decomposes it into host/port/path so the mobile webview knows which
// navigation to intercept.
func extractCallbackTarget(oauthURL string) (host string, port int, path string, ok bool) {
	p, err := url.Parse(oauthURL)
	if err != nil {
		return "", 0, "", false
	}
	redirect := p.Query().Get("redirect_uri")
	if redirect == "" {
		return "", 0, "", false
	}
	rp, err := url.Parse(redirect)
	if err != nil {
		return "", 0, "", false
	}
	host = rp.Hostname()
	if rp.Port() != "" {
		fmt.Sscanf(rp.Port(), "%d", &port)
	} else if rp.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	path = rp.Path
	if path == "" {
		path = "/"
	}
	return host, port, path, host != ""
}

// Relay fetches the agent-local callback URL the user would have hit if
// their phone were the same machine as codex. Called by the WS layer after
// the mobile webview intercepts the redirect and forwards us the captured
// query string. Returns when codex's listener has responded (or errored).
func (m *Manager) Relay(ctx context.Context, loginID, rawQuery string) error {
	m.mu.Lock()
	login := m.byID[loginID]
	m.mu.Unlock()
	if login == nil {
		return ErrUnknownLogin
	}
	if login.callbackPort == 0 || login.callbackPath == "" {
		return errors.New("cliauth: no callback target captured for this login")
	}
	target := fmt.Sprintf("http://127.0.0.1:%d%s", login.callbackPort, login.callbackPath)
	if rawQuery != "" {
		if strings.Contains(target, "?") {
			target += "&" + rawQuery
		} else {
			target += "?" + rawQuery
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	cli := &http.Client{Timeout: 15 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("cliauth: relay: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("cliauth: relay status %d", resp.StatusCode)
	}
	return nil
}

func tmuxSessionAlive(name string) bool {
	err := exec.Command("tmux", "has-session", "-t", name).Run()
	return err == nil
}

func killTmux(name string) error {
	return exec.Command("tmux", "kill-session", "-t", name).Run()
}

func sendEnter(ctx context.Context, sessionName string) error {
	target := sessionName + ":0.0"
	if out, err := exec.CommandContext(ctx, "tmux", "send-keys", "-t", target, "Enter").CombinedOutput(); err != nil {
		return fmt.Errorf("tmux send-keys Enter: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func mtime(p string) time.Time {
	fi, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

func mtimeNewer(p string, baseline time.Time) bool {
	t := mtime(p)
	if t.IsZero() {
		return false
	}
	return t.After(baseline)
}

var (
	// Strip CSI sequences, OSC sequences terminated by either BEL (\x07) or
	// ST (ESC \). Codex uses OSC 8 hyperlinks (ST-terminated) heavily so
	// missing the ST case would leave escape bytes embedded in extracted
	// URLs and break Safari's openURL.
	ansiRE   = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)
	secretRE = regexp.MustCompile(`(?:sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|oauth_[A-Za-z0-9_-]{20,})`)
)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

func cleanTerminalLine(s string) string {
	s = stripANSI(s)
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, s)
}

func isClaudeFirstRunSetup(s string) bool {
	compact := strings.ToLower(strings.ReplaceAll(s, " ", ""))
	return strings.Contains(compact, "choosethetextstyle") ||
		strings.Contains(compact, "syntaxtheme:") ||
		(strings.Contains(compact, "welcometoclaudecode") && strings.Contains(compact, "let'sgetstarted"))
}

func scrubSecrets(s string) string {
	return secretRE.ReplaceAllStringFunc(s, func(m string) string {
		// Preserve the recognisable prefix (sk-, sk-ant-, oauth_) so logs
		// stay diagnosable; redact only the secret body.
		for _, sep := range []byte{'-', '_'} {
			if i := strings.IndexByte(m, sep); i > 0 && i < 8 {
				return m[:i+1] + "[REDACTED]"
			}
		}
		return "[REDACTED]"
	})
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func randID() string {
	b := make([]byte, 8)
	_, _ = io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)
}
