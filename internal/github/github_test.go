package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/review"
	"github.com/rockclaver/claver/agent/internal/store"
)

func fixture(t *testing.T) (*Manager, *store.Store, *projects.Manager, *review.Manager, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pm, err := projects.New(filepath.Join(dir, "projects"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "proj" }
	if _, err := pm.CreateEmpty("demo"); err != nil {
		t.Fatal(err)
	}
	ws := pm.WorkspaceDir("proj")
	mustGit(t, ws, "config", "user.email", "test@example.com")
	mustGit(t, ws, "config", "user.name", "Test")
	mustWrite(t, ws, "README.md", "seed\n")
	mustGit(t, ws, "add", "README.md")
	mustGit(t, ws, "commit", "-q", "-m", "seed")
	rm := review.New(pm, st, review.HeuristicSummarizer{})
	m := New(st, pm, rm, NewTokenVault(filepath.Join(dir, "github.key"), filepath.Join(dir, "tokens")), "client-id")
	m.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return m, st, pm, rm, ws
}

// AC: "Device Flow happy path works end-to-end against real GitHub; flow
// gracefully handles expired device codes and slow-down responses."
func TestDeviceFlow_HappyPathSlowDownAndExpiredCodes(t *testing.T) {
	m, st, _, _, _ := fixture(t)
	var pollCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/device/code":
			_, _ = w.Write([]byte(`{"device_code":"dev","user_code":"USER","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}`))
		case "/login/oauth/access_token":
			pollCount++
			if pollCount == 1 {
				_, _ = w.Write([]byte(`{"error":"slow_down"}`))
				return
			}
			if pollCount == 2 {
				_, _ = w.Write([]byte(`{"error":"expired_token"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"gho_secret"}`))
		case "/user":
			if r.Header.Get("Authorization") != "Bearer gho_secret" {
				t.Fatalf("missing auth header: %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"login":"octo"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	m.LoginBase = ts.URL
	m.APIBase = ts.URL

	start, err := m.StartDeviceFlow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if start.DeviceCode != "dev" || start.UserCode != "USER" {
		t.Fatalf("bad start: %+v", start)
	}
	if _, err := m.PollDeviceFlow(context.Background(), "dev"); !errors.Is(err, ErrSlowDown) {
		t.Fatalf("slow_down got %v", err)
	}
	if _, err := m.PollDeviceFlow(context.Background(), "dev"); !errors.Is(err, ErrExpiredDeviceCode) {
		t.Fatalf("expired got %v", err)
	}
	got, err := m.PollDeviceFlow(context.Background(), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccountLogin != "octo" {
		t.Fatalf("account = %+v", got)
	}
	if _, err := st.GetGitHubToken("octo"); err != nil {
		t.Fatalf("token row missing: %v", err)
	}
}

// AC: "OAuth token is stored in `github_tokens` as ciphertext; the encryption
// key file is `0600` and root-owned."
func TestTokenVault_StoresCiphertextAndKeyIs0600(t *testing.T) {
	m, st, _, _, _ := fixture(t)
	path, err := m.Vault.Seal("octo", "gho_secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutGitHubToken(store.GitHubToken{AccountLogin: "octo", CiphertextPath: path}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "gho_secret") {
		t.Fatal("ciphertext blob contains plaintext token")
	}
	info, err := os.Stat(m.Vault.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %03o want 600", info.Mode().Perm())
	}
	opened, err := m.Vault.Open("octo", path)
	if err != nil {
		t.Fatal(err)
	}
	if opened != "gho_secret" {
		t.Fatalf("open = %q", opened)
	}
}

// AC: "Repo browse shows user + org repos with pagination; selecting one
// drives the Phase 3 import flow."
func TestRepoBrowse_PaginatesUserAndOrgRepos_AndImportClones(t *testing.T) {
	m, _, pm, _, _ := fixture(t)
	pm.IDGen = func() string { return "imported" }
	seed := t.TempDir()
	src := filepath.Join(seed, "src")
	mustGit(t, seed, "init", "--bare", src)
	repoJSON := `{"id":1,"name":"src","full_name":"octo/src","clone_url":"file://` + src + `","private":false,"default_branch":"main"}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/user/repos":
			if r.URL.Query().Get("affiliation") != "owner,collaborator,organization_member" {
				t.Fatalf("affiliation query missing org repos: %s", r.URL.RawQuery)
			}
			w.Header().Set("Link", `<`+r.URL.String()+`&page=2>; rel="next"`)
			_, _ = w.Write([]byte(`[` + repoJSON + `]`))
		case r.URL.Path == "/repos/octo/src":
			_, _ = w.Write([]byte(repoJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	m.APIBase = ts.URL
	storeToken(t, m, "octo", "token")

	repos, next, err := m.ListRepos(context.Background(), "octo", 1, 25)
	if err != nil {
		t.Fatal(err)
	}
	if !next || len(repos) != 1 || repos[0].FullName != "octo/src" {
		t.Fatalf("repos=%+v next=%v", repos, next)
	}
	p, err := m.ImportRepo(context.Background(), "octo", "octo/src")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "octo/src" || p.RemoteURL == "" {
		t.Fatalf("import did not create project: %+v", p)
	}
}

// AC: "Commit requires an approved change set (no committing un-reviewed
// agent output)."
func TestCommit_RequiresApprovedChangeSet(t *testing.T) {
	m, _, _, rm, ws := fixture(t)
	mustWrite(t, ws, "reviewed.txt", "approved\n")
	if _, err := m.Commit("proj", "commit without review", []string{"reviewed.txt"}); !errors.Is(err, ErrUnapprovedChanges) {
		t.Fatalf("unapproved commit got %v", err)
	}
	if _, _, err := rm.Approve("proj", "", []string{"reviewed.txt"}, "ok"); err != nil {
		t.Fatal(err)
	}
	sha, err := m.Commit("proj", "approved commit", []string{"reviewed.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if sha == "" {
		t.Fatal("empty commit sha")
	}
}

// AC: "Push requires a valid biometric `confirmation_token` and writes an
// Audit Log entry; pushes without a token are rejected and logged."
func TestPush_RequiresConfirmationTokenAndAuditsFailures(t *testing.T) {
	m, st, _, rm, _ := fixture(t)
	storeToken(t, m, "octo", "token")
	err := m.Push("proj", "octo", "", []string{"README.md"})
	if !errors.Is(err, ErrConfirmationNeeded) {
		t.Fatalf("missing token got %v", err)
	}
	entries, err := st.ListAudit("push.attempt", "proj", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.Contains(entries[0].Summary, "missing confirmation_token") {
		t.Fatalf("missing push audit: %+v", entries)
	}
	tok, err := rm.MintConfirmationToken("github.push", "proj", []string{"README.md"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := rm.ConsumeToken(tok.Token, "github.push", "proj", []string{"README.md"}, "wrong"); !errors.Is(err, review.ErrTokenMismatch) {
		t.Fatalf("token should be action-bound, got %v", err)
	}
}

// AC: "PR create supports AI-drafted title/body and lets the user edit before
// submitting." and "PR list shows open/closed state and CI status for the
// project's branches."
func TestPullRequests_DraftCreateAndListWithCIStatus(t *testing.T) {
	m, _, _, _, ws := fixture(t)
	storeToken(t, m, "octo", "token")
	mustWrite(t, ws, "pr.txt", "body\n")
	title, body, err := m.DraftPR("proj")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(title, "pr.txt") || !strings.Contains(body, "pr.txt") {
		t.Fatalf("draft did not mention changed file: title=%q body=%q", title, body)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/repos/octo/src/pulls":
			var in map[string]string
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Fatal(err)
			}
			if in["title"] != "Edited title" || in["body"] != "Edited body" {
				t.Fatalf("PR create did not use edited fields: %+v", in)
			}
			_, _ = w.Write([]byte(`{"number":7,"title":"Edited title","state":"open","html_url":"https://github.com/octo/src/pull/7","head":{"ref":"feature","sha":"abc"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/repos/octo/src/pulls":
			_, _ = w.Write([]byte(`[{"number":7,"title":"Edited title","state":"open","html_url":"https://github.com/octo/src/pull/7","head":{"ref":"feature","sha":"abc"}},{"number":6,"title":"Closed","state":"closed","html_url":"u","head":{"ref":"old","sha":"def"}}]`))
		case strings.HasSuffix(r.URL.Path, "/status"):
			_, _ = w.Write([]byte(`{"state":"success"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	m.APIBase = ts.URL
	pr, err := m.CreatePR(context.Background(), "octo", "octo/src", "feature", "main", "Edited title", "Edited body")
	if err != nil {
		t.Fatal(err)
	}
	if pr.Number != 7 || pr.Title != "Edited title" {
		t.Fatalf("bad create response: %+v", pr)
	}
	prs, err := m.ListPRs(context.Background(), "octo", "octo/src")
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 2 || prs[0].State != "open" || prs[1].State != "closed" || prs[0].CI != "success" {
		t.Fatalf("bad PR list: %+v", prs)
	}
}

// AC: "Revoke-token clears the row, removes the encrypted blob, and forces
// re-auth on next GitHub call."
func TestRevoke_RemovesRowBlobAndForcesReauth(t *testing.T) {
	m, st, _, _, _ := fixture(t)
	path := storeToken(t, m, "octo", "token")
	if err := m.Revoke(context.Background(), "octo"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetGitHubToken("octo"); err == nil {
		t.Fatal("token row still exists")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blob still exists or unexpected stat err: %v", err)
	}
	if _, _, err := m.ListRepos(context.Background(), "octo", 1, 10); !errors.Is(err, ErrTokenMissing) {
		t.Fatalf("next call should force reauth, got %v", err)
	}
}

func storeToken(t *testing.T, m *Manager, account, token string) string {
	t.Helper()
	path, err := m.Vault.Seal(account, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Store.PutGitHubToken(store.GitHubToken{AccountLogin: account, CiphertextPath: path}); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func mustWrite(t *testing.T, dir, name, body string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
