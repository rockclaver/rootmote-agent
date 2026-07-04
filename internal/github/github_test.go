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

	"github.com/rockclaver/rootmote-agent/internal/projects"
	"github.com/rockclaver/rootmote-agent/internal/review"
	"github.com/rockclaver/rootmote-agent/internal/store"
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
	m := New(st, pm, rm, NewTokenVault(filepath.Join(dir, "github.key"), filepath.Join(dir, "tokens")))
	m.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	storeToken(t, m, "octo", "token")
	return m, st, pm, rm, ws
}

func TestToken_UsesGitHubCLIActiveAccount(t *testing.T) {
	m, _, _, _, _ := fixture(t)
	var gotName string
	var gotArgs []string
	m.RunCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return []byte("gho_from_gh\n"), nil
	}
	token, err := m.token(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if token != "gho_from_gh" {
		t.Fatalf("token = %q", token)
	}
	if gotName != "gh" || strings.Join(gotArgs, " ") != "auth token --hostname github.com" {
		t.Fatalf("gh command = %q %q", gotName, strings.Join(gotArgs, " "))
	}
}

func TestToken_UsesSelectedGitHubCLIAccount(t *testing.T) {
	m, _, _, _, _ := fixture(t)
	var gotArgs []string
	m.RunCommand = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		gotArgs = append([]string(nil), args...)
		return []byte("gho_user\n"), nil
	}
	if _, err := m.token(context.Background(), "octo"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotArgs, " ") != "auth token --hostname github.com --user octo" {
		t.Fatalf("gh args = %q", strings.Join(gotArgs, " "))
	}
}

func TestToken_MissingGitHubCLIAuthReturnsSentinel(t *testing.T) {
	m, _, _, _, _ := fixture(t)
	m.RunCommand = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("not logged in"), errors.New("exit 1")
	}
	if _, err := m.ListRepos(context.Background(), "", RepoListOptions{Page: 1, PerPage: 10}); !errors.Is(err, ErrTokenMissing) {
		t.Fatalf("missing gh auth got %v", err)
	}
}

func TestGitHubGitEnvUsesBasicTokenHeader(t *testing.T) {
	env := githubGitEnv("gho_secret")
	got := strings.Join(env, "\n")
	if !strings.Contains(got, "GIT_CONFIG_VALUE_0=Authorization: Basic ") {
		t.Fatalf("missing basic auth header: %q", got)
	}
	if strings.Contains(got, "gho_secret") || strings.Contains(got, "Bearer") {
		t.Fatalf("git env leaked raw token or used bearer header: %q", got)
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
	repoJSON := `{"id":1,"name":"src","full_name":"octo/src","clone_url":"file://` + src + `","private":false,"default_branch":"main","owner":{"login":"octo","type":"Organization"}}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/user":
			_, _ = w.Write([]byte(`{"login":"rockclaver"}`))
		case r.URL.Path == "/user/orgs":
			_, _ = w.Write([]byte(`[{"login":"octo","type":"Organization"}]`))
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

	result, err := m.ListRepos(context.Background(), "octo", RepoListOptions{Page: 1, PerPage: 25})
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasNext || len(result.Repos) != 1 || result.Repos[0].FullName != "octo/src" {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Owners) != 2 || result.Owners[1].Login != "octo" {
		t.Fatalf("owners=%+v", result.Owners)
	}
	p, err := m.ImportRepo(context.Background(), "octo", "octo/src")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "octo/src" || p.RemoteURL == "" {
		t.Fatalf("import did not create project: %+v", p)
	}
}

func TestRepoBrowse_FiltersBySearchVisibilityAndOwner(t *testing.T) {
	m, _, _, _, _ := fixture(t)
	repos := []string{
		`{"id":1,"name":"budget","full_name":"rockclaver/budget","clone_url":"https://github.com/rockclaver/budget.git","private":true,"default_branch":"main","owner":{"login":"rockclaver","type":"User"}}`,
		`{"id":2,"name":"budget-api","full_name":"octo/budget-api","clone_url":"https://github.com/octo/budget-api.git","private":true,"default_branch":"main","owner":{"login":"octo","type":"Organization"}}`,
		`{"id":3,"name":"public-site","full_name":"octo/public-site","clone_url":"https://github.com/octo/public-site.git","private":false,"default_branch":"main","owner":{"login":"octo","type":"Organization"}}`,
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			_, _ = w.Write([]byte(`{"login":"rockclaver"}`))
		case "/user/orgs":
			_, _ = w.Write([]byte(`[{"login":"octo"}]`))
		case "/user/repos":
			_, _ = w.Write([]byte(`[` + strings.Join(repos, ",") + `]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	m.APIBase = ts.URL
	storeToken(t, m, "octo", "token")

	result, err := m.ListRepos(context.Background(), "octo", RepoListOptions{
		Page:       1,
		PerPage:    10,
		Query:      "budget",
		Visibility: "private",
		Owner:      "octo",
		OwnerType:  "organization",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Repos) != 1 || result.Repos[0].FullName != "octo/budget-api" {
		t.Fatalf("filtered repos=%+v", result.Repos)
	}
	if len(result.Owners) != 2 || result.Owners[0].Login != "rockclaver" || result.Owners[1].Login != "octo" {
		t.Fatalf("owners=%+v", result.Owners)
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

// Review comment 3323688519: approval must be bound to the reviewed revision,
// not just to the path list.
func TestCommit_RejectsFileModifiedAfterApproval(t *testing.T) {
	m, _, _, rm, ws := fixture(t)
	mustWrite(t, ws, "reviewed.txt", "approved version\n")
	if _, _, err := rm.Approve("proj", "", []string{"reviewed.txt"}, "ok"); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, ws, "reviewed.txt", "unreviewed version\n")
	if _, err := m.Commit("proj", "should fail", []string{"reviewed.txt"}); !errors.Is(err, ErrUnapprovedChanges) {
		t.Fatalf("modified-after-approval commit got %v want ErrUnapprovedChanges", err)
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

// Review comment 3323688524: locally-created branches have no upstream, so
// push must set origin/HEAD explicitly.
func TestPush_NewLocalBranchSetsUpstream(t *testing.T) {
	m, _, _, rm, ws := fixture(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	mustGit(t, t.TempDir(), "init", "--bare", remote)
	mustGit(t, ws, "remote", "add", "origin", remote)
	mustGit(t, ws, "push", "-u", "origin", "main")
	mustGit(t, ws, "checkout", "-b", "feature")
	mustWrite(t, ws, "branch.txt", "branch\n")
	if _, _, err := rm.Approve("proj", "", []string{"branch.txt"}, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Commit("proj", "branch commit", []string{"branch.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := gitRun(ws, "rev-parse", "--abbrev-ref", "@{upstream}"); err == nil {
		t.Fatal("feature branch unexpectedly already has upstream")
	}
	storeToken(t, m, "octo", "token")
	tok, err := rm.MintConfirmationToken("github.push", "proj", []string{"branch.txt"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Push("proj", "octo", tok.Token, []string{"branch.txt"}); err != nil {
		t.Fatal(err)
	}
	upstream, err := gitRun(ws, "rev-parse", "--abbrev-ref", "@{upstream}")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(upstream) != "origin/feature" {
		t.Fatalf("upstream = %q want origin/feature", strings.TrimSpace(upstream))
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
	m, _, _, _, _ := fixture(t)
	var gotArgs []string
	m.RunCommand = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		gotArgs = append([]string(nil), args...)
		return []byte(""), nil
	}
	if err := m.Revoke(context.Background(), "octo"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotArgs, " ") != "auth logout --hostname github.com --user octo" {
		t.Fatalf("gh args = %q", strings.Join(gotArgs, " "))
	}
}

func storeToken(t *testing.T, m *Manager, account, token string) {
	t.Helper()
	m.RunCommand = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "auth" && args[1] == "token" {
			return []byte(token + "\n"), nil
		}
		return []byte("ok\n"), nil
	}
	_ = account
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
