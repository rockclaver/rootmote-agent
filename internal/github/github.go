package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rockclaver/claver/agent/internal/projects"
	"github.com/rockclaver/claver/agent/internal/review"
	"github.com/rockclaver/claver/agent/internal/store"
)

var (
	ErrAuthPending        = errors.New("github device flow authorization pending")
	ErrSlowDown           = errors.New("github device flow slow down")
	ErrExpiredDeviceCode  = errors.New("github device code expired")
	ErrTokenMissing       = errors.New("github token missing")
	ErrUnapprovedChanges  = errors.New("commit requires an approved change set")
	ErrConfirmationNeeded = errors.New("push requires confirmation_token")
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Manager struct {
	Store       *store.Store
	Projects    *projects.Manager
	Review      *review.Manager
	Vault       *TokenVault
	ClientID    string
	HTTP        HTTPClient
	APIBase     string
	LoginBase   string
	Now         func() time.Time
	DraftPRBody func(projectID string, files []review.ChangedFile) (string, string)
}

type DeviceStart struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type DevicePoll struct {
	AccountLogin string `json:"account_login"`
}

type Repo struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	CloneURL      string `json:"clone_url"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
}

type PullRequest struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"`
	URL    string `json:"url"`
	Head   string `json:"head"`
	CI     string `json:"ci_status"`
}

func New(st *store.Store, pm *projects.Manager, rm *review.Manager, vault *TokenVault, clientID string) *Manager {
	return &Manager{
		Store:     st,
		Projects:  pm,
		Review:    rm,
		Vault:     vault,
		ClientID:  clientID,
		HTTP:      http.DefaultClient,
		APIBase:   "https://api.github.com",
		LoginBase: "https://github.com",
		Now:       time.Now,
	}
}

func (m *Manager) StartDeviceFlow(ctx context.Context) (DeviceStart, error) {
	if m.ClientID == "" {
		return DeviceStart{}, errors.New("github client_id not configured")
	}
	form := url.Values{"client_id": {m.ClientID}, "scope": {"repo read:org workflow"}}
	var out DeviceStart
	if err := m.postForm(ctx, m.LoginBase+"/login/device/code", "", form, &out); err != nil {
		return DeviceStart{}, err
	}
	return out, nil
}

func (m *Manager) PollDeviceFlow(ctx context.Context, deviceCode string) (DevicePoll, error) {
	form := url.Values{
		"client_id":   {m.ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := m.postForm(ctx, m.LoginBase+"/login/oauth/access_token", "", form, &tokenResp); err != nil {
		return DevicePoll{}, err
	}
	switch tokenResp.Error {
	case "authorization_pending":
		return DevicePoll{}, ErrAuthPending
	case "slow_down":
		return DevicePoll{}, ErrSlowDown
	case "expired_token":
		return DevicePoll{}, ErrExpiredDeviceCode
	case "":
	default:
		return DevicePoll{}, errors.New(tokenResp.Error)
	}
	if tokenResp.AccessToken == "" {
		return DevicePoll{}, errors.New("github returned empty access_token")
	}
	user, err := m.viewer(ctx, tokenResp.AccessToken)
	if err != nil {
		return DevicePoll{}, err
	}
	path, err := m.Vault.Seal(user, tokenResp.AccessToken)
	if err != nil {
		return DevicePoll{}, err
	}
	if err := m.Store.PutGitHubToken(store.GitHubToken{
		AccountLogin:   user,
		CiphertextPath: path,
		CreatedAt:      m.Now(),
		UpdatedAt:      m.Now(),
	}); err != nil {
		return DevicePoll{}, err
	}
	_, _ = m.Review.LogAudit(store.AuditEntry{
		Type:      "github.token.grant",
		Actor:     "mobile",
		Summary:   "GitHub token granted for " + user,
		CreatedAt: m.Now(),
	})
	return DevicePoll{AccountLogin: user}, nil
}

func (m *Manager) ListRepos(ctx context.Context, account string, page, perPage int) ([]Repo, bool, error) {
	token, err := m.token(account)
	if err != nil {
		return nil, false, err
	}
	if page <= 0 {
		page = 1
	}
	if perPage <= 0 || perPage > 100 {
		perPage = 50
	}
	u := fmt.Sprintf("%s/user/repos?affiliation=owner,collaborator,organization_member&sort=updated&page=%d&per_page=%d", m.APIBase, page, perPage)
	var repos []Repo
	next, err := m.get(ctx, u, token, &repos)
	return repos, next, err
}

func (m *Manager) ImportRepo(ctx context.Context, account, fullName string) (store.Project, error) {
	token, err := m.token(account)
	if err != nil {
		return store.Project{}, err
	}
	var repo Repo
	if err := m.getNoPage(ctx, m.APIBase+"/repos/"+fullName, token, &repo); err != nil {
		return store.Project{}, err
	}
	return m.Projects.ImportWithEnv(repo.FullName, repo.CloneURL, githubGitEnv(token))
}

func (m *Manager) Commit(projectID, message string, files []string) (string, error) {
	if strings.TrimSpace(message) == "" {
		return "", errors.New("commit message required")
	}
	if err := m.requireApproved(projectID, files); err != nil {
		return "", err
	}
	dir := m.Projects.WorkspaceDir(projectID)
	args := append([]string{"add", "--"}, files...)
	if _, err := gitRun(dir, args...); err != nil {
		return "", err
	}
	if _, err := gitRun(dir, "commit", "-m", message); err != nil {
		return "", err
	}
	out, err := gitRun(dir, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(out)
	_, _ = m.Review.LogAudit(store.AuditEntry{
		Type:      "github.commit",
		ProjectID: projectID,
		Actor:     "mobile",
		Summary:   "Committed approved change set " + sha,
		CreatedAt: m.Now(),
	})
	return sha, nil
}

func (m *Manager) Push(projectID, account, confirmationToken string, files []string) error {
	if confirmationToken == "" {
		_, _ = m.logPush(projectID, false, "missing confirmation_token")
		return ErrConfirmationNeeded
	}
	if err := m.Review.ConsumeToken(confirmationToken, "github.push", projectID, files, ""); err != nil {
		_, _ = m.logPush(projectID, false, err.Error())
		return err
	}
	token, err := m.token(account)
	if err != nil {
		_, _ = m.logPush(projectID, false, err.Error())
		return err
	}
	if _, err := gitRunWithEnv(m.Projects.WorkspaceDir(projectID), githubGitEnv(token), "push"); err != nil {
		_, _ = m.logPush(projectID, false, err.Error())
		return err
	}
	_, err = m.logPush(projectID, true, "push succeeded")
	return err
}

func (m *Manager) DraftPR(projectID string) (string, string, error) {
	files, err := m.Review.Status(projectID)
	if err != nil {
		return "", "", err
	}
	if m.DraftPRBody != nil {
		title, body := m.DraftPRBody(projectID, files)
		return title, body, nil
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Path)
	}
	title := "Update " + projectID
	if len(names) > 0 {
		title = "Update " + names[0]
	}
	body := "## Summary\n- Updates " + strings.Join(names, ", ") + "\n\n## Test plan\n- Not run by agent\n"
	return title, body, nil
}

func (m *Manager) CreatePR(ctx context.Context, account, repoFullName, head, base, title, body string) (PullRequest, error) {
	token, err := m.token(account)
	if err != nil {
		return PullRequest{}, err
	}
	payload := map[string]string{"title": title, "body": body, "head": head, "base": base}
	var resp struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		State   string `json:"state"`
		HTMLURL string `json:"html_url"`
		Head    struct {
			Ref string `json:"ref"`
		} `json:"head"`
	}
	if err := m.postJSON(ctx, m.APIBase+"/repos/"+repoFullName+"/pulls", token, payload, &resp); err != nil {
		return PullRequest{}, err
	}
	return PullRequest{Number: resp.Number, Title: resp.Title, State: resp.State, URL: resp.HTMLURL, Head: resp.Head.Ref}, nil
}

func (m *Manager) ListPRs(ctx context.Context, account, repoFullName string) ([]PullRequest, error) {
	token, err := m.token(account)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		State   string `json:"state"`
		HTMLURL string `json:"html_url"`
		Head    struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
	}
	if err := m.getNoPage(ctx, m.APIBase+"/repos/"+repoFullName+"/pulls?state=all&sort=updated&per_page=50", token, &raw); err != nil {
		return nil, err
	}
	out := make([]PullRequest, 0, len(raw))
	for _, pr := range raw {
		ci := "unknown"
		var status struct {
			State string `json:"state"`
		}
		if err := m.getNoPage(ctx, m.APIBase+"/repos/"+repoFullName+"/commits/"+pr.Head.SHA+"/status", token, &status); err == nil && status.State != "" {
			ci = status.State
		}
		out = append(out, PullRequest{Number: pr.Number, Title: pr.Title, State: pr.State, URL: pr.HTMLURL, Head: pr.Head.Ref, CI: ci})
	}
	return out, nil
}

func (m *Manager) Revoke(ctx context.Context, account string) error {
	row, err := m.Store.GetGitHubToken(account)
	if err != nil {
		return err
	}
	if err := m.Vault.Delete(row.CiphertextPath); err != nil {
		return err
	}
	if err := m.Store.DeleteGitHubToken(account); err != nil {
		return err
	}
	_, _ = m.Review.LogAudit(store.AuditEntry{Type: "github.token.revoke", Actor: "mobile", Summary: "GitHub token revoked for " + account, CreatedAt: m.Now()})
	return nil
}

func (m *Manager) token(account string) (string, error) {
	if account == "" {
		rows, err := m.Store.ListGitHubTokens()
		if err != nil {
			return "", err
		}
		if len(rows) == 0 {
			return "", ErrTokenMissing
		}
		account = rows[0].AccountLogin
	}
	row, err := m.Store.GetGitHubToken(account)
	if err != nil {
		return "", ErrTokenMissing
	}
	return m.Vault.Open(account, row.CiphertextPath)
}

func (m *Manager) requireApproved(projectID string, files []string) error {
	if len(files) == 0 {
		return ErrUnapprovedChanges
	}
	entries, err := m.Store.ListAudit("review.approve", projectID, 50)
	if err != nil {
		return err
	}
	want := normalized(files)
	for _, e := range entries {
		var ev review.ReviewEvent
		if err := json.Unmarshal([]byte(e.Data), &ev); err == nil && equalStrings(normalized(ev.Files), want) {
			return nil
		}
	}
	return ErrUnapprovedChanges
}

func (m *Manager) viewer(ctx context.Context, token string) (string, error) {
	var out struct {
		Login string `json:"login"`
	}
	if err := m.getNoPage(ctx, m.APIBase+"/user", token, &out); err != nil {
		return "", err
	}
	if out.Login == "" {
		return "", errors.New("github viewer login missing")
	}
	return out.Login, nil
}

func (m *Manager) logPush(projectID string, ok bool, summary string) (store.AuditEntry, error) {
	body, _ := json.Marshal(map[string]any{"ok": ok, "summary": summary})
	return m.Review.LogAudit(store.AuditEntry{Type: "push.attempt", ProjectID: projectID, Actor: "mobile", Summary: summary, Data: string(body), CreatedAt: m.Now()})
}

func (m *Manager) postForm(ctx context.Context, endpoint, token string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return m.do(req, out)
}

func (m *Manager) postJSON(ctx context.Context, endpoint, token string, payload any, out any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return m.do(req, out)
}

func (m *Manager) getNoPage(ctx context.Context, endpoint, token string, out any) error {
	_, err := m.get(ctx, endpoint, token, out)
	return err
}

func (m *Manager) get(ctx context.Context, endpoint, token string, out any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	next := false
	err = m.doWithResponse(req, out, func(resp *http.Response) {
		next = strings.Contains(resp.Header.Get("Link"), `rel="next"`)
	})
	return next, err
}

func (m *Manager) do(req *http.Request, out any) error {
	return m.doWithResponse(req, out, nil)
}

func (m *Manager) doWithResponse(req *http.Request, out any, seen func(*http.Response)) error {
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if seen != nil {
		seen(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("github %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil && len(body) > 0 {
		return json.Unmarshal(body, out)
	}
	return nil
}

func gitRun(dir string, args ...string) (string, error) {
	return gitRunWithEnv(dir, nil, args...)
}

func gitRunWithEnv(dir string, extraEnv []string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C", "GIT_PAGER=cat")
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func githubGitEnv(token string) []string {
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.https://github.com/.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: Bearer " + token,
	}
}

func normalized(in []string) []string {
	out := make([]string, 0, len(in))
	for _, f := range in {
		f = filepath.Clean(f)
		if f != "." && !strings.HasPrefix(f, "..") && !strings.HasPrefix(f, "/") {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
