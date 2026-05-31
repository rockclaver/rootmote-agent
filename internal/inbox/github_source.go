package inbox

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	gh "github.com/rockclaver/claver/agent/internal/github"
	"github.com/rockclaver/claver/agent/internal/store"
)

// githubLister is the subset of *github.Manager the source needs. Exposed as
// an interface so tests can supply a stub without spinning a vault.
type githubLister interface {
	ListPRs(ctx context.Context, account, repoFullName string) ([]gh.PullRequest, error)
}

// tokenLister is the subset of *store.Store the source needs.
type tokenLister interface {
	ListGitHubTokens() ([]store.GitHubToken, error)
	ListProjects() ([]store.Project, error)
}

// GitHubSource produces inbox items for open PRs awaiting review and PRs
// whose latest commit failed CI. Lookups go through the GitHub API, so this
// source maintains its own cache rather than hitting the network on every
// inbox.list call; Start() runs the periodic refresh.
type GitHubSource struct {
	GitHub  githubLister
	Store   tokenLister
	Refresh time.Duration
	Now     func() time.Time
	// Publish, if set, is called for each new item discovered on refresh so
	// it streams to live inbox subscribers without waiting for inbox.list.
	Publish func(Item)

	mu    sync.Mutex
	cache []Item
	seen  map[string]struct{}
}

// Items returns the cached snapshot. Refresh runs in the background.
func (g *GitHubSource) Items(_ context.Context) ([]Item, error) {
	if g == nil {
		return nil, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Item, len(g.cache))
	copy(out, g.cache)
	return out, nil
}

// Start kicks off a goroutine that refreshes the cache every g.Refresh until
// ctx is cancelled. It runs one refresh immediately so the first inbox.list
// call has data.
func (g *GitHubSource) Start(ctx context.Context) {
	if g == nil || g.GitHub == nil || g.Store == nil {
		return
	}
	if g.Refresh <= 0 {
		g.Refresh = 2 * time.Minute
	}
	if g.Now == nil {
		g.Now = time.Now
	}
	go func() {
		g.refresh(ctx)
		ticker := time.NewTicker(g.Refresh)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.refresh(ctx)
			}
		}
	}()
}

func (g *GitHubSource) refresh(ctx context.Context) {
	tokens, err := g.Store.ListGitHubTokens()
	if err != nil || len(tokens) == 0 {
		return
	}
	projects, err := g.Store.ListProjects()
	if err != nil {
		return
	}
	now := g.Now()
	var fresh []Item
	for _, p := range projects {
		full := GitHubRepoFromURL(p.RemoteURL)
		if full == "" {
			continue
		}
		owner := strings.SplitN(full, "/", 2)[0]
		// Try the account whose login owns the repo first; fall back to any
		// other stored token. ListGitHubTokens returns AccountLogin verbatim.
		accounts := pickAccounts(tokens, owner)
		var prs []gh.PullRequest
		for _, acct := range accounts {
			prs, err = g.GitHub.ListPRs(ctx, acct, full)
			if err == nil {
				break
			}
		}
		if err != nil || len(prs) == 0 {
			continue
		}
		for _, pr := range prs {
			if pr.State != "open" {
				continue
			}
			if pr.CI == "failure" || pr.CI == "error" {
				fresh = append(fresh, prToItem(full, pr, TypeCIFailed, "CI failed: ", "error", now))
				continue
			}
			fresh = append(fresh, prToItem(full, pr, TypePRReview, "PR awaiting review: ", "info", now))
		}
	}
	g.mu.Lock()
	g.cache = fresh
	if g.seen == nil {
		g.seen = make(map[string]struct{})
	}
	var newItems []Item
	for _, it := range fresh {
		if _, ok := g.seen[it.ID]; !ok {
			g.seen[it.ID] = struct{}{}
			newItems = append(newItems, it)
		}
	}
	g.mu.Unlock()
	if g.Publish != nil {
		for _, it := range newItems {
			g.Publish(it)
		}
	}
}

func prToItem(repo string, pr gh.PullRequest, t Type, titlePrefix, severity string, now time.Time) Item {
	return Item{
		ID:         fmt.Sprintf("%s:%s#%d", t, repo, pr.Number),
		Type:       t,
		Title:      titlePrefix + pr.Title,
		Body:       fmt.Sprintf("%s #%d", repo, pr.Number),
		Severity:   severity,
		CreatedAt:  now,
		Actionable: false,
		Data: map[string]any{
			"repo":   repo,
			"number": pr.Number,
			"url":    pr.URL,
			"head":   pr.Head,
			"ci":     pr.CI,
		},
	}
}

// GitHubRepoFromURL parses a github clone URL into "owner/repo", or returns
// "" if the URL is not a recognised github URL. Accepts https and ssh forms.
func GitHubRepoFromURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	u = strings.TrimSuffix(u, ".git")
	for _, prefix := range []string{
		"https://github.com/", "http://github.com/",
		"git@github.com:", "ssh://git@github.com/",
	} {
		if strings.HasPrefix(u, prefix) {
			rest := strings.TrimPrefix(u, prefix)
			parts := strings.SplitN(rest, "/", 3)
			if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
				return ""
			}
			return parts[0] + "/" + parts[1]
		}
	}
	return ""
}

func pickAccounts(tokens []store.GitHubToken, owner string) []string {
	owner = strings.ToLower(owner)
	var matching, others []string
	for _, t := range tokens {
		if strings.EqualFold(t.AccountLogin, owner) {
			matching = append(matching, t.AccountLogin)
		} else if t.AccountLogin != "" {
			others = append(others, t.AccountLogin)
		}
	}
	return append(matching, others...)
}
