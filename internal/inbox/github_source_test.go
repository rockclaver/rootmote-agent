package inbox

import (
	"context"
	"errors"
	"testing"
	"time"

	gh "github.com/rockclaver/claver/agent/internal/github"
	"github.com/rockclaver/claver/agent/internal/store"
)

func TestGitHubRepoFromURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/octo/src.git":   "octo/src",
		"https://github.com/octo/src":       "octo/src",
		"git@github.com:octo/src.git":       "octo/src",
		"ssh://git@github.com/octo/src.git": "octo/src",
		"https://gitlab.com/octo/src.git":   "",
		"":                                  "",
		"not-a-url":                         "",
	}
	for in, want := range cases {
		if got := GitHubRepoFromURL(in); got != want {
			t.Errorf("GitHubRepoFromURL(%q) = %q want %q", in, got, want)
		}
	}
}

type fakeListers struct {
	tokens   []store.GitHubToken
	projects []store.Project
}

func (f *fakeListers) ListGitHubTokens() ([]store.GitHubToken, error) {
	return f.tokens, nil
}
func (f *fakeListers) ListProjects() ([]store.Project, error) {
	return f.projects, nil
}

type fakeGH struct {
	byRepo map[string][]gh.PullRequest
	err    error
}

func (f *fakeGH) ListPRs(_ context.Context, _, repo string) ([]gh.PullRequest, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byRepo[repo], nil
}

func TestGitHubSource_RefreshCachesPRsAndCIFailures(t *testing.T) {
	src := &GitHubSource{
		Store: &fakeListers{
			tokens: []store.GitHubToken{{AccountLogin: "octo"}},
			projects: []store.Project{
				{ID: "p1", RemoteURL: "https://github.com/octo/src.git"},
				{ID: "p2", RemoteURL: "https://gitlab.com/x/y"},
			},
		},
		GitHub: &fakeGH{
			byRepo: map[string][]gh.PullRequest{
				"octo/src": {
					{Number: 11, Title: "fix bug", State: "open", CI: "success"},
					{Number: 12, Title: "broken", State: "open", CI: "failure"},
					{Number: 13, Title: "closed", State: "closed", CI: "success"},
				},
			},
		},
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	src.refresh(context.Background())
	items, _ := src.Items(context.Background())
	if len(items) != 2 {
		t.Fatalf("want 2 items (PR + CI failure), got %d", len(items))
	}
	var sawPR, sawCI bool
	for _, it := range items {
		switch it.Type {
		case TypePRReview:
			sawPR = true
		case TypeCIFailed:
			sawCI = true
		}
	}
	if !sawPR || !sawCI {
		t.Fatalf("expected one PRReview and one CIFailed, got: %+v", items)
	}
}

func TestGitHubSource_RefreshPublishesNewItemsOnce(t *testing.T) {
	var published []Item
	src := &GitHubSource{
		Store: &fakeListers{
			tokens: []store.GitHubToken{{AccountLogin: "octo"}},
			projects: []store.Project{
				{RemoteURL: "https://github.com/octo/src"},
			},
		},
		GitHub: &fakeGH{
			byRepo: map[string][]gh.PullRequest{
				"octo/src": {{Number: 1, Title: "x", State: "open", CI: "failure"}},
			},
		},
		Now:     time.Now,
		Publish: func(it Item) { published = append(published, it) },
	}
	src.refresh(context.Background())
	src.refresh(context.Background())
	if len(published) != 1 {
		t.Fatalf("Publish should fire once per new ID, got %d", len(published))
	}
}

func TestGitHubSource_HandlesAPIErrorPerRepo(t *testing.T) {
	src := &GitHubSource{
		Store: &fakeListers{
			tokens:   []store.GitHubToken{{AccountLogin: "octo"}},
			projects: []store.Project{{RemoteURL: "https://github.com/octo/src"}},
		},
		GitHub: &fakeGH{err: errors.New("boom")},
		Now:    time.Now,
	}
	src.refresh(context.Background())
	items, _ := src.Items(context.Background())
	if len(items) != 0 {
		t.Fatalf("want empty cache on error, got %d", len(items))
	}
}

func TestGitHubSource_NilManagerSafe(t *testing.T) {
	var src *GitHubSource
	items, err := src.Items(context.Background())
	if err != nil || items != nil {
		t.Fatalf("nil source should return nil, nil")
	}
	src = &GitHubSource{}
	src.Start(context.Background()) // no GitHub/Store; should not panic
}
