// Package projects implements the Project Workspace deep module: one
// directory per project under ~/rootmote/projects/<id>, never shared, with
// git operations exposed at a small, testable surface.
package projects

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rockclaver/rootmote-agent/internal/store"
)

// ErrDirtyTree signals that a branch operation refused to act on a workspace
// with uncommitted changes. Callers can re-invoke with Force=true after
// explicit user confirmation (mobile UI: "you have N uncommitted changes,
// continue?").
var ErrDirtyTree = errors.New("workspace has uncommitted changes")

// ErrAuthRequired signals that a clone refused because the remote demands
// credentials. In Phase 3 there is no auth path yet; Phase 6's GitHub Device
// Flow will fill this gap. The mobile UI translates this into "this repo is
// private — sign in to GitHub to import it."
var ErrAuthRequired = errors.New("remote requires authentication")

// ErrNotFound mirrors store.ErrNotFound at this layer so callers don't need to
// import the store package.
var ErrNotFound = store.ErrNotFound

// Status is the workspace's git status snapshot.
type Status struct {
	Branch      string `json:"branch"`
	DirtyCount  int    `json:"dirty_count"`
	HasUpstream bool   `json:"has_upstream"`
	Ahead       int    `json:"ahead"`
	Behind      int    `json:"behind"`
}

// Commit is one entry from a project's local git history.
type Commit struct {
	SHA         string `json:"sha"`
	ShortSHA    string `json:"short_sha"`
	AuthorName  string `json:"author_name"`
	AuthorEmail string `json:"author_email"`
	UnixTime    int64  `json:"unix_time"`
	Subject     string `json:"subject"`
}

// Manager owns the workspace root and the State Store.
type Manager struct {
	Root  string
	Store *store.Store
	// IDGen makes new project IDs. Defaults to a 16-byte random hex.
	IDGen func() string
}

// New constructs a Manager and ensures the workspace root exists.
func New(root string, st *store.Store) (*Manager, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &Manager{Root: root, Store: st, IDGen: randomID}, nil
}

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// WorkspaceDir returns the absolute path for a project ID.
func (m *Manager) WorkspaceDir(id string) string {
	return filepath.Join(m.Root, id)
}

// CreateEmpty initialises a fresh git repo at the project's workspace.
func (m *Manager) CreateEmpty(name string) (store.Project, error) {
	id := m.IDGen()
	dir := m.WorkspaceDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return store.Project{}, err
	}
	if _, err := run(dir, "git", "init", "--initial-branch=main", "--quiet"); err != nil {
		_ = os.RemoveAll(dir)
		return store.Project{}, fmt.Errorf("git init: %w", err)
	}
	p := store.Project{ID: id, Name: name}
	if err := m.Store.CreateProject(p); err != nil {
		_ = os.RemoveAll(dir)
		return store.Project{}, err
	}
	return m.Store.GetProject(id)
}

// Import clones an existing repository by URL into the project's workspace.
func (m *Manager) Import(name, url string) (store.Project, error) {
	return m.ImportWithEnv(name, url, nil)
}

// ImportWithEnv clones an existing repository with additional git environment.
// Callers use this for one-shot credentials such as GitHub extraHeader values;
// persisted project state keeps only the clean remote URL.
func (m *Manager) ImportWithEnv(name, url string, env []string) (store.Project, error) {
	if url == "" {
		return store.Project{}, errors.New("import: url is required")
	}
	id := m.IDGen()
	dir := m.WorkspaceDir(id)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return store.Project{}, err
	}
	if out, err := runWithEnv(m.Root, env, "git", "clone", "--quiet", url, dir); err != nil {
		_ = os.RemoveAll(dir)
		if isAuthError(out) {
			return store.Project{}, fmt.Errorf("%w: %s", ErrAuthRequired, url)
		}
		return store.Project{}, fmt.Errorf("git clone: %w", err)
	}
	p := store.Project{ID: id, Name: name, RemoteURL: url}
	if err := m.Store.CreateProject(p); err != nil {
		_ = os.RemoveAll(dir)
		return store.Project{}, err
	}
	return m.Store.GetProject(id)
}

// List returns all known projects.
func (m *Manager) List() ([]store.Project, error) {
	return m.Store.ListProjects()
}

// Get loads a single project row.
func (m *Manager) Get(id string) (store.Project, error) {
	return m.Store.GetProject(id)
}

// Status reports the workspace's git state.
func (m *Manager) Status(id string) (Status, error) {
	if _, err := m.Store.GetProject(id); err != nil {
		return Status{}, err
	}
	dir := m.WorkspaceDir(id)

	// symbolic-ref works even on an unborn branch (fresh `git init` with no
	// commits yet), which rev-parse HEAD does not.
	branch, err := run(dir, "git", "symbolic-ref", "--short", "HEAD")
	if err != nil {
		// Detached HEAD: fall back to rev-parse.
		if rp, rpErr := run(dir, "git", "rev-parse", "--abbrev-ref", "HEAD"); rpErr == nil {
			branch = rp
		} else {
			return Status{}, fmt.Errorf("read branch: %w", err)
		}
	}
	st := Status{Branch: strings.TrimSpace(branch)}

	porcelain, err := run(dir, "git", "status", "--porcelain")
	if err != nil {
		return Status{}, fmt.Errorf("status: %w", err)
	}
	st.DirtyCount = countNonEmptyLines(porcelain)

	if ub, err := run(dir, "git", "rev-parse", "--abbrev-ref", "@{upstream}"); err == nil {
		st.HasUpstream = true
		// "ahead\tbehind"
		if counts, err := run(dir, "git", "rev-list", "--left-right", "--count", "HEAD..."+strings.TrimSpace(ub)); err == nil {
			parts := strings.Fields(strings.TrimSpace(counts))
			if len(parts) == 2 {
				st.Ahead, _ = strconv.Atoi(parts[0])
				st.Behind, _ = strconv.Atoi(parts[1])
			}
		}
	}
	return st, nil
}

// History returns recent commits from the project's local git repository.
func (m *Manager) History(id string, limit int, offset int) ([]Commit, error) {
	if _, err := m.Store.GetProject(id); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	dir := m.WorkspaceDir(id)
	out, err := run(dir, "git", "log", "--skip", strconv.Itoa(offset), "-n", strconv.Itoa(limit), "--format=%H%x1f%h%x1f%an%x1f%ae%x1f%at%x1f%s%x1e")
	if err != nil {
		if isNoCommitsError(out) {
			return []Commit{}, nil
		}
		return nil, fmt.Errorf("history: %w", err)
	}
	records := strings.Split(out, "\x1e")
	commits := make([]Commit, 0, len(records))
	for _, record := range records {
		record = strings.TrimSpace(record)
		if record == "" {
			continue
		}
		parts := strings.SplitN(record, "\x1f", 6)
		if len(parts) != 6 {
			return nil, fmt.Errorf("history: malformed git log record")
		}
		ts, err := strconv.ParseInt(parts[4], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("history: parse commit time: %w", err)
		}
		commits = append(commits, Commit{
			SHA:         parts[0],
			ShortSHA:    parts[1],
			AuthorName:  parts[2],
			AuthorEmail: parts[3],
			UnixTime:    ts,
			Subject:     parts[5],
		})
	}
	return commits, nil
}

// Files returns workspace-relative file paths for @-mention autocomplete. It
// lists git-tracked plus untracked-not-ignored files (so freshly created files
// surface), filters by query (case-insensitive substring) when one is given,
// and ranks basename-prefix matches first. The result is capped at limit
// (default 50, max 200). A non-git or empty workspace yields an empty list
// rather than an error.
func (m *Manager) Files(id, query string, limit int) ([]string, error) {
	if _, err := m.Store.GetProject(id); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	dir := m.WorkspaceDir(id)
	out, err := run(dir, "git", "ls-files", "--cached", "--others", "--exclude-standard")
	if err != nil {
		// Not a git repo (or git unavailable): no autocomplete source, not fatal.
		return []string{}, nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	seen := make(map[string]struct{})
	matched := make([]string, 0, 64)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		if q == "" || strings.Contains(strings.ToLower(line), q) {
			matched = append(matched, line)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if q != "" {
			ri, rj := fileMatchRank(matched[i], q), fileMatchRank(matched[j], q)
			if ri != rj {
				return ri < rj
			}
		}
		return matched[i] < matched[j]
	})
	if len(matched) > limit {
		matched = matched[:limit]
	}
	return matched, nil
}

// fileMatchRank ranks a path against a lowercased query: 0 = basename prefix,
// 1 = full-path prefix, 2 = substring elsewhere. Lower sorts first.
func fileMatchRank(path, q string) int {
	switch {
	case strings.HasPrefix(strings.ToLower(filepath.Base(path)), q):
		return 0
	case strings.HasPrefix(strings.ToLower(path), q):
		return 1
	default:
		return 2
	}
}

// BranchCreate creates a new branch and switches to it. If force is false and
// the tree is dirty, returns ErrDirtyTree so the UI can confirm.
func (m *Manager) BranchCreate(id, branch string, force bool) error {
	dir, err := m.requireClean(id, force)
	if err != nil {
		return err
	}
	if _, err := run(dir, "git", "checkout", "-b", branch); err != nil {
		return fmt.Errorf("checkout -b: %w", err)
	}
	return nil
}

// BranchSwitch switches to an existing branch. If force is false and the tree
// is dirty, returns ErrDirtyTree.
func (m *Manager) BranchSwitch(id, branch string, force bool) error {
	dir, err := m.requireClean(id, force)
	if err != nil {
		return err
	}
	if _, err := run(dir, "git", "checkout", branch); err != nil {
		return fmt.Errorf("checkout: %w", err)
	}
	return nil
}

func (m *Manager) requireClean(id string, force bool) (string, error) {
	if _, err := m.Store.GetProject(id); err != nil {
		return "", err
	}
	dir := m.WorkspaceDir(id)
	if force {
		return dir, nil
	}
	porcelain, err := run(dir, "git", "status", "--porcelain")
	if err != nil {
		return "", fmt.Errorf("status: %w", err)
	}
	if countNonEmptyLines(porcelain) > 0 {
		return "", ErrDirtyTree
	}
	return dir, nil
}

// Delete removes the project row and, if wipe is true, the workspace dir.
// When wipe is requested the workspace is removed first; only on success do we
// drop the row, so a failed wipe leaves the project still listable and the
// user can retry instead of being stuck with an orphan workspace dir.
func (m *Manager) Delete(id string, wipe bool) error {
	if _, err := m.Store.GetProject(id); err != nil {
		return err
	}
	if wipe {
		if err := os.RemoveAll(m.WorkspaceDir(id)); err != nil {
			return err
		}
	}
	return m.Store.DeleteProject(id)
}

func run(dir, name string, args ...string) (string, error) {
	return runWithEnv(dir, nil, name, args...)
}

func runWithEnv(dir string, extraEnv []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	// Quieter, deterministic git: no pager, English messages.
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
		"GIT_PAGER=cat",
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// isAuthError reports whether git's combined output looks like a credentials
// refusal (private repo, bad creds, terminal prompts disabled). Phase 3 has
// no credential path; GitHub imports pass credentials through the GitHub CLI.
func isAuthError(out string) bool {
	s := strings.ToLower(out)
	switch {
	case strings.Contains(s, "terminal prompts disabled"),
		strings.Contains(s, "could not read username"),
		strings.Contains(s, "could not read password"),
		strings.Contains(s, "authentication failed"),
		strings.Contains(s, "invalid username or password"),
		strings.Contains(s, "repository not found"):
		return true
	}
	return false
}

func isNoCommitsError(out string) bool {
	s := strings.ToLower(out)
	return strings.Contains(s, "does not have any commits yet") ||
		strings.Contains(s, "your current branch") && strings.Contains(s, "does not have any commits")
}

func countNonEmptyLines(s string) int {
	n := 0
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}
