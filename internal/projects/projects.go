// Package projects implements the Project Workspace deep module: one
// directory per project under ~/claver/projects/<id>, never shared, with
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
	"strconv"
	"strings"

	"github.com/rockclaver/claver/agent/internal/store"
)

// ErrDirtyTree signals that a branch operation refused to act on a workspace
// with uncommitted changes. Callers can re-invoke with Force=true after
// explicit user confirmation (mobile UI: "you have N uncommitted changes,
// continue?").
var ErrDirtyTree = errors.New("workspace has uncommitted changes")

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
	if _, err := runWithEnv(m.Root, env, "git", "clone", "--quiet", url, dir); err != nil {
		_ = os.RemoveAll(dir)
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

func countNonEmptyLines(s string) int {
	n := 0
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}
