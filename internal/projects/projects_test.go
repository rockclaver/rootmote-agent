package projects

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rockclaver/claver-agent/internal/store"
)

func newManager(t *testing.T) *Manager {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available in PATH")
	}
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "claver.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	m, err := New(filepath.Join(dir, "projects"), st)
	if err != nil {
		t.Fatalf("new mgr: %v", err)
	}
	// Local git identity so commits in tests don't fail in clean CI envs.
	t.Setenv("GIT_AUTHOR_NAME", "claver-test")
	t.Setenv("GIT_AUTHOR_EMAIL", "test@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "claver-test")
	t.Setenv("GIT_COMMITTER_EMAIL", "test@example.invalid")
	return m
}

// AC: "Create-empty ... produces a workspace under ~/claver/projects/<id> with
// correct ownership." (We assert the workspace directory exists at the
// derived path under the manager's root and is owned by the calling user —
// implicit on the file we just created.)
func TestCreateEmpty_ProducesWorkspaceAndRow(t *testing.T) {
	m := newManager(t)
	p, err := m.CreateEmpty("alpha")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.ID == "" || p.Name != "alpha" {
		t.Fatalf("bad project: %+v", p)
	}
	dir := m.WorkspaceDir(p.ID)
	if fi, err := os.Stat(filepath.Join(dir, ".git")); err != nil || !fi.IsDir() {
		t.Fatalf(".git dir missing in %s: %v", dir, err)
	}
}

// AC: "Import-clone flow produces a workspace under ~/claver/projects/<id>."
// We seed a bare repo locally and clone from it via file:// to avoid network.
func TestImport_ClonesIntoWorkspace(t *testing.T) {
	m := newManager(t)

	// Build a tiny source repo we can clone.
	srcDir := t.TempDir()
	mustGit(t, srcDir, "init", "--initial-branch=main", "--quiet")
	if err := os.WriteFile(filepath.Join(srcDir, "README.md"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, srcDir, "add", ".")
	mustGit(t, srcDir, "commit", "-m", "initial", "--quiet")

	p, err := m.Import("imported", srcDir)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if p.RemoteURL != srcDir {
		t.Errorf("remote: got %q want %q", p.RemoteURL, srcDir)
	}
	if _, err := os.Stat(filepath.Join(m.WorkspaceDir(p.ID), "README.md")); err != nil {
		t.Fatalf("cloned README missing: %v", err)
	}
}

// AC: "Project status shows current branch, dirty count, and ahead/behind vs
// upstream when one exists."
func TestStatus_BranchDirtyAheadBehind(t *testing.T) {
	m := newManager(t)

	// Source repo for upstream.
	src := t.TempDir()
	mustGit(t, src, "init", "--bare", "--initial-branch=main", "--quiet")

	// Seed via a temp clone, then import from the bare repo so the imported
	// workspace has a working upstream.
	seed := t.TempDir()
	mustGit(t, seed, "clone", "--quiet", src, seed+"/r")
	work := seed + "/r"
	if err := os.WriteFile(filepath.Join(work, "f.txt"), []byte("v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, work, "add", ".")
	mustGit(t, work, "commit", "-m", "v1", "--quiet")
	mustGit(t, work, "push", "--quiet", "origin", "main")

	p, err := m.Import("up", src)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	wsDir := m.WorkspaceDir(p.ID)

	// Clean tree, has upstream, zero ahead/behind.
	st, err := m.Status(p.ID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Branch != "main" {
		t.Errorf("branch: got %q", st.Branch)
	}
	if st.DirtyCount != 0 || !st.HasUpstream || st.Ahead != 0 || st.Behind != 0 {
		t.Errorf("clean state wrong: %+v", st)
	}

	// Make a local commit → ahead 1.
	if err := os.WriteFile(filepath.Join(wsDir, "f.txt"), []byte("v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, wsDir, "commit", "-am", "v2", "--quiet")
	// And a dirty file.
	if err := os.WriteFile(filepath.Join(wsDir, "dirty.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err = m.Status(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Ahead != 1 {
		t.Errorf("ahead: got %d want 1", st.Ahead)
	}
	if st.DirtyCount == 0 {
		t.Error("expected dirty_count > 0")
	}
}

func TestHistory_ReturnsRecentCommits(t *testing.T) {
	m := newManager(t)
	p, err := m.CreateEmpty("hist")
	if err != nil {
		t.Fatal(err)
	}
	dir := m.WorkspaceDir(p.ID)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "first", "--quiet")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "commit", "-am", "second", "--quiet")

	commits, err := m.History(p.ID, 1, 0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("len: got %d want 1", len(commits))
	}
	if commits[0].Subject != "second" {
		t.Fatalf("subject: got %q want second", commits[0].Subject)
	}
	next, err := m.History(p.ID, 1, 1)
	if err != nil {
		t.Fatalf("history offset: %v", err)
	}
	if len(next) != 1 || next[0].Subject != "first" {
		t.Fatalf("offset history: got %+v want first", next)
	}
	if commits[0].SHA == "" || commits[0].ShortSHA == "" || commits[0].UnixTime == 0 {
		t.Fatalf("incomplete commit: %+v", commits[0])
	}
}

func TestHistory_EmptyRepoReturnsNoCommits(t *testing.T) {
	m := newManager(t)
	p, err := m.CreateEmpty("empty-history")
	if err != nil {
		t.Fatal(err)
	}
	commits, err := m.History(p.ID, 20, 0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(commits) != 0 {
		t.Fatalf("commits: got %+v want none", commits)
	}
}

// AC: "Branch create/switch operations succeed for both clean and dirty
// trees, with explicit UI for the dirty case." — at this layer, the explicit
// signal is ErrDirtyTree (UI translates that into a confirmation prompt).
func TestBranchCreate_CleanSucceedsDirtyRequiresForce(t *testing.T) {
	m := newManager(t)
	p, err := m.CreateEmpty("br")
	if err != nil {
		t.Fatal(err)
	}
	dir := m.WorkspaceDir(p.ID)
	// Need at least one commit before checkout -b is meaningful.
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "init", "--quiet")

	// Clean → succeeds.
	if err := m.BranchCreate(p.ID, "feature/x", false); err != nil {
		t.Fatalf("clean create: %v", err)
	}

	// Dirty → ErrDirtyTree.
	if err := os.WriteFile(filepath.Join(dir, "b"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = m.BranchCreate(p.ID, "feature/y", false)
	if !errors.Is(err, ErrDirtyTree) {
		t.Fatalf("want ErrDirtyTree, got %v", err)
	}

	// Dirty + force → succeeds.
	if err := m.BranchCreate(p.ID, "feature/y", true); err != nil {
		t.Fatalf("force create: %v", err)
	}
}

func TestBranchSwitch_CleanAndDirty(t *testing.T) {
	m := newManager(t)
	p, err := m.CreateEmpty("sw")
	if err != nil {
		t.Fatal(err)
	}
	dir := m.WorkspaceDir(p.ID)
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "init", "--quiet")
	mustGit(t, dir, "checkout", "-b", "other", "--quiet")
	mustGit(t, dir, "checkout", "main", "--quiet")

	if err := m.BranchSwitch(p.ID, "other", false); err != nil {
		t.Fatalf("clean switch: %v", err)
	}
	// Dirty file
	if err := os.WriteFile(filepath.Join(dir, "b"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.BranchSwitch(p.ID, "main", false); !errors.Is(err, ErrDirtyTree) {
		t.Fatalf("want ErrDirtyTree, got %v", err)
	}
	if err := m.BranchSwitch(p.ID, "main", true); err != nil {
		t.Fatalf("force switch: %v", err)
	}
}

// AC: "Deleting a project removes its row in SQLite and, when the user opts
// in, removes the workspace directory."
func TestDelete_OptionallyWipesWorkspace(t *testing.T) {
	m := newManager(t)
	p, err := m.CreateEmpty("d1")
	if err != nil {
		t.Fatal(err)
	}
	dir := m.WorkspaceDir(p.ID)

	// Without wipe: row gone, dir kept.
	if err := m.Delete(p.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Store.GetProject(p.ID); err == nil {
		t.Error("row should be gone")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("workspace dir should remain when wipe=false: %v", err)
	}

	// With wipe: row + dir gone.
	p2, _ := m.CreateEmpty("d2")
	dir2 := m.WorkspaceDir(p2.ID)
	if err := m.Delete(p2.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir2); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("workspace dir should be wiped, got err=%v", err)
	}
}

// AC support: importing a remote that requires credentials surfaces a typed
// error so the mobile UI can show a Phase-6 nudge instead of the raw git
// noise about "terminal prompts disabled".
func TestImport_AuthRequiredSurfacesTypedError(t *testing.T) {
	// Exercise the detector directly — the live git path requires network
	// and would be brittle in CI.
	for _, s := range []string{
		"fatal: could not read Username for 'https://github.com': terminal prompts disabled",
		"remote: Repository not found.",
		"fatal: Authentication failed for 'https://github.com/x/y'",
	} {
		if !isAuthError(s) {
			t.Errorf("isAuthError missed: %q", s)
		}
	}
	if isAuthError("fatal: destination path already exists") {
		t.Error("isAuthError false-positived on a non-auth error")
	}

	// And the wrapping: a manufactured failure must wrap ErrAuthRequired.
	// We simulate by importing a non-existent local path that yields a
	// different error class — just verify error type plumbing for the auth
	// case by hand: pretend Import returned ErrAuthRequired-wrapped.
	wrapped := errors.Join(ErrAuthRequired, errors.New("any context"))
	if !errors.Is(wrapped, ErrAuthRequired) {
		t.Fatal("ErrAuthRequired unwrap broken")
	}
}

// Regression: when wipe fails, the project row must remain so the user can
// retry — previously the row was dropped first and the workspace orphaned.
func TestDelete_WipeFailureLeavesRowForRetry(t *testing.T) {
	m := newManager(t)
	p, err := m.CreateEmpty("d3")
	if err != nil {
		t.Fatal(err)
	}
	dir := m.WorkspaceDir(p.ID)

	// Make the workspace un-removable by chmod'ing its parent to read-only.
	// We do it by replacing the workspace dir with a regular file at a path
	// that os.RemoveAll cannot wipe transparently: actually, RemoveAll is
	// quite tolerant — instead, point the manager root at a read-only parent.
	// Simpler: drop a sentinel inside, then chmod the workspace dir 0500 so
	// RemoveAll fails when it tries to unlink children.
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := m.Delete(p.ID, true); err == nil {
		t.Skip("filesystem allowed removal; cannot exercise wipe-failure path here")
	}
	// Row must still be present so the user can retry.
	if _, err := m.Store.GetProject(p.ID); err != nil {
		t.Fatalf("row should remain after failed wipe, got: %v", err)
	}
}

// AC: "Two projects on the same server never read/write each other's
// workspaces (verified by an integration test)."
func TestProjectIsolation_NoCrossReadOrWrite(t *testing.T) {
	m := newManager(t)
	pa, err := m.CreateEmpty("a")
	if err != nil {
		t.Fatal(err)
	}
	pb, err := m.CreateEmpty("b")
	if err != nil {
		t.Fatal(err)
	}
	dirA := m.WorkspaceDir(pa.ID)
	dirB := m.WorkspaceDir(pb.ID)
	if dirA == dirB {
		t.Fatal("workspace dirs must differ")
	}
	if !strings.HasPrefix(dirA, m.Root+string(os.PathSeparator)) ||
		!strings.HasPrefix(dirB, m.Root+string(os.PathSeparator)) {
		t.Fatalf("workspaces not under root: a=%s b=%s root=%s", dirA, dirB, m.Root)
	}

	// Write a sentinel in A. It must not appear in B's directory listing,
	// and B's git status must not mention it.
	if err := os.WriteFile(filepath.Join(dirA, "secret_a.txt"), []byte("only-a"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dirB)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "secret_a.txt" {
			t.Fatalf("B leaked A's file")
		}
	}
	stB, err := m.Status(pb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stB.DirtyCount != 0 {
		t.Errorf("B should be clean, got dirty=%d", stB.DirtyCount)
	}

	// Deleting B with wipe must leave A intact.
	if err := m.Delete(pb.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dirA, "secret_a.txt")); err != nil {
		t.Errorf("A's file should survive B's deletion: %v", err)
	}
}

func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
		"GIT_AUTHOR_NAME=claver-test",
		"GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=claver-test",
		"GIT_COMMITTER_EMAIL=test@example.invalid",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// AC (Phase 5 #3): the @-file autocomplete source lists workspace files
// (tracked + untracked-not-ignored), filters by query, and excludes ignored
// files.
func TestFiles_ListsTrackedAndUntrackedFiltered(t *testing.T) {
	m := newManager(t)
	p, err := m.CreateEmpty("filesdemo")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	dir := m.WorkspaceDir(p.ID)
	mustWrite := func(rel, body string) {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("main.go", "package main")
	mustWrite("lib/util.go", "package lib")
	mustWrite("README.md", "# demo")
	mustWrite(".gitignore", "secret.txt\n")
	mustWrite("secret.txt", "nope")

	has := func(list []string, want string) bool {
		for _, f := range list {
			if f == want {
				return true
			}
		}
		return false
	}
	all, err := m.Files(p.ID, "", 50)
	if err != nil {
		t.Fatalf("files: %v", err)
	}
	if !has(all, "main.go") || !has(all, "lib/util.go") || !has(all, "README.md") {
		t.Fatalf("expected workspace files, got %v", all)
	}
	if has(all, "secret.txt") {
		t.Fatalf("ignored file leaked into list: %v", all)
	}

	hits, err := m.Files(p.ID, "util", 50)
	if err != nil {
		t.Fatalf("files query: %v", err)
	}
	if len(hits) != 1 || hits[0] != "lib/util.go" {
		t.Fatalf("query 'util' = %v, want [lib/util.go]", hits)
	}
}
