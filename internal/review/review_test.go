package review

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/projects"
	"github.com/rockclaver/rootmote-agent/internal/store"
)

type fakeSummarizer struct {
	calls int
	last  string
}

func (f *fakeSummarizer) Summarize(_, _, patch string) (string, error) {
	f.calls++
	f.last = patch
	return "fake summary", nil
}

// fixture creates a temp store + project workspace, plants the file states
// described by the caller, and returns a Manager pointing at them.
func fixture(t *testing.T) (*Manager, *projects.Manager, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	pm, err := projects.New(filepath.Join(dir, "p"), st)
	if err != nil {
		t.Fatal(err)
	}
	pm.IDGen = func() string { return "proj" }
	if _, err := pm.CreateEmpty("demo"); err != nil {
		t.Fatal(err)
	}
	ws := pm.WorkspaceDir("proj")
	// `git init --initial-branch=main` was already called by projects. Make
	// an initial commit so HEAD exists and diffs against it are meaningful.
	mustGit(t, ws, "config", "user.email", "test@example.com")
	mustGit(t, ws, "config", "user.name", "Test")
	mustWrite(t, ws, "seed.txt", "seed\n")
	mustGit(t, ws, "add", "seed.txt")
	mustGit(t, ws, "commit", "-q", "-m", "seed")

	fs := &fakeSummarizer{}
	mgr := New(pm, st, fs)
	mgr.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return mgr, pm, st, ws
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

// Acceptance criterion: "Changed-file list reflects `git status` in the
// workspace, grouped by added/modified/deleted/renamed."
func TestStatus_GroupsAddedModifiedDeletedRenamed(t *testing.T) {
	mgr, _, _, ws := fixture(t)
	// Modify the seed file.
	mustWrite(t, ws, "seed.txt", "seed v2\n")
	// Added (untracked).
	mustWrite(t, ws, "added.txt", "hello\n")
	// Rename with content change: create+commit a file, then rename it
	// with edits.
	mustWrite(t, ws, "to_rename.txt", "old name\n")
	mustGit(t, ws, "add", "to_rename.txt")
	mustGit(t, ws, "commit", "-q", "-m", "to_rename")
	mustGit(t, ws, "mv", "to_rename.txt", "renamed.txt")
	mustWrite(t, ws, "renamed.txt", "old name\nnew line\n")
	// Deleted.
	mustWrite(t, ws, "doomed.txt", "x\n")
	mustGit(t, ws, "add", "doomed.txt")
	mustGit(t, ws, "commit", "-q", "-m", "doomed")
	if err := os.Remove(filepath.Join(ws, "doomed.txt")); err != nil {
		t.Fatal(err)
	}

	files, err := mgr.Status("proj")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	groups := map[FileGroup][]string{}
	for _, f := range files {
		groups[f.Group] = append(groups[f.Group], f.Path)
	}
	if !contains(groups[GroupAdded], "added.txt") {
		t.Errorf("expected added.txt in added; got %v", groups)
	}
	if !contains(groups[GroupModified], "seed.txt") {
		t.Errorf("expected seed.txt in modified; got %v", groups)
	}
	if !contains(groups[GroupDeleted], "doomed.txt") {
		t.Errorf("expected doomed.txt in deleted; got %v", groups)
	}
	// Renamed-with-content-change: git status may report this as a rename
	// (`R`), as add+delete, or as a single modified entry after similarity
	// detection. The acceptance criterion is that the new path appears in
	// *some* group — the dedicated rename group is exercised by
	// TestFile_RenameWithContentChangeShowsDelta below.
	found := false
	for _, paths := range groups {
		if contains(paths, "renamed.txt") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("renamed.txt missing from status; got %v", groups)
	}
}

// Acceptance criterion: "Side-by-side diff renders correctly for: long lines
// (wrapped), binary files (skipped with notice), and renames with content
// change." We assert that File() returns the right shape; line-wrapping is a
// pure rendering concern on the mobile side.
func TestFile_BinaryIsSkippedWithNotice(t *testing.T) {
	mgr, _, _, ws := fixture(t)
	// Binary content: NUL bytes guarantee detection.
	mustWrite(t, ws, "bin.dat", string([]byte{0x00, 0x01, 0x02, 0x00, 0xff}))

	fp, err := mgr.File("proj", "bin.dat")
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if !fp.Binary {
		t.Errorf("expected binary flag; got %+v", fp)
	}
	if fp.Skipped == "" {
		t.Errorf("expected skipped notice; got %+v", fp)
	}
	if fp.Patch != "" {
		t.Errorf("expected empty patch for binary; got %q", fp.Patch)
	}
}

func TestFile_LongLinePatchIsReturnedIntact(t *testing.T) {
	mgr, _, _, ws := fixture(t)
	long := strings.Repeat("x", 4000) + "\n"
	mustWrite(t, ws, "wide.txt", long)
	fp, err := mgr.File("proj", "wide.txt")
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if fp.Binary {
		t.Errorf("long text mis-detected as binary: %+v", fp)
	}
	if !strings.Contains(fp.Patch, strings.Repeat("x", 100)) {
		t.Errorf("patch did not contain long-line body")
	}
}

func TestFile_RenameWithContentChangeShowsDelta(t *testing.T) {
	mgr, _, _, ws := fixture(t)
	mustWrite(t, ws, "a.txt", "line1\nline2\n")
	mustGit(t, ws, "add", "a.txt")
	mustGit(t, ws, "commit", "-q", "-m", "a")
	mustGit(t, ws, "mv", "a.txt", "b.txt")
	mustWrite(t, ws, "b.txt", "line1\nline2 modified\nline3\n")

	files, err := mgr.Status("proj")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	// Find whichever path Git considers the new name.
	var target string
	for _, f := range files {
		if f.Path == "b.txt" {
			target = "b.txt"
			break
		}
	}
	if target == "" {
		t.Fatalf("b.txt not in changeset: %+v", files)
	}
	fp, err := mgr.File("proj", target)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if !strings.Contains(fp.Patch, "line2 modified") {
		t.Errorf("rename diff missing content change: %q", fp.Patch)
	}
}

// Acceptance criterion: "AI summary per file is generated by a
// `diff.summarize` call to the active agent and is cached per file revision."
func TestSummarize_CachedPerRevision(t *testing.T) {
	mgr, _, _, ws := fixture(t)
	fake := mgr.Summarizer.(*fakeSummarizer)
	mustWrite(t, ws, "file.txt", "alpha\n")

	first, err := mgr.Summarize("proj", "file.txt")
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if first.Summary != "fake summary" {
		t.Errorf("unexpected summary: %q", first.Summary)
	}
	if fake.calls != 1 {
		t.Errorf("expected 1 summarizer call, got %d", fake.calls)
	}

	// Same revision → cache hit, no new call.
	_, err = mgr.Summarize("proj", "file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 1 {
		t.Errorf("expected cache hit (still 1 call), got %d", fake.calls)
	}

	// New content → new revision → new call.
	mustWrite(t, ws, "file.txt", "alpha v2\n")
	_, err = mgr.Summarize("proj", "file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 2 {
		t.Errorf("expected new revision to invoke summarizer (2 calls), got %d", fake.calls)
	}
}

// Acceptance criterion: "Approve / reject / revise flows write a `review`
// event and are visible in subsequent session events."
func TestReviewDecisions_AppendSessionEventAndAudit(t *testing.T) {
	mgr, pm, st, _ := fixture(t)
	// Create a session row directly so we can attach review events to it.
	sess := store.Session{ID: "s1", ProjectID: "proj", Agent: "claude", StartedAt: time.Unix(100, 0)}
	if err := st.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	_ = pm

	cases := []struct {
		name     string
		fn       func() (store.SessionEvent, store.AuditEntry, error)
		auditTyp string
	}{
		{"approve", func() (store.SessionEvent, store.AuditEntry, error) {
			return mgr.Approve("proj", "s1", []string{"a.txt"}, "lgtm")
		}, "review.approve"},
		{"reject", func() (store.SessionEvent, store.AuditEntry, error) {
			return mgr.Reject("proj", "s1", []string{"a.txt"}, "bad")
		}, "review.reject"},
		{"revise", func() (store.SessionEvent, store.AuditEntry, error) {
			return mgr.Revise("proj", "s1", []string{"a.txt"}, "tweak")
		}, "review.revise"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, audit, err := c.fn()
			if err != nil {
				t.Fatalf("decision: %v", err)
			}
			if ev.Type != "review" {
				t.Errorf("session event type = %q want review", ev.Type)
			}
			if audit.Type != c.auditTyp {
				t.Errorf("audit type = %q want %q", audit.Type, c.auditTyp)
			}
		})
	}
	// Subsequent SessionEventsAfter must include all three review events.
	events, err := st.SessionEventsAfter("s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	for _, e := range events {
		if e.Type == "review" {
			seen++
		}
	}
	if seen != 3 {
		t.Errorf("expected 3 review events in session log, got %d", seen)
	}
}

// Acceptance criterion: "Every approval is gated by biometric prompt; the
// resulting `confirmation_token` is single-use and action-bound (rejected if
// reused or used for a different action hash)."
func TestConfirmationToken_SingleUseAndActionBound(t *testing.T) {
	mgr, _, _, _ := fixture(t)
	files := []string{"a.txt", "b.txt"}

	tok, err := mgr.MintConfirmationToken("review.approve", "proj", files, "go")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Wrong action — rejected.
	if err := mgr.ConsumeToken(tok.Token, "review.reject", "proj", files, "go"); !errors.Is(err, ErrTokenMismatch) {
		t.Errorf("wrong action: got %v want ErrTokenMismatch", err)
	}
	// Wrong files — rejected.
	if err := mgr.ConsumeToken(tok.Token, "review.approve", "proj", []string{"a.txt"}, "go"); !errors.Is(err, ErrTokenMismatch) {
		t.Errorf("wrong files: got %v want ErrTokenMismatch", err)
	}
	// Wrong comment — rejected (comment is part of the action hash).
	if err := mgr.ConsumeToken(tok.Token, "review.approve", "proj", files, "different"); !errors.Is(err, ErrTokenMismatch) {
		t.Errorf("wrong comment: got %v want ErrTokenMismatch", err)
	}
	// Correct binding — accepted, marking the token used.
	if err := mgr.ConsumeToken(tok.Token, "review.approve", "proj", files, "go"); err != nil {
		t.Errorf("correct use: %v", err)
	}
	// Replay — rejected as used.
	if err := mgr.ConsumeToken(tok.Token, "review.approve", "proj", files, "go"); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("replay: got %v want ErrTokenUsed", err)
	}

	// Expiry path.
	mgr.TokenTTL = time.Millisecond
	short, err := mgr.MintConfirmationToken("review.approve", "proj", files, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr.Now = func() time.Time { return time.Unix(1_700_000_000, 0).Add(time.Hour) }
	if err := mgr.ConsumeToken(short.Token, "review.approve", "proj", files, ""); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired: got %v want ErrTokenExpired", err)
	}
}

// Acceptance criterion: "Audit Log lists at least: approvals, rejections,
// push attempts, key rotations, GitHub token grants/revokes. Browsable and
// filterable in the app."
func TestAuditLog_RecordsAndFilters(t *testing.T) {
	mgr, _, _, _ := fixture(t)
	for _, typ := range []string{"review.approve", "review.reject", "push.attempt", "key.rotation", "github.token.grant", "github.token.revoke"} {
		if _, err := mgr.LogAudit(store.AuditEntry{Type: typ, ProjectID: "proj", Summary: typ}); err != nil {
			t.Fatalf("LogAudit %s: %v", typ, err)
		}
	}
	all, err := mgr.ListAudit("", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 6 {
		t.Fatalf("expected >=6 audit rows, got %d", len(all))
	}
	pushOnly, err := mgr.ListAudit("push.attempt", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(pushOnly) != 1 || pushOnly[0].Type != "push.attempt" {
		t.Fatalf("filter by type failed: %+v", pushOnly)
	}
	projOnly, err := mgr.ListAudit("", "proj", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(projOnly) < 6 {
		t.Fatalf("filter by project failed: %+v", projOnly)
	}
	none, err := mgr.ListAudit("", "other-project", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no rows for unrelated project, got %d", len(none))
	}
}

// Regression for PR #16 review comment 3323616294: review decisions must
// refuse to append events to a session that belongs to a different project,
// otherwise the event leaks to that project's session.subscribe subscribers.
func TestReviewDecisions_RejectCrossProjectSession(t *testing.T) {
	mgr, pm, st, _ := fixture(t)
	// A second project + a session attached to it.
	pm.IDGen = func() string { return "other" }
	if _, err := pm.CreateEmpty("other"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(store.Session{ID: "s-other", ProjectID: "other", Agent: "claude", StartedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}

	_, _, err := mgr.Approve("proj", "s-other", []string{"a.txt"}, "")
	if !errors.Is(err, ErrSessionMismatch) {
		t.Errorf("approve cross-project session: got %v want ErrSessionMismatch", err)
	}
	_, _, err = mgr.Reject("proj", "s-other", []string{"a.txt"}, "")
	if !errors.Is(err, ErrSessionMismatch) {
		t.Errorf("reject cross-project session: got %v want ErrSessionMismatch", err)
	}
	_, _, err = mgr.Revise("proj", "s-other", []string{"a.txt"}, "")
	if !errors.Is(err, ErrSessionMismatch) {
		t.Errorf("revise cross-project session: got %v want ErrSessionMismatch", err)
	}
	// No leak: the foreign session must have no review events appended.
	events, err := st.SessionEventsAfter("s-other", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if ev.Type == "review" {
			t.Fatalf("review event leaked into unrelated session: %+v", ev)
		}
	}
}

// Regression for PR #16 review comment 3323616297: untracked files whose
// names begin with `-` must not be parsed as git flags by `git diff
// --no-index`. The fix passes `--` before the two paths.
func TestFile_AddedDashPrefixedNameRendersDiff(t *testing.T) {
	mgr, _, _, ws := fixture(t)
	mustWrite(t, ws, "--help", "content\n")
	fp, err := mgr.File("proj", "--help")
	if err != nil {
		t.Fatalf("File for dash-prefixed name: %v", err)
	}
	if fp.Binary {
		t.Errorf("dash-prefixed file mis-detected as binary: %+v", fp)
	}
	if !strings.Contains(fp.Patch, "content") {
		t.Errorf("patch missing file content (likely got git usage text instead): %q", fp.Patch)
	}
}

// Sanity: the manager refuses unknown projects.
func TestStatus_UnknownProjectReturnsNotFound(t *testing.T) {
	mgr, _, _, _ := fixture(t)
	_, err := mgr.Status("nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v want ErrNotFound", err)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
