// Package review owns the Diff Renderer and Review Gate deep modules: it
// translates `git status` into the grouped, mobile-friendly file list, serves
// per-file diffs (including the binary-skip and rename-with-content-change
// cases), caches AI-generated summaries, and gates approval on a single-use,
// action-bound confirmation token minted after a fresh biometric prompt.
package review

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/projects"
	"github.com/rockclaver/rootmote-agent/internal/store"
)

// Errors returned by the review module. Callers translate them to wire-level
// error kinds.
var (
	ErrTokenInvalid    = errors.New("confirmation_token is invalid")
	ErrTokenExpired    = errors.New("confirmation_token is expired")
	ErrTokenUsed       = errors.New("confirmation_token has already been used")
	ErrTokenMismatch   = errors.New("confirmation_token does not match this action")
	ErrSessionMismatch = errors.New("session_id does not belong to project_id")
	ErrNotFound        = projects.ErrNotFound
)

// Status group buckets exposed on the wire. Matching `git status` porcelain
// columns: added / modified / deleted / renamed.
type FileGroup string

const (
	GroupAdded    FileGroup = "added"
	GroupModified FileGroup = "modified"
	GroupDeleted  FileGroup = "deleted"
	GroupRenamed  FileGroup = "renamed"
)

// ChangedFile is one row in the Phase-5 changed-file list.
type ChangedFile struct {
	Path     string    `json:"path"`
	OldPath  string    `json:"old_path,omitempty"`
	Group    FileGroup `json:"group"`
	Binary   bool      `json:"binary"`
	Revision string    `json:"revision"`
}

// FilePatch is the side-by-side-renderable patch for a single file.
type FilePatch struct {
	Path     string `json:"path"`
	OldPath  string `json:"old_path,omitempty"`
	Group    string `json:"group"`
	Binary   bool   `json:"binary"`
	Skipped  string `json:"skipped,omitempty"`
	Patch    string `json:"patch"`
	Revision string `json:"revision"`
}

// Summarizer produces a one-paragraph natural-language summary of a patch. The
// real binding for "active agent" wiring lives in the agent's session manager;
// tests inject a deterministic fake.
type Summarizer interface {
	Summarize(projectID, path, patch string) (string, error)
}

// Manager owns the State Store rows and shells out to git on the project
// workspace.
type Manager struct {
	Projects   *projects.Manager
	Store      *store.Store
	Now        func() time.Time
	TokenTTL   time.Duration
	Summarizer Summarizer

	// randToken is overridable in tests; defaults to 32 random bytes hex.
	randToken func() string
}

// New constructs a Manager with sensible defaults.
func New(p *projects.Manager, s *store.Store, sum Summarizer) *Manager {
	return &Manager{
		Projects:   p,
		Store:      s,
		Now:        time.Now,
		TokenTTL:   5 * time.Minute,
		Summarizer: sum,
		randToken:  randomToken,
	}
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Status returns the grouped changed-file list for a project workspace.
func (m *Manager) Status(projectID string) ([]ChangedFile, error) {
	dir, err := m.workspaceDir(projectID)
	if err != nil {
		return nil, err
	}
	// -z and -uall give a stable, NUL-delimited listing of every changed path
	// (staged + unstaged + untracked) including renames.
	out, err := gitRun(dir, "status", "--porcelain=v1", "-z", "-uall")
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	files := parsePorcelainZ(out)
	for i := range files {
		files[i].Binary = isBinaryFile(dir, files[i].Path)
		files[i].Revision = revision(dir, files[i].Path)
	}
	return files, nil
}

// File returns the rendered patch for one path in the workspace.
func (m *Manager) File(projectID, path string) (FilePatch, error) {
	dir, err := m.workspaceDir(projectID)
	if err != nil {
		return FilePatch{}, err
	}
	if !safeRelPath(path) {
		return FilePatch{}, fmt.Errorf("invalid path")
	}
	// We need the file's group and old_path (for renames) — re-derive from
	// status rather than trusting the caller. This also makes the diff for
	// a "renamed with content change" correctly show the content delta from
	// OldPath → Path.
	files, err := m.Status(projectID)
	if err != nil {
		return FilePatch{}, err
	}
	var target *ChangedFile
	for i := range files {
		if files[i].Path == path {
			target = &files[i]
			break
		}
	}
	if target == nil {
		return FilePatch{}, fmt.Errorf("file %q not in changeset: %w", path, ErrNotFound)
	}
	fp := FilePatch{
		Path:     target.Path,
		OldPath:  target.OldPath,
		Group:    string(target.Group),
		Binary:   target.Binary,
		Revision: target.Revision,
	}
	if target.Binary {
		fp.Skipped = "binary file"
		return fp, nil
	}
	// `git diff HEAD --` covers staged+unstaged in the working tree against
	// the last commit. For untracked (Added) files there is no HEAD blob, so
	// we render them with `--no-index /dev/null path`.
	var patchOut string
	if target.Group == GroupAdded && target.OldPath == "" {
		// `--` separates options from paths so that filenames starting with
		// a dash (e.g. "--help") are not parsed as git flags.
		patchOut, err = gitRun(dir, "diff", "--no-index", "--unified=3", "--", "/dev/null", target.Path)
		if err != nil {
			return FilePatch{}, fmt.Errorf("diff %q: %w", target.Path, err)
		}
	} else if target.OldPath != "" {
		patchOut, err = gitRun(dir, "diff", "-M", "--unified=3", "HEAD", "--", target.OldPath, target.Path)
		if err != nil {
			return FilePatch{}, fmt.Errorf("diff rename %q→%q: %w", target.OldPath, target.Path, err)
		}
	} else {
		patchOut, err = gitRun(dir, "diff", "--unified=3", "HEAD", "--", target.Path)
		if err != nil {
			return FilePatch{}, fmt.Errorf("diff %q: %w", target.Path, err)
		}
	}
	fp.Patch = patchOut
	return fp, nil
}

// Summarize returns a cached or newly-generated summary for the given file's
// current content revision.
func (m *Manager) Summarize(projectID, path string) (store.DiffSummary, error) {
	fp, err := m.File(projectID, path)
	if err != nil {
		return store.DiffSummary{}, err
	}
	if cached, err := m.Store.GetDiffSummary(projectID, path, fp.Revision); err == nil {
		return cached, nil
	}
	body := fp.Patch
	if fp.Binary {
		body = "binary file " + path
	}
	summary, err := m.Summarizer.Summarize(projectID, path, body)
	if err != nil {
		return store.DiffSummary{}, fmt.Errorf("summarize: %w", err)
	}
	row := store.DiffSummary{
		ProjectID: projectID,
		Path:      path,
		Revision:  fp.Revision,
		Summary:   summary,
		CreatedAt: m.Now(),
	}
	if err := m.Store.PutDiffSummary(row); err != nil {
		return store.DiffSummary{}, err
	}
	return row, nil
}

// MintConfirmationToken stores a fresh single-use token bound to the
// (action, project_id, sorted files, comment) tuple.
func (m *Manager) MintConfirmationToken(action, projectID string, files []string, comment string) (store.ConfirmationToken, error) {
	tok := store.ConfirmationToken{
		Token:      m.randToken(),
		ActionHash: ActionHash(action, projectID, files, comment),
		ProjectID:  projectID,
		CreatedAt:  m.Now(),
		ExpiresAt:  m.Now().Add(m.TokenTTL),
	}
	if err := m.Store.CreateConfirmationToken(tok); err != nil {
		return store.ConfirmationToken{}, err
	}
	return tok, nil
}

// ConsumeToken validates and atomically marks a token used. Returns the
// matching error sentinel if the token is missing, expired, already used, or
// bound to a different action.
func (m *Manager) ConsumeToken(token, action, projectID string, files []string, comment string) error {
	if token == "" {
		return ErrTokenInvalid
	}
	row, err := m.Store.GetConfirmationToken(token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrTokenInvalid
		}
		return err
	}
	if row.UsedAt != nil {
		return ErrTokenUsed
	}
	if !m.Now().Before(row.ExpiresAt) {
		return ErrTokenExpired
	}
	if row.ActionHash != ActionHash(action, projectID, files, comment) {
		return ErrTokenMismatch
	}
	ok, err := m.Store.MarkConfirmationTokenUsed(token, m.Now())
	if err != nil {
		return err
	}
	if !ok {
		return ErrTokenUsed
	}
	return nil
}

// Decision is the outcome of a review action.
type Decision string

const (
	DecisionApproved Decision = "approved"
	DecisionRejected Decision = "rejected"
	DecisionRevise   Decision = "revise"
)

// ReviewEvent is the structured payload appended to the session event log so
// `session.subscribe` clients observe the review decision in order.
type ReviewEvent struct {
	Decision  Decision          `json:"decision"`
	ProjectID string            `json:"project_id"`
	Files     []string          `json:"files"`
	Revisions map[string]string `json:"revisions,omitempty"`
	Comment   string            `json:"comment"`
	CreatedAt int64             `json:"created_at"`
}

// Approve writes a review event for the given files. The caller (server.go)
// must have already consumed the matching confirmation token via ConsumeToken.
func (m *Manager) Approve(projectID, sessionID string, files []string, comment string) (store.SessionEvent, store.AuditEntry, error) {
	return m.recordDecision(DecisionApproved, "review.approve", projectID, sessionID, files, comment)
}

// Reject writes a review event marking the files rejected with a free-form
// comment.
func (m *Manager) Reject(projectID, sessionID string, files []string, comment string) (store.SessionEvent, store.AuditEntry, error) {
	return m.recordDecision(DecisionRejected, "review.reject", projectID, sessionID, files, comment)
}

// Revise writes a review event asking the agent to revise the files.
func (m *Manager) Revise(projectID, sessionID string, files []string, comment string) (store.SessionEvent, store.AuditEntry, error) {
	return m.recordDecision(DecisionRevise, "review.revise", projectID, sessionID, files, comment)
}

func (m *Manager) recordDecision(d Decision, auditType, projectID, sessionID string, files []string, comment string) (store.SessionEvent, store.AuditEntry, error) {
	if _, err := m.Projects.Get(projectID); err != nil {
		return store.SessionEvent{}, store.AuditEntry{}, err
	}
	now := m.Now()
	ev := ReviewEvent{Decision: d, ProjectID: projectID, Files: files, Revisions: m.revisionsFor(projectID, files), Comment: comment, CreatedAt: now.Unix()}
	body, _ := jsonMarshal(ev)
	var sessEv store.SessionEvent
	if sessionID != "" {
		// Reject if the session belongs to a different project, otherwise a
		// client could append a review event into an unrelated session and
		// leak it to that project's `session.subscribe` subscribers.
		sess, err := m.Store.GetSession(sessionID)
		if err != nil {
			return store.SessionEvent{}, store.AuditEntry{}, err
		}
		if sess.ProjectID != projectID {
			return store.SessionEvent{}, store.AuditEntry{}, ErrSessionMismatch
		}
		s, err := m.Store.AppendSessionEvent(store.SessionEvent{
			SessionID: sessionID,
			Type:      "review",
			Data:      body,
			CreatedAt: now,
		})
		if err != nil {
			return store.SessionEvent{}, store.AuditEntry{}, err
		}
		sessEv = s
	}
	audit, err := m.Store.AppendAudit(store.AuditEntry{
		Type:      auditType,
		ProjectID: projectID,
		SessionID: sessionID,
		Actor:     "mobile",
		Summary:   string(d) + " " + strings.Join(files, ", "),
		Data:      body,
		CreatedAt: now,
	})
	if err != nil {
		return store.SessionEvent{}, store.AuditEntry{}, err
	}
	return sessEv, audit, nil
}

func (m *Manager) revisionsFor(projectID string, files []string) map[string]string {
	status, err := m.Status(projectID)
	if err != nil {
		return nil
	}
	want := map[string]struct{}{}
	for _, f := range files {
		want[f] = struct{}{}
	}
	out := map[string]string{}
	for _, f := range status {
		if _, ok := want[f.Path]; ok {
			out[f.Path] = f.Revision
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// LogAudit is a generic audit append used by callers outside this package
// (e.g. push attempts, key rotations, GitHub token grants/revokes).
func (m *Manager) LogAudit(e store.AuditEntry) (store.AuditEntry, error) {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = m.Now()
	}
	return m.Store.AppendAudit(e)
}

// ListAudit proxies the underlying store query.
func (m *Manager) ListAudit(filterType, projectID string, limit int) ([]store.AuditEntry, error) {
	return m.Store.ListAudit(filterType, projectID, limit)
}

// ActionHash is the value the confirmation_token is bound to. Exposed so the
// mobile client (and tests) can compute the same hash when minting tokens.
func ActionHash(action, projectID string, files []string, comment string) string {
	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	h := sha256.New()
	h.Write([]byte(action))
	h.Write([]byte{0})
	h.Write([]byte(projectID))
	h.Write([]byte{0})
	for _, f := range sorted {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	h.Write([]byte(comment))
	return hex.EncodeToString(h.Sum(nil))
}

func (m *Manager) workspaceDir(projectID string) (string, error) {
	if _, err := m.Projects.Get(projectID); err != nil {
		return "", err
	}
	return m.Projects.WorkspaceDir(projectID), nil
}

// parsePorcelainZ parses `git status --porcelain=v1 -z -uall` output. Records
// are NUL-delimited; rename records consume a second NUL-terminated field
// (the old path).
func parsePorcelainZ(out string) []ChangedFile {
	files := make([]ChangedFile, 0)
	parts := strings.Split(out, "\x00")
	for i := 0; i < len(parts); i++ {
		entry := parts[i]
		if len(entry) < 3 {
			continue
		}
		x, y := entry[0], entry[1]
		path := entry[3:]
		f := ChangedFile{Path: path}
		switch {
		case x == 'R' || y == 'R':
			f.Group = GroupRenamed
			if i+1 < len(parts) {
				f.OldPath = parts[i+1]
				i++
			}
		case x == 'A' || y == 'A' || (x == '?' && y == '?'):
			f.Group = GroupAdded
		case x == 'D' || y == 'D':
			f.Group = GroupDeleted
		default:
			f.Group = GroupModified
		}
		files = append(files, f)
	}
	sort.SliceStable(files, func(i, j int) bool {
		if files[i].Group != files[j].Group {
			return groupOrder(files[i].Group) < groupOrder(files[j].Group)
		}
		return files[i].Path < files[j].Path
	})
	return files
}

func groupOrder(g FileGroup) int {
	switch g {
	case GroupAdded:
		return 0
	case GroupModified:
		return 1
	case GroupRenamed:
		return 2
	case GroupDeleted:
		return 3
	}
	return 4
}

func isBinaryFile(dir, path string) bool {
	// `git check-attr` would require a .gitattributes; use `git diff
	// --numstat` against /dev/null which prints "-\t-\t" for binary content.
	// `--` separates options from paths so dash-prefixed filenames are not
	// parsed as flags.
	out, err := gitRun(dir, "diff", "--numstat", "--no-index", "--", "/dev/null", path)
	if err == nil && strings.HasPrefix(strings.TrimSpace(out), "-\t-\t") {
		return true
	}
	// Fall back: read first 8000 bytes and look for a NUL.
	full := dir + "/" + path
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		return false
	}
	f, err := os.Open(full)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 8000)
	n, _ := f.Read(buf)
	for _, b := range buf[:n] {
		if b == 0 {
			return true
		}
	}
	return false
}

func revision(dir, path string) string {
	// `git hash-object` of the current working-tree contents.
	out, err := gitRun(dir, "hash-object", "--", path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func gitRun(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
		"GIT_PAGER=cat",
	)
	out, err := cmd.CombinedOutput()
	// `git diff --no-index` exits 1 when there are differences; that is not
	// an error condition for us — surface stdout regardless.
	if err != nil {
		if isGitDiffExitOne(err, args) {
			return string(out), nil
		}
		return string(out), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func isGitDiffExitOne(err error, args []string) bool {
	if len(args) == 0 || args[0] != "diff" {
		return false
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return true
	}
	return false
}

func safeRelPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\x00") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
