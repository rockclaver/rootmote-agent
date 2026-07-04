// Package storage implements the Storage Analyzer deep module: it finds
// what's eating a host's disk (package/build caches, apt archives, the
// systemd journal, old /tmp files, trash, and — via the existing Docker
// Manager — stopped containers, dangling images, build cache, and unused
// volumes), performs guarded one-tap cleanup of those known-safe locations,
// and lets a caller browse and delete arbitrary files/directories.
//
// Every mutating call (Clean, DeletePath) is expected to be gated by the
// agent's existing confirmation-token + audit machinery at the server layer,
// exactly like docker.container.action and infra.service.action — this
// package only owns the guard that refuses to ever delete a protected path,
// and the mechanics of computing/reclaiming space.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/docker"
)

// Category IDs. Stable machine-readable strings used on the wire for both
// storage.scan rows and the storage.clean{category} request.
const (
	CategoryPipCache        = "pip_cache"
	CategoryNodeCache       = "node_cache"
	CategoryGoCache         = "go_cache"
	CategoryTrash           = "trash"
	CategoryAptCache        = "apt_cache"
	CategoryTmpFiles        = "tmp_files"
	CategoryJournalLogs     = "journal_logs"
	CategoryDockerContainer = "docker_containers"
	CategoryDockerImages    = "docker_images"
	CategoryDockerBuild     = "docker_build_cache"
	CategoryDockerVolumes   = "docker_volumes"
)

// Deep-scan tuning. The large-files scan is a pure stat-based directory
// walk (no file content is read), so even a generous time budget rarely
// triggers on a real host — it exists as a safety valve, not the norm.
const (
	// defaultDeepScanMinSize is the size floor for a file to count as
	// "large" enough to report.
	defaultDeepScanMinSize = 100 << 20 // 100 MiB
	// defaultDeepScanMaxResults caps how many files the response carries;
	// LargeFilesTotalBytes/Count still reflect every match, capped or not.
	defaultDeepScanMaxResults = 500
	// defaultDeepScanBudget bounds wall-clock walk time before the scan
	// gives up and reports a truncated, partial result.
	defaultDeepScanBudget = 45 * time.Second
	// deepScanCacheTTL is how long a completed deep scan is served from
	// cache before a fresh walk runs again.
	deepScanCacheTTL = 10 * time.Minute
)

// deepScanBaseExcludes are directories the deep scan never descends into:
// OS-managed trees a user shouldn't be picking files out of by hand. The
// agent's own DataDir and Docker's internal storage (already covered by the
// docker_* prune categories — walking overlay2 diffs directly would be
// noisy and unsafe to delete from) are added per-instance in New.
var deepScanBaseExcludes = []string{
	"/proc", "/sys", "/dev", "/run", "/boot",
	"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc",
}

// tmpMaxAge is how old a /tmp file must be before the tmp_files category
// considers it junk. Anything under a live tmux-* socket directory is never
// touched regardless of age — those back running terminal sessions.
const tmpMaxAge = 7 * 24 * time.Hour

// journalVacuumFloor is the target size passed to `journalctl
// --vacuum-size`; the journal is trimmed down to roughly this size, not
// wiped entirely, so recent logs survive a cleanup.
const journalVacuumFloor = "200M"

// ErrProtectedPath indicates a delete was rejected by the protected-path
// guard. The guard fires before any filesystem mutation.
var ErrProtectedPath = errors.New("storage: refused to delete protected path")

// ProtectedPathError carries the offending path and reason so the UI can
// show a precise explanation, mirroring systemd.ProtectedUnitError and
// process.ProtectedPIDError.
type ProtectedPathError struct {
	Path   string
	Reason string
}

func (e *ProtectedPathError) Error() string {
	return fmt.Sprintf("storage: refused to delete protected path %q: %s", e.Path, e.Reason)
}

func (e *ProtectedPathError) Unwrap() error { return ErrProtectedPath }

// Category is one row in a storage.scan response: a named place taking up
// space, with an associated Clean action.
type Category struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	SizeBytes   int64  `json:"size_bytes"`
	ItemCount   int    `json:"item_count,omitempty"`
	// Safe is false when Clean carries real risk beyond reclaiming
	// obviously-disposable space (e.g. unused named Docker volumes may hold
	// data nobody else references). The UI must surface SafetyNote before
	// letting the user proceed.
	Safe       bool   `json:"safe"`
	SafetyNote string `json:"safety_note,omitempty"`
}

// CleanResult is the outcome of Clean: bytes freed and (when meaningful) how
// many items were removed.
type CleanResult struct {
	Category     string `json:"category"`
	FreedBytes   int64  `json:"freed_bytes"`
	ItemsRemoved int    `json:"items_removed,omitempty"`
}

// Entry is one child of a Browse listing.
type Entry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size_bytes"`
	Approx  bool      `json:"size_approx,omitempty"`
	ModTime time.Time `json:"mod_time"`
	// Protected mirrors the guard DeletePath enforces, so the UI can grey
	// out delete before the user even tries.
	Protected     bool   `json:"protected"`
	ProtectReason string `json:"protect_reason,omitempty"`
}

// Listing is the result of Browse: one directory's immediate children.
type Listing struct {
	Path    string  `json:"path"`
	Parent  string  `json:"parent,omitempty"`
	Entries []Entry `json:"entries"`
}

// DeleteResult is the outcome of DeletePath.
type DeleteResult struct {
	Path       string `json:"path"`
	FreedBytes int64  `json:"freed_bytes"`
}

// remover is the escalation boundary for filesystem mutations that might
// land outside rootmote-agent.service's ReadWritePaths=/var/lib/rootmote
// /etc/caddy/rootmote — nearly everywhere else on a production host, since
// ProtectSystem=strict mounts the rest of the filesystem read-only inside
// the unit's own private mount namespace. That restriction holds even for
// a sudo-escalated root child: a plain execve (all sudo does) never leaves
// the calling process's mount namespace, so root there still sees the
// read-only bind mounts. The escalation path instead joins PID 1's real,
// unsandboxed mount namespace first via `nsenter --mount=/proc/1/ns/mnt`
// before running the target command as root — the same NoNewPrivileges=false
// / sudoers.d NOPASSWD allowlist model rootmote-agent.service already exists
// to support for reboot/ufw/firewall-cmd. Reads (Scan, Browse, DeepScan)
// never need this: ProtectSystem=strict only blocks writes.
type remover interface {
	Remove(ctx context.Context, path string) error
	RemoveAll(ctx context.Context, path string) error
	// Run executes an arbitrary command (journalctl --vacuum-size), applying
	// the same escalation fallback, and returns its combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// defaultRemover is the production remover.
type defaultRemover struct {
	execCommand func(name string, args ...string) *exec.Cmd
	lookPath    func(file string) (string, error)
	geteuid     func() int
}

func (r defaultRemover) Remove(ctx context.Context, path string) error {
	err := os.Remove(path)
	if err == nil || !r.needsEscalation(err) {
		return err
	}
	if _, escErr := r.escalate(ctx, "rm", "-f", path); escErr != nil {
		return fmt.Errorf("storage: privileged delete of %q: %w", path, escErr)
	}
	return nil
}

func (r defaultRemover) RemoveAll(ctx context.Context, path string) error {
	err := os.RemoveAll(path)
	if err == nil || !r.needsEscalation(err) {
		return err
	}
	if _, escErr := r.escalate(ctx, "rm", "-rf", path); escErr != nil {
		return fmt.Errorf("storage: privileged delete of %q: %w", path, escErr)
	}
	return nil
}

func (r defaultRemover) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := r.execCommand(name, args...).CombinedOutput()
	if err == nil {
		return out, nil
	}
	if r.geteuid() == 0 {
		return out, wrapCmdErr(name, out, err)
	}
	return r.escalate(ctx, name, args...)
}

// needsEscalation is true for exactly the two ways an unprivileged,
// sandboxed removal fails that joining the real host mount namespace as
// root can get around: a plain Unix permission error (a root-owned path)
// or EROFS (anywhere outside ReadWritePaths under ProtectSystem=strict).
func (r defaultRemover) needsEscalation(err error) bool {
	if r.geteuid() == 0 {
		return false
	}
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS)
}

// escalate runs name with args as root inside PID 1's real mount
// namespace, via the rootmote-agent-firewall.sudoers NOPASSWD allowlist.
func (r defaultRemover) escalate(ctx context.Context, name string, args ...string) ([]byte, error) {
	_ = ctx
	binPath, err := r.lookPath(name)
	if err != nil {
		binPath = "/bin/" + name
	}
	nsenterPath, err := r.lookPath("nsenter")
	if err != nil {
		nsenterPath = "/usr/bin/nsenter"
	}
	sudoArgs := append([]string{"-n", nsenterPath, "--mount=/proc/1/ns/mnt", "--", binPath}, args...)
	out, err := r.execCommand("sudo", sudoArgs...).CombinedOutput()
	if err != nil {
		return out, wrapCmdErr(name, out, err)
	}
	return out, nil
}

func wrapCmdErr(name string, out []byte, err error) error {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("%s: %s", name, msg)
}

// DockerPruner is the Storage module's narrow view of Docker space
// reclamation. *docker.Manager satisfies this today; tests pass a fake.
type DockerPruner interface {
	DiskUsage(ctx context.Context) (docker.DiskUsage, error)
	PruneContainers(ctx context.Context) (docker.PruneResult, error)
	PruneImages(ctx context.Context) (docker.PruneResult, error)
	PruneBuildCache(ctx context.Context) (docker.PruneResult, error)
	PruneVolumes(ctx context.Context) (docker.PruneResult, error)
}

// Config configures the Manager.
type Config struct {
	// HomeDir anchors the user-level caches (pip/npm/go/trash). Defaults to
	// os.UserHomeDir() when empty.
	HomeDir string
	// DataDir is the agent's own state directory (state.db, project
	// workspaces' parent). Protected against deletion.
	DataDir string
	// ProjectsRoot is the workspace root under DataDir. Its exact path is
	// protected; individual project subdirectories are not — deleting one
	// stale project's workspace is a legitimate cleanup action.
	ProjectsRoot string
	// Docker, when non-nil, enables the four docker_* categories. Nil
	// (Docker not configured on this agent) simply omits them.
	Docker DockerPruner
	// ExtraProtected lets the host extend the protected-path blocklist.
	ExtraProtected []string
	// Now returns the current time. Defaults to time.Now; overridable so
	// tests can control /tmp file-age math without sleeping.
	Now func() time.Time
	// ExecCommand builds a command to run (journalctl). Defaults to
	// exec.Command; overridable so tests never shell out for real.
	ExecCommand func(name string, args ...string) *exec.Cmd
	// LookPath resolves a binary on PATH. Defaults to exec.LookPath.
	LookPath func(file string) (string, error)
	// TmpDir is the root the tmp_files category scans/cleans. Defaults to
	// /tmp; overridable so tests never touch the real /tmp.
	TmpDir string
	// DeepScanRoot is the filesystem root the large-files deep scan walks.
	// Defaults to "/"; overridable so tests never walk the real root disk.
	DeepScanRoot string
}

type cacheSpec struct {
	id, label, description string
	dirs                   []string
}

// Manager is the Storage Analyzer deep module.
type Manager struct {
	homeDir          string
	protected        map[string]string
	docker           DockerPruner
	caches           []cacheSpec
	now              func() time.Time
	execCommand      func(name string, args ...string) *exec.Cmd
	lookPath         func(file string) (string, error)
	tmpRoot          string
	deepScanRoot     string
	deepScanExcludes []string
	deepScanMu       sync.Mutex
	lastDeepScan     *DeepScanResult
	remover          remover
}

// protectedSystemDirs are always refused, on every host, regardless of
// config. Deleting any of these — even if somehow reachable through a
// browse/delete round trip — would break the machine.
var protectedSystemDirs = []string{
	"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64",
	"/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/srv",
	"/sys", "/tmp", "/usr", "/var",
}

// New constructs a Manager.
func New(cfg Config) (*Manager, error) {
	home := strings.TrimRight(cfg.HomeDir, "/")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("storage: HomeDir not set and could not determine one: %w", err)
		}
		home = strings.TrimRight(h, "/")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	execCommand := cfg.ExecCommand
	if execCommand == nil {
		execCommand = exec.Command
	}
	lookPath := cfg.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	tmpRoot := strings.TrimRight(cfg.TmpDir, "/")
	if tmpRoot == "" {
		tmpRoot = "/tmp"
	}
	deepScanRoot := strings.TrimRight(cfg.DeepScanRoot, "/")
	if deepScanRoot == "" {
		deepScanRoot = "/"
	}
	deepScanExcludes := append([]string{}, deepScanBaseExcludes...)
	deepScanExcludes = append(deepScanExcludes, filepath.Join(deepScanRoot, "var", "lib", "docker"))
	if cfg.DataDir != "" {
		deepScanExcludes = append(deepScanExcludes, filepath.Clean(cfg.DataDir))
	}

	protected := map[string]string{}
	addProtected := func(path, reason string) {
		clean := filepath.Clean(path)
		protected[clean] = reason
		// Some hosts (notably macOS, used in local dev/tests) alias a
		// top-level dir through a symlink (e.g. /etc -> /private/etc).
		// Index the resolved form too so the guard matches regardless of
		// the runtime's own symlink layout.
		if resolved, err := filepath.EvalSymlinks(clean); err == nil && resolved != clean {
			protected[resolved] = reason
		}
	}
	for _, p := range protectedSystemDirs {
		addProtected(p, "refusing to delete a system directory")
	}
	addProtected(home, "refusing to delete the entire home directory")
	if cfg.DataDir != "" {
		addProtected(cfg.DataDir, "the agent's own state lives here")
	}
	if cfg.ProjectsRoot != "" {
		addProtected(cfg.ProjectsRoot, "refusing to delete every project at once")
	}
	for _, p := range cfg.ExtraProtected {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		addProtected(p, "protected by host configuration")
	}

	return &Manager{
		homeDir:          home,
		protected:        protected,
		docker:           cfg.Docker,
		now:              now,
		execCommand:      execCommand,
		lookPath:         lookPath,
		tmpRoot:          tmpRoot,
		deepScanRoot:     deepScanRoot,
		deepScanExcludes: deepScanExcludes,
		remover: defaultRemover{
			execCommand: execCommand,
			lookPath:    lookPath,
			geteuid:     os.Geteuid,
		},
		caches: []cacheSpec{
			{
				id:          CategoryPipCache,
				label:       "Python package cache",
				description: "pip's downloaded wheel/sdist cache. Safe to clear — pip re-downloads as needed.",
				dirs:        []string{filepath.Join(home, ".cache", "pip")},
			},
			{
				id:          CategoryNodeCache,
				label:       "Node package cache",
				description: "npm/yarn/pnpm/bun package caches. Safe to clear — package managers re-fetch as needed.",
				dirs: []string{
					filepath.Join(home, ".npm", "_cacache"),
					filepath.Join(home, ".cache", "yarn"),
					filepath.Join(home, ".local", "share", "pnpm", "store"),
					filepath.Join(home, ".bun", "install", "cache"),
				},
			},
			{
				id:          CategoryGoCache,
				label:       "Go build cache",
				description: "Go's compiler build cache and module download cache. Safe to clear — rebuilt on next build.",
				dirs: []string{
					filepath.Join(home, ".cache", "go-build"),
					filepath.Join(home, "go", "pkg", "mod", "cache", "download"),
				},
			},
			{
				id:          CategoryTrash,
				label:       "Trash",
				description: "Files moved to the desktop trash. Safe to empty.",
				dirs:        []string{filepath.Join(home, ".local", "share", "Trash")},
			},
		},
	}, nil
}

// Scan computes the current size of every known culprit category and
// returns the non-empty ones sorted by size, largest first. A category whose
// underlying capability is unavailable (no Docker, no journalctl) is simply
// omitted — never an error, never a zeroed row.
func (m *Manager) Scan(ctx context.Context) ([]Category, error) {
	var out []Category

	for _, spec := range m.caches {
		size := m.cacheSpecSize(ctx, spec)
		if size <= 0 {
			continue
		}
		out = append(out, Category{
			ID: spec.id, Label: spec.label, Description: spec.description,
			SizeBytes: size, Safe: true,
		})
	}

	if size, count := m.aptCacheSize(); size > 0 {
		out = append(out, Category{
			ID:          CategoryAptCache,
			Label:       "APT package cache",
			Description: "Downloaded .deb packages under /var/cache/apt/archives. Safe to clear.",
			SizeBytes:   size, ItemCount: count, Safe: true,
		})
	}

	if _, total := m.tmpOldFiles(ctx); total > 0 {
		out = append(out, Category{
			ID:          CategoryTmpFiles,
			Label:       "Old temporary files",
			Description: fmt.Sprintf("Regular files under /tmp older than %d days (live tmux sessions are skipped).", int(tmpMaxAge.Hours()/24)),
			SizeBytes:   total, Safe: true,
		})
	}

	if size, ok := m.journalDiskUsageBytes(ctx); ok && size > 0 {
		out = append(out, Category{
			ID:          CategoryJournalLogs,
			Label:       "System journal",
			Description: fmt.Sprintf("systemd journal logs. Cleanup vacuums down to roughly %s, keeping recent entries.", journalVacuumFloor),
			SizeBytes:   size, Safe: true,
		})
	}

	out = append(out, m.dockerCategories(ctx)...)

	sort.SliceStable(out, func(i, j int) bool { return out[i].SizeBytes > out[j].SizeBytes })
	return out, nil
}

func (m *Manager) dockerCategories(ctx context.Context) []Category {
	if m.docker == nil {
		return nil
	}
	du, err := m.docker.DiskUsage(ctx)
	if err != nil || !du.Available {
		return nil
	}
	var out []Category
	if du.ContainersReclaimableBytes > 0 {
		out = append(out, Category{
			ID:          CategoryDockerContainer,
			Label:       "Stopped containers",
			Description: "Disk used by stopped/exited containers. Safe to prune.",
			SizeBytes:   du.ContainersReclaimableBytes, ItemCount: du.ContainersReclaimableCount, Safe: true,
		})
	}
	if du.ImagesReclaimableBytes > 0 {
		out = append(out, Category{
			ID:          CategoryDockerImages,
			Label:       "Dangling Docker images",
			Description: "Untagged images no container references. Safe to prune.",
			SizeBytes:   du.ImagesReclaimableBytes, ItemCount: du.ImagesReclaimableCount, Safe: true,
		})
	}
	if du.BuildCacheReclaimableBytes > 0 {
		out = append(out, Category{
			ID:          CategoryDockerBuild,
			Label:       "Docker build cache",
			Description: "Unused BuildKit layer cache. Safe to prune — rebuilt as needed.",
			SizeBytes:   du.BuildCacheReclaimableBytes, Safe: true,
		})
	}
	if du.VolumesReclaimableBytes > 0 {
		out = append(out, Category{
			ID:          CategoryDockerVolumes,
			Label:       "Unused Docker volumes",
			Description: "Volumes with no attached container, including named volumes.",
			SizeBytes:   du.VolumesReclaimableBytes, ItemCount: du.VolumesReclaimableCount,
			Safe:       false,
			SafetyNote: "May permanently remove data in named volumes nothing currently uses.",
		})
	}
	return out
}

// LargeFile is one file found by the deep scan.
type LargeFile struct {
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	ModTime   time.Time `json:"mod_time"`
}

// DeepScanOptions configures a DeepScan call.
type DeepScanOptions struct {
	// Force skips the cache and re-walks the filesystem even if a recent
	// result exists.
	Force bool
	// MinSizeBytes overrides the default "large" threshold. <= 0 uses the
	// default (100 MiB).
	MinSizeBytes int64
}

// DeepScanResult is the outcome of DeepScan: every known culprit (the same
// categories Scan reports) plus a thorough, filesystem-wide list of
// individual large files — the two combine into TotalReclaimableBytes, the
// number the mobile app's "Reclaim ~X GB" card headlines.
type DeepScanResult struct {
	GeneratedAt  time.Time `json:"generated_at"`
	MinSizeBytes int64     `json:"min_size_bytes"`
	// LargeFiles is capped at defaultDeepScanMaxResults, sorted largest
	// first; LargeFilesTotalBytes/Count reflect every match found, capped
	// or not.
	LargeFiles           []LargeFile `json:"large_files"`
	LargeFilesTotalBytes int64       `json:"large_files_total_bytes"`
	LargeFilesTotalCount int         `json:"large_files_total_count"`
	// LargeFilesTruncated is true when the walk hit its time budget before
	// covering the whole filesystem — the totals above are then a lower
	// bound, not exact.
	LargeFilesTruncated bool `json:"large_files_truncated"`

	Categories           []Category `json:"categories"`
	CategoriesTotalBytes int64      `json:"categories_total_bytes"`

	TotalReclaimableBytes int64 `json:"total_reclaimable_bytes"`
}

// DeepScan performs (or returns a cached) filesystem-wide sweep: every
// regular file at or above the size threshold, found by walking the host
// disk directly rather than relying on a fixed list of known cache
// directories, plus the same category rollup Scan reports. Results are
// cached for deepScanCacheTTL so re-opening a screen doesn't always pay for
// a fresh walk; Force bypasses the cache.
func (m *Manager) DeepScan(ctx context.Context, opts DeepScanOptions) (DeepScanResult, error) {
	minSize := opts.MinSizeBytes
	if minSize <= 0 {
		minSize = defaultDeepScanMinSize
	}

	m.deepScanMu.Lock()
	if !opts.Force && m.lastDeepScan != nil && m.lastDeepScan.MinSizeBytes == minSize &&
		m.now().Sub(m.lastDeepScan.GeneratedAt) < deepScanCacheTTL {
		cached := *m.lastDeepScan
		m.deepScanMu.Unlock()
		return cached, nil
	}
	m.deepScanMu.Unlock()

	files, totalBytes, totalCount, truncated := scanLargeFiles(
		ctx, m.deepScanRoot, minSize, defaultDeepScanMaxResults, defaultDeepScanBudget, m.deepScanExcludes,
	)
	categories, err := m.Scan(ctx)
	if err != nil {
		categories = nil
	}
	var catTotal int64
	for _, c := range categories {
		catTotal += c.SizeBytes
	}

	result := DeepScanResult{
		GeneratedAt:           m.now(),
		MinSizeBytes:          minSize,
		LargeFiles:            files,
		LargeFilesTotalBytes:  totalBytes,
		LargeFilesTotalCount:  totalCount,
		LargeFilesTruncated:   truncated,
		Categories:            categories,
		CategoriesTotalBytes:  catTotal,
		TotalReclaimableBytes: totalBytes + catTotal,
	}

	m.deepScanMu.Lock()
	cp := result
	m.lastDeepScan = &cp
	m.deepScanMu.Unlock()
	return result, nil
}

// scanLargeFiles walks root, staying on root's filesystem device (like
// `find -xdev`) and skipping excludes, collecting every regular file at or
// above minSize. Nothing is read except directory entries and stat info —
// no file content — so it stays fast even across a large tree. The result
// is sorted largest-first and capped at maxResults; totalBytes/totalCount
// reflect every match, uncapped.
func scanLargeFiles(
	ctx context.Context, root string, minSize int64, maxResults int, budget time.Duration, excludes []string,
) (files []LargeFile, totalBytes int64, totalCount int, truncated bool) {
	deadline := time.Now().Add(budget)
	rootDev, haveRootDev := deviceIDOf(root)
	excludeSet := make(map[string]struct{}, len(excludes))
	for _, ex := range excludes {
		excludeSet[filepath.Clean(ex)] = struct{}{}
	}

	var all []LargeFile
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil || time.Now().After(deadline) {
			truncated = true
			return filepath.SkipAll
		}
		if err != nil {
			// Permission errors and races are expected walking a whole
			// disk; skip and keep going rather than aborting the scan.
			return nil
		}
		if d.IsDir() {
			if p != root {
				if _, skip := excludeSet[p]; skip {
					return filepath.SkipDir
				}
			}
			if haveRootDev {
				if info, ierr := d.Info(); ierr == nil {
					if dev, ok := deviceID(info); ok && dev != rootDev {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks, sockets, devices: not a file we can usefully reclaim
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() < minSize {
			return nil
		}
		totalBytes += info.Size()
		totalCount++
		all = append(all, LargeFile{Path: p, SizeBytes: info.Size(), ModTime: info.ModTime()})
		return nil
	})

	sort.SliceStable(all, func(i, j int) bool { return all[i].SizeBytes > all[j].SizeBytes })
	if len(all) > maxResults {
		all = all[:maxResults]
	}
	return all, totalBytes, totalCount, truncated
}

func deviceIDOf(path string) (uint64, bool) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, false
	}
	return deviceID(info)
}

func deviceID(info fs.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true
}

// Clean performs the deletion/prune backing categoryID and returns the
// bytes actually freed. Unknown category IDs and unavailable capabilities
// (e.g. docker_* with no Docker configured) return an error.
func (m *Manager) Clean(ctx context.Context, categoryID string) (CleanResult, error) {
	for _, spec := range m.caches {
		if spec.id == categoryID {
			freed, err := m.clearCacheSpec(spec)
			return CleanResult{Category: categoryID, FreedBytes: freed}, err
		}
	}
	switch categoryID {
	case CategoryAptCache:
		freed, count, err := m.clearGlobFiles(ctx, filepath.Join("/var/cache/apt/archives", "*.deb"))
		return CleanResult{Category: categoryID, FreedBytes: freed, ItemsRemoved: count}, err
	case CategoryTmpFiles:
		files, _ := m.tmpOldFiles(ctx)
		var freed int64
		removed := 0
		for _, f := range files {
			info, statErr := os.Lstat(f)
			if statErr != nil {
				continue
			}
			if os.Remove(f) == nil {
				freed += info.Size()
				removed++
			}
		}
		return CleanResult{Category: categoryID, FreedBytes: freed, ItemsRemoved: removed}, nil
	case CategoryJournalLogs:
		return m.vacuumJournal(ctx)
	case CategoryDockerContainer, CategoryDockerImages, CategoryDockerBuild, CategoryDockerVolumes:
		return m.cleanDocker(ctx, categoryID)
	default:
		return CleanResult{}, fmt.Errorf("storage: unknown category %q", categoryID)
	}
}

func (m *Manager) cleanDocker(ctx context.Context, categoryID string) (CleanResult, error) {
	if m.docker == nil {
		return CleanResult{}, errors.New("storage: docker not configured on this agent")
	}
	var res docker.PruneResult
	var err error
	switch categoryID {
	case CategoryDockerContainer:
		res, err = m.docker.PruneContainers(ctx)
	case CategoryDockerImages:
		res, err = m.docker.PruneImages(ctx)
	case CategoryDockerBuild:
		res, err = m.docker.PruneBuildCache(ctx)
	case CategoryDockerVolumes:
		res, err = m.docker.PruneVolumes(ctx)
	}
	if err != nil {
		return CleanResult{}, err
	}
	return CleanResult{Category: categoryID, FreedBytes: res.FreedBytes, ItemsRemoved: res.Count}, nil
}

// Browse lists path's immediate children with recursively-computed sizes.
// An empty path defaults to the configured home directory. Reads are never
// guarded — only DeletePath is.
func (m *Manager) Browse(ctx context.Context, path string) (Listing, error) {
	if strings.TrimSpace(path) == "" {
		path = m.homeDir
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return Listing{}, fmt.Errorf("storage: path must be absolute, got %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return Listing{}, err
	}
	if !info.IsDir() {
		return Listing{}, fmt.Errorf("storage: %q is not a directory", path)
	}
	dirEntries, err := os.ReadDir(path)
	if err != nil {
		return Listing{}, err
	}

	entries := make([]Entry, len(dirEntries))
	const workers = 8
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, de := range dirEntries {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, de fs.DirEntry) {
			defer wg.Done()
			defer func() { <-sem }()
			childPath := filepath.Join(path, de.Name())
			entry := Entry{Name: de.Name(), Path: childPath}
			fi, statErr := de.Info()
			if statErr == nil {
				entry.ModTime = fi.ModTime()
			}
			if reason, protected := m.protectedPathReason(childPath); protected {
				entry.Protected = true
				entry.ProtectReason = reason
			}
			if de.IsDir() {
				entry.IsDir = true
				entry.Size, entry.Approx = dirSize(ctx, childPath, sizeBudget{maxEntries: 20000, timeout: 1500 * time.Millisecond})
			} else if statErr == nil {
				entry.Size = fi.Size()
			}
			entries[i] = entry
		}(i, de)
	}
	wg.Wait()

	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Size > entries[j].Size })

	parent := ""
	if path != "/" {
		parent = filepath.Dir(path)
	}
	return Listing{Path: path, Parent: parent, Entries: entries}, nil
}

// DeletePath removes path, refusing before any syscall if the protected-path
// guard fires. Directories require recursive=true.
func (m *Manager) DeletePath(ctx context.Context, path string, recursive bool) (DeleteResult, error) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return DeleteResult{}, fmt.Errorf("storage: path must be absolute, got %q", path)
	}
	if reason, protected := m.protectedPathReason(path); protected {
		return DeleteResult{}, &ProtectedPathError{Path: path, Reason: reason}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return DeleteResult{}, err
	}
	if info.IsDir() && !recursive {
		return DeleteResult{}, fmt.Errorf("storage: %q is a directory; recursive delete required", path)
	}
	var freed int64
	if info.IsDir() {
		freed, _ = dirSize(ctx, path, sizeBudget{})
		if err := m.remover.RemoveAll(ctx, path); err != nil {
			return DeleteResult{}, err
		}
	} else {
		freed = info.Size()
		if err := m.remover.Remove(ctx, path); err != nil {
			return DeleteResult{}, err
		}
	}
	return DeleteResult{Path: path, FreedBytes: freed}, nil
}

// IsProtectedPath reports whether path is refused by the protected-path
// guard, and why. Lets the server-layer dispatch reject a storage.delete
// before consuming a confirmation token, mirroring
// systemd.Manager.IsProtected / process.Manager.IsProtected.
func (m *Manager) IsProtectedPath(path string) (string, bool) {
	return m.protectedPathReason(path)
}

// protectedPathReason reports whether path (or, defensively, its
// symlink-resolved target) matches the protected-path blocklist. An unknown
// path is never protected — the blocklist is a fixed, explicit set, not a
// heuristic.
func (m *Manager) protectedPathReason(path string) (string, bool) {
	clean := filepath.Clean(path)
	if clean == "/" || clean == "." || clean == "" {
		return "refusing to delete the root filesystem", true
	}
	if reason, ok := m.protected[clean]; ok {
		return reason, true
	}
	if resolved, err := filepath.EvalSymlinks(clean); err == nil && resolved != clean {
		if resolved == "/" {
			return "refusing to delete the root filesystem", true
		}
		if reason, ok := m.protected[resolved]; ok {
			return reason, true
		}
	}
	return "", false
}

func (m *Manager) cacheSpecSize(ctx context.Context, spec cacheSpec) int64 {
	var total int64
	for _, dir := range spec.dirs {
		size, _ := dirSize(ctx, dir, sizeBudget{})
		total += size
	}
	return total
}

func (m *Manager) clearCacheSpec(spec cacheSpec) (int64, error) {
	var total int64
	var firstErr error
	for _, dir := range spec.dirs {
		freed, err := clearDir(dir)
		total += freed
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return total, firstErr
}

func (m *Manager) aptCacheSize() (int64, int) {
	matches, err := filepath.Glob(filepath.Join("/var/cache/apt/archives", "*.deb"))
	if err != nil {
		return 0, 0
	}
	var total int64
	for _, f := range matches {
		if info, err := os.Lstat(f); err == nil && !info.IsDir() {
			total += info.Size()
		}
	}
	return total, len(matches)
}

// tmpOldFiles returns every regular file under /tmp older than tmpMaxAge,
// skipping anything under a live tmux-* socket directory, plus their total
// size. Scan and Clean share this so the displayed size always matches what
// Clean actually removes.
func (m *Manager) tmpOldFiles(ctx context.Context) ([]string, int64) {
	cutoff := m.now().Add(-tmpMaxAge)
	var files []string
	var total int64
	root := m.tmpRoot
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			return nil
		}
		if p == root {
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(filepath.Base(p), "tmux-") {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.ModTime().After(cutoff) {
			return nil
		}
		files = append(files, p)
		total += info.Size()
		return nil
	})
	return files, total
}

func (m *Manager) journalAvailable() bool {
	_, err := m.lookPath("journalctl")
	return err == nil
}

// journalDiskUsageBytes shells out to `journalctl --disk-usage`, parsing its
// human-readable summary. ok is false when journalctl isn't on PATH or the
// call fails, so Scan can omit the category instead of showing a bogus 0.
func (m *Manager) journalDiskUsageBytes(ctx context.Context) (int64, bool) {
	if !m.journalAvailable() {
		return 0, false
	}
	cmd := m.execCommand("journalctl", "--disk-usage")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return 0, false
	}
	size, ok := parseJournalDiskUsage(string(out))
	return size, ok
}

func (m *Manager) vacuumJournal(ctx context.Context) (CleanResult, error) {
	if !m.journalAvailable() {
		return CleanResult{}, errors.New("storage: journalctl not available")
	}
	before, _ := m.journalDiskUsageBytes(ctx)
	if _, err := m.remover.Run(ctx, "journalctl", "--vacuum-size="+journalVacuumFloor); err != nil {
		return CleanResult{}, fmt.Errorf("storage: journalctl vacuum: %w", err)
	}
	after, _ := m.journalDiskUsageBytes(context.Background())
	freed := before - after
	if freed < 0 {
		freed = 0
	}
	return CleanResult{Category: CategoryJournalLogs, FreedBytes: freed}, nil
}

// clearDir removes dir's contents (recreating an empty dir in its place) and
// returns the bytes freed. A missing dir is a no-op, not an error — most
// hosts won't have every cache populated.
func clearDir(dir string) (int64, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("storage: %q is not a directory", dir)
	}
	freed, _ := dirSize(context.Background(), dir, sizeBudget{})
	if err := os.RemoveAll(dir); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return freed, err
	}
	return freed, nil
}

// clearGlobFiles removes every file matching pattern (directories are
// skipped) and returns bytes freed and files removed.
func (m *Manager) clearGlobFiles(ctx context.Context, pattern string) (int64, int, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return 0, 0, err
	}
	var freed int64
	count := 0
	for _, f := range matches {
		info, statErr := os.Lstat(f)
		if statErr != nil || info.IsDir() {
			continue
		}
		if m.remover.Remove(ctx, f) == nil {
			freed += info.Size()
			count++
		}
	}
	return freed, count, nil
}

// sizeBudget bounds a directory walk so Browse stays responsive on huge
// trees. A zero-value budget walks unbounded (used for cache dirs, which are
// expected to be well within reason, and for DeletePath's pre-delete size —
// approximation there is acceptable since it's informational only).
type sizeBudget struct {
	maxEntries int
	timeout    time.Duration
}

// dirSize sums regular-file sizes under root, honoring budget and ctx
// cancellation. approx is true when the walk was cut short — the returned
// size is then a lower bound, not exact.
func dirSize(ctx context.Context, root string, budget sizeBudget) (size int64, approx bool) {
	var deadline time.Time
	if budget.timeout > 0 {
		deadline = time.Now().Add(budget.timeout)
	}
	count := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			approx = true
			return filepath.SkipAll
		}
		if err != nil {
			// Best-effort: permission errors and races (file removed mid-walk)
			// don't abort the whole measurement, they just under-count.
			return nil
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			approx = true
			return filepath.SkipAll
		}
		count++
		if budget.maxEntries > 0 && count > budget.maxEntries {
			approx = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		size += info.Size()
		return nil
	})
	return size, approx
}

// parseJournalDiskUsage extracts a byte count from journalctl's
// `--disk-usage` human-readable line, e.g. "Archived and active journals
// take up 512.0M in the file system.". systemd formats sizes with 1024-based
// K/M/G/T suffixes (no "i").
func parseJournalDiskUsage(out string) (int64, bool) {
	fields := strings.Fields(out)
	for i, f := range fields {
		if size, ok := parseHumanSize(f); ok && i > 0 {
			return size, true
		}
	}
	return 0, false
}

func parseHumanSize(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	mult := int64(1)
	switch suffix := s[len(s)-1]; suffix {
	case 'K', 'k':
		mult = 1 << 10
		s = s[:len(s)-1]
	case 'M', 'm':
		mult = 1 << 20
		s = s[:len(s)-1]
	case 'G', 'g':
		mult = 1 << 30
		s = s[:len(s)-1]
	case 'T', 't':
		mult = 1 << 40
		s = s[:len(s)-1]
	case 'B', 'b':
		s = s[:len(s)-1]
	default:
		if suffix < '0' || suffix > '9' {
			return 0, false
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return int64(f * float64(mult)), true
}
