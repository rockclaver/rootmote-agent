package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/docker"
)

func writeFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func newTestManager(t *testing.T, cfg Config) *Manager {
	t.Helper()
	if cfg.LookPath == nil {
		cfg.LookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// AC: Scan reports the pip/node/go/trash cache categories with real sizes,
// and only when they're non-empty.
func TestScan_ReportsPopulatedCacheCategories(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".cache", "pip", "wheel.whl"), 1000)
	writeFile(t, filepath.Join(home, ".cache", "go-build", "obj"), 500)
	// npm/yarn/trash left empty on purpose — must not appear.

	m := newTestManager(t, Config{HomeDir: home})
	cats, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	byID := map[string]Category{}
	for _, c := range cats {
		byID[c.ID] = c
	}
	if got := byID[CategoryPipCache]; got.SizeBytes != 1000 || !got.Safe {
		t.Fatalf("pip_cache = %+v, want size 1000 safe", got)
	}
	if got := byID[CategoryGoCache]; got.SizeBytes != 500 {
		t.Fatalf("go_cache = %+v, want size 500", got)
	}
	if _, ok := byID[CategoryNodeCache]; ok {
		t.Fatal("empty node_cache must be omitted from scan")
	}
	if _, ok := byID[CategoryTrash]; ok {
		t.Fatal("empty trash must be omitted from scan")
	}
}

// AC: Scan sorts categories by size, largest first.
func TestScan_SortsBySizeDescending(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".cache", "pip", "small.whl"), 10)
	writeFile(t, filepath.Join(home, ".cache", "go-build", "big"), 9000)

	m := newTestManager(t, Config{HomeDir: home})
	cats, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(cats) < 2 {
		t.Fatalf("expected at least 2 categories, got %d", len(cats))
	}
	if !sort.SliceIsSorted(cats, func(i, j int) bool { return cats[i].SizeBytes > cats[j].SizeBytes }) {
		t.Fatalf("categories not sorted by size desc: %+v", cats)
	}
}

// AC: Clean on a cache category frees exactly the bytes Scan reported, and
// the directory survives (empty) for the tool that populates it.
func TestClean_CacheCategory_FreesScannedBytesAndKeepsDirAlive(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".cache", "pip")
	writeFile(t, filepath.Join(dir, "a.whl"), 300)
	writeFile(t, filepath.Join(dir, "b.whl"), 700)

	m := newTestManager(t, Config{HomeDir: home})
	cats, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var before Category
	for _, c := range cats {
		if c.ID == CategoryPipCache {
			before = c
		}
	}
	if before.SizeBytes != 1000 {
		t.Fatalf("scanned pip_cache size = %d, want 1000", before.SizeBytes)
	}

	res, err := m.Clean(context.Background(), CategoryPipCache)
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if res.FreedBytes != 1000 {
		t.Fatalf("FreedBytes = %d, want 1000", res.FreedBytes)
	}
	info, statErr := os.Stat(dir)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("cache dir must survive cleanup as an empty dir: %v", statErr)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("cache dir must be empty after clean, got %d entries", len(entries))
	}

	// Re-scanning afterward must show it gone.
	cats2, _ := m.Scan(context.Background())
	for _, c := range cats2 {
		if c.ID == CategoryPipCache {
			t.Fatalf("pip_cache should be empty (omitted) after clean, still reports %+v", c)
		}
	}
}

// AC: Clean on an unknown category returns an error rather than silently
// doing nothing.
func TestClean_UnknownCategory_Errors(t *testing.T) {
	m := newTestManager(t, Config{HomeDir: t.TempDir()})
	if _, err := m.Clean(context.Background(), "not_a_real_category"); err == nil {
		t.Fatal("expected error for unknown category")
	}
}

// fakeDockerPruner drives every Docker-availability and prune state without
// a real Docker socket.
type fakeDockerPruner struct {
	usage       docker.DiskUsage
	usageErr    error
	pruneResult docker.PruneResult
	pruneErr    error
	calls       []string
}

func (f *fakeDockerPruner) DiskUsage(context.Context) (docker.DiskUsage, error) {
	return f.usage, f.usageErr
}
func (f *fakeDockerPruner) PruneContainers(context.Context) (docker.PruneResult, error) {
	f.calls = append(f.calls, "containers")
	return f.pruneResult, f.pruneErr
}
func (f *fakeDockerPruner) PruneImages(context.Context) (docker.PruneResult, error) {
	f.calls = append(f.calls, "images")
	return f.pruneResult, f.pruneErr
}
func (f *fakeDockerPruner) PruneBuildCache(context.Context) (docker.PruneResult, error) {
	f.calls = append(f.calls, "build_cache")
	return f.pruneResult, f.pruneErr
}
func (f *fakeDockerPruner) PruneVolumes(context.Context) (docker.PruneResult, error) {
	f.calls = append(f.calls, "volumes")
	return f.pruneResult, f.pruneErr
}

// AC: Docker categories appear only when Docker is available and their
// reclaimable bytes are non-zero; docker_volumes is flagged unsafe.
func TestScan_DockerCategories(t *testing.T) {
	fake := &fakeDockerPruner{usage: docker.DiskUsage{
		Available:                  true,
		ContainersReclaimableBytes: 100,
		ImagesReclaimableBytes:     0, // must be omitted
		BuildCacheReclaimableBytes: 300,
		VolumesReclaimableBytes:    400,
		VolumesReclaimableCount:    2,
	}}
	m := newTestManager(t, Config{HomeDir: t.TempDir(), Docker: fake})
	cats, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	byID := map[string]Category{}
	for _, c := range cats {
		byID[c.ID] = c
	}
	if _, ok := byID[CategoryDockerContainer]; !ok {
		t.Fatal("expected docker_containers category")
	}
	if _, ok := byID[CategoryDockerImages]; ok {
		t.Fatal("zero-size docker_images must be omitted")
	}
	vol, ok := byID[CategoryDockerVolumes]
	if !ok {
		t.Fatal("expected docker_volumes category")
	}
	if vol.Safe {
		t.Fatal("docker_volumes must be marked unsafe")
	}
	if vol.SafetyNote == "" {
		t.Fatal("docker_volumes must carry a safety note")
	}
}

// AC: Docker unavailable (daemon down, or not configured) omits every
// docker_* category — never an error, never a zeroed row.
func TestScan_DockerUnavailable_OmitsCategories(t *testing.T) {
	fake := &fakeDockerPruner{usage: docker.DiskUsage{Available: false}}
	m := newTestManager(t, Config{HomeDir: t.TempDir(), Docker: fake})
	cats, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, c := range cats {
		if c.ID == CategoryDockerContainer || c.ID == CategoryDockerImages ||
			c.ID == CategoryDockerBuild || c.ID == CategoryDockerVolumes {
			t.Fatalf("docker category %q must be omitted when unavailable", c.ID)
		}
	}

	m2 := newTestManager(t, Config{HomeDir: t.TempDir()}) // Docker: nil
	cats2, _ := m2.Scan(context.Background())
	for _, c := range cats2 {
		if c.ID == CategoryDockerContainer {
			t.Fatal("docker categories must be omitted when Docker is not configured")
		}
	}
}

// AC: Clean on a docker_* category delegates to the matching Prune method
// and maps the result; docker not configured is a typed error.
func TestClean_DockerCategory_DelegatesToPruner(t *testing.T) {
	fake := &fakeDockerPruner{pruneResult: docker.PruneResult{FreedBytes: 555, Count: 3}}
	m := newTestManager(t, Config{HomeDir: t.TempDir(), Docker: fake})
	res, err := m.Clean(context.Background(), CategoryDockerVolumes)
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if res.FreedBytes != 555 || res.ItemsRemoved != 3 {
		t.Fatalf("CleanResult = %+v", res)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "volumes" {
		t.Fatalf("expected PruneVolumes call, got %v", fake.calls)
	}

	m2 := newTestManager(t, Config{HomeDir: t.TempDir()}) // Docker: nil
	if _, err := m2.Clean(context.Background(), CategoryDockerContainer); err == nil {
		t.Fatal("expected error cleaning docker category with no Docker configured")
	}
}

// AC: the protected-path guard refuses system directories, the agent's data
// dir, the projects root, and (defensively) a symlink pointing at one —
// before any filesystem mutation — while a plain unprotected path is not
// flagged.
func TestProtectedPathGuard(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, "rootmote")
	projectsRoot := filepath.Join(dataDir, "projects")
	if err := os.MkdirAll(projectsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, Config{HomeDir: home, DataDir: dataDir, ProjectsRoot: projectsRoot})

	for _, p := range []string{"/", "/etc", "/usr", "/var", home, dataDir, projectsRoot} {
		if _, protected := m.protectedPathReason(p); !protected {
			t.Errorf("expected %q to be protected", p)
		}
	}

	// A child of the projects root is a legitimate delete target.
	oneProject := filepath.Join(projectsRoot, "some-app")
	if _, protected := m.protectedPathReason(oneProject); protected {
		t.Errorf("child of projects root %q must not be protected", oneProject)
	}

	// A symlink pointing at a protected target must not bypass the guard.
	link := filepath.Join(home, "escape-hatch")
	if err := os.Symlink("/etc", link); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}
	if _, protected := m.protectedPathReason(link); !protected {
		t.Errorf("symlink to /etc must be protected")
	}
}

// AC: DeletePath refuses a protected path before touching the filesystem,
// and successfully removes an unprotected file/dir with the correct freed
// bytes.
func TestDeletePath(t *testing.T) {
	home := t.TempDir()
	m := newTestManager(t, Config{HomeDir: home})

	var pe *ProtectedPathError
	if _, err := m.DeletePath(context.Background(), "/etc", true); !errors.As(err, &pe) {
		t.Fatalf("DeletePath(/etc) err = %v, want *ProtectedPathError", err)
	}
	if _, statErr := os.Stat("/etc"); statErr != nil {
		t.Fatalf("/etc must still exist: %v", statErr)
	}

	file := filepath.Join(home, "junk.log")
	writeFile(t, file, 42)
	res, err := m.DeletePath(context.Background(), file, false)
	if err != nil {
		t.Fatalf("DeletePath file: %v", err)
	}
	if res.FreedBytes != 42 {
		t.Fatalf("FreedBytes = %d, want 42", res.FreedBytes)
	}
	if _, statErr := os.Stat(file); !os.IsNotExist(statErr) {
		t.Fatal("file should be gone")
	}

	dir := filepath.Join(home, "old-project")
	writeFile(t, filepath.Join(dir, "a.txt"), 100)
	writeFile(t, filepath.Join(dir, "b.txt"), 200)
	if _, err := m.DeletePath(context.Background(), dir, false); err == nil {
		t.Fatal("expected error deleting a directory without recursive=true")
	}
	res2, err := m.DeletePath(context.Background(), dir, true)
	if err != nil {
		t.Fatalf("DeletePath dir recursive: %v", err)
	}
	if res2.FreedBytes != 300 {
		t.Fatalf("FreedBytes = %d, want 300", res2.FreedBytes)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatal("dir should be gone")
	}
}

// AC: Browse lists children with sizes, marks a protected child, and
// reports a sane parent.
func TestBrowse(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, "notes.txt"), 123)
	writeFile(t, filepath.Join(home, "sub", "a.bin"), 10)
	writeFile(t, filepath.Join(home, "sub", "b.bin"), 20)

	dataDir := filepath.Join(home, "rootmote")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, Config{HomeDir: home, DataDir: dataDir})

	listing, err := m.Browse(context.Background(), home)
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	byName := map[string]Entry{}
	for _, e := range listing.Entries {
		byName[e.Name] = e
	}
	if got := byName["notes.txt"]; got.Size != 123 || got.IsDir {
		t.Fatalf("notes.txt entry = %+v", got)
	}
	if got := byName["sub"]; got.Size != 30 || !got.IsDir {
		t.Fatalf("sub dir entry = %+v, want size 30", got)
	}
	if got := byName["rootmote"]; !got.Protected {
		t.Fatalf("rootmote (data dir) entry must be protected: %+v", got)
	}
	if listing.Parent != filepath.Dir(home) {
		t.Fatalf("Parent = %q, want %q", listing.Parent, filepath.Dir(home))
	}

	// Browsing root must not panic and its parent must be empty (root has none).
	rootListing, err := m.Browse(context.Background(), "/")
	if err != nil {
		t.Fatalf("Browse(/): %v", err)
	}
	if rootListing.Parent != "" {
		t.Fatalf("Browse(/) parent = %q, want empty", rootListing.Parent)
	}
}

// AC: /tmp cleanup only touches regular files older than the age threshold
// and never descends into a live tmux-* socket directory.
func TestTmpOldFiles_RespectsAgeAndSkipsTmuxSockets(t *testing.T) {
	tmp := t.TempDir()
	old := filepath.Join(tmp, "old.log")
	fresh := filepath.Join(tmp, "fresh.log")
	tmuxFile := filepath.Join(tmp, "tmux-1000", "default")
	writeFile(t, old, 50)
	writeFile(t, fresh, 60)
	writeFile(t, tmuxFile, 999)

	oldTime := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(old, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	oldTmux := time.Now().Add(-365 * 24 * time.Hour)
	if err := os.Chtimes(tmuxFile, oldTmux, oldTmux); err != nil {
		t.Fatal(err)
	}

	m := newTestManager(t, Config{HomeDir: t.TempDir(), TmpDir: tmp})

	files, total := m.tmpOldFiles(context.Background())
	if total != 50 {
		t.Fatalf("total = %d, want 50 (only old.log)", total)
	}
	if len(files) != 1 || files[0] != old {
		t.Fatalf("files = %v, want [%s]", files, old)
	}
}

// AC: parseJournalDiskUsage extracts a byte count from journalctl's
// human-readable disk-usage line, using systemd's 1024-based K/M/G/T units.
func TestParseJournalDiskUsage(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"Archived and active journals take up 512.0M in the file system.\n", 512 * (1 << 20), true},
		{"Archived and active journals take up 1.5G in the file system.\n", int64(1.5 * (1 << 30)), true},
		{"", 0, false},
		{"no numbers here", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseJournalDiskUsage(tc.in)
		if ok != tc.ok {
			t.Errorf("parseJournalDiskUsage(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("parseJournalDiskUsage(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// AC: the deep scan finds large files anywhere under its root — not just
// inside the fixed cache/docker categories — which is the whole point of
// "deep and thorough" versus the shallow, known-locations-only Scan.
func TestDeepScan_FindsLargeFilesAnywhereUnderRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "srv", "backups", "db-dump.sql"), 5000)
	writeFile(t, filepath.Join(root, "root", "old-export.tar"), 3000)
	writeFile(t, filepath.Join(root, "srv", "backups", "tiny.txt"), 10)

	m := newTestManager(t, Config{HomeDir: t.TempDir(), DeepScanRoot: root})
	result, err := m.DeepScan(context.Background(), DeepScanOptions{MinSizeBytes: 1000})
	if err != nil {
		t.Fatalf("DeepScan: %v", err)
	}
	if result.LargeFilesTotalCount != 2 {
		t.Fatalf("LargeFilesTotalCount = %d, want 2 (tiny.txt below threshold)", result.LargeFilesTotalCount)
	}
	if result.LargeFilesTotalBytes != 8000 {
		t.Fatalf("LargeFilesTotalBytes = %d, want 8000", result.LargeFilesTotalBytes)
	}
	if len(result.LargeFiles) != 2 {
		t.Fatalf("LargeFiles len = %d, want 2", len(result.LargeFiles))
	}
	// Sorted largest-first.
	if result.LargeFiles[0].SizeBytes != 5000 || result.LargeFiles[1].SizeBytes != 3000 {
		t.Fatalf("LargeFiles not sorted desc: %+v", result.LargeFiles)
	}
	if result.LargeFilesTruncated {
		t.Fatal("small fixture must not truncate")
	}
}

// AC: TotalReclaimableBytes combines the deep large-files total with the
// existing shallow category rollup — the headline number the mobile card
// shows is the sum of both, not just one.
func TestDeepScan_CombinesCategoriesAndLargeFilesIntoTotal(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".cache", "pip", "w.whl"), 1000)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "data", "big.bin"), 4000)

	m := newTestManager(t, Config{HomeDir: home, DeepScanRoot: root})
	result, err := m.DeepScan(context.Background(), DeepScanOptions{MinSizeBytes: 500})
	if err != nil {
		t.Fatalf("DeepScan: %v", err)
	}
	if result.CategoriesTotalBytes != 1000 {
		t.Fatalf("CategoriesTotalBytes = %d, want 1000", result.CategoriesTotalBytes)
	}
	if result.LargeFilesTotalBytes != 4000 {
		t.Fatalf("LargeFilesTotalBytes = %d, want 4000", result.LargeFilesTotalBytes)
	}
	if result.TotalReclaimableBytes != 5000 {
		t.Fatalf("TotalReclaimableBytes = %d, want 5000 (1000 categories + 4000 large files)", result.TotalReclaimableBytes)
	}
}

// AC: an excluded directory (e.g. the agent's own data dir, or Docker's
// internal storage) is never descended into by the deep scan, even though
// it lives on the same device as everything else.
func TestDeepScan_ExcludesConfiguredDirectories(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "var", "lib", "rootmote")
	writeFile(t, filepath.Join(dataDir, "state.db"), 9000)
	writeFile(t, filepath.Join(root, "home", "dev", "video.mp4"), 2000)

	m := newTestManager(t, Config{HomeDir: t.TempDir(), DeepScanRoot: root, DataDir: dataDir})
	result, err := m.DeepScan(context.Background(), DeepScanOptions{MinSizeBytes: 500})
	if err != nil {
		t.Fatalf("DeepScan: %v", err)
	}
	for _, f := range result.LargeFiles {
		if f.Path == filepath.Join(dataDir, "state.db") {
			t.Fatalf("agent data dir must be excluded from the deep scan, found %+v", f)
		}
	}
	if result.LargeFilesTotalBytes != 2000 {
		t.Fatalf("LargeFilesTotalBytes = %d, want 2000 (excluded file must not count)", result.LargeFilesTotalBytes)
	}
}

// AC: results are cached for deepScanCacheTTL; a second call without Force
// returns the identical cached snapshot instead of re-walking, and Force
// always re-walks.
func TestDeepScan_CachesResultUntilForced(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "big.bin"), 2000)

	calls := 0
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	m := newTestManager(t, Config{
		HomeDir:      t.TempDir(),
		DeepScanRoot: root,
		Now: func() time.Time {
			// Monotonically increasing, well within the 10-minute cache TTL
			// between any two calls in this test — robust to however many
			// internal now() calls a single DeepScan happens to make.
			now := base.Add(time.Duration(calls) * time.Millisecond)
			calls++
			return now
		},
	})

	first, err := m.DeepScan(context.Background(), DeepScanOptions{MinSizeBytes: 500})
	if err != nil {
		t.Fatalf("DeepScan: %v", err)
	}
	second, err := m.DeepScan(context.Background(), DeepScanOptions{MinSizeBytes: 500})
	if err != nil {
		t.Fatalf("DeepScan (cached): %v", err)
	}
	if !second.GeneratedAt.Equal(first.GeneratedAt) {
		t.Fatalf("expected cached GeneratedAt %v, got %v", first.GeneratedAt, second.GeneratedAt)
	}
	third, err := m.DeepScan(context.Background(), DeepScanOptions{MinSizeBytes: 500, Force: true})
	if err != nil {
		t.Fatalf("DeepScan (forced): %v", err)
	}
	if third.GeneratedAt.Equal(first.GeneratedAt) {
		t.Fatal("Force must bypass the cache and re-walk")
	}
}

// AC: exceeding the time budget stops the walk early and reports
// LargeFilesTruncated instead of blocking indefinitely.
func TestScanLargeFiles_TruncatesWhenBudgetExceeded(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "big.bin"), 2000)

	_, _, _, truncated := scanLargeFiles(context.Background(), root, 500, 500, 0, nil)
	if !truncated {
		t.Fatal("expected truncated=true with a zero time budget")
	}
}

// AC: the result list is capped at maxResults while totals still reflect
// every match found.
func TestScanLargeFiles_CapsResultsButNotTotals(t *testing.T) {
	root := t.TempDir()
	for i := range 5 {
		writeFile(t, filepath.Join(root, fmt.Sprintf("f%d.bin", i)), 1000+i)
	}
	files, totalBytes, totalCount, truncated := scanLargeFiles(context.Background(), root, 500, 2, time.Minute, nil)
	if truncated {
		t.Fatal("full budget must not truncate this small fixture")
	}
	if len(files) != 2 {
		t.Fatalf("files len = %d, want 2 (capped)", len(files))
	}
	if totalCount != 5 {
		t.Fatalf("totalCount = %d, want 5 (uncapped)", totalCount)
	}
	wantTotal := int64(1000 + 1001 + 1002 + 1003 + 1004)
	if totalBytes != wantTotal {
		t.Fatalf("totalBytes = %d, want %d (uncapped)", totalBytes, wantTotal)
	}
}

// fakeRemover lets DeletePath/clearGlobFiles/vacuumJournal wiring be tested
// without ever shelling out to a real sudo/nsenter/rm — those are exercised
// separately, directly against defaultRemover, below.
type fakeRemover struct {
	removeErr    error
	removeAllErr error
	runOut       []byte
	runErr       error
	removed      []string
	removedAll   []string
	ranCmds      [][]string
}

func (f *fakeRemover) Remove(_ context.Context, path string) error {
	f.removed = append(f.removed, path)
	return f.removeErr
}

func (f *fakeRemover) RemoveAll(_ context.Context, path string) error {
	f.removedAll = append(f.removedAll, path)
	return f.removeAllErr
}

func (f *fakeRemover) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.ranCmds = append(f.ranCmds, append([]string{name}, args...))
	return f.runOut, f.runErr
}

// AC: DeletePath routes a file delete through m.remover.Remove (not a raw
// os.Remove), and surfaces whatever error the remover reports — this is
// the seam privilege escalation hooks into.
func TestDeletePath_DelegatesFileRemovalToRemover(t *testing.T) {
	home := t.TempDir()
	m := newTestManager(t, Config{HomeDir: home})
	file := filepath.Join(home, "big.log")
	writeFile(t, file, 42)

	fr := &fakeRemover{}
	m.remover = fr
	res, err := m.DeletePath(context.Background(), file, false)
	if err != nil {
		t.Fatalf("DeletePath: %v", err)
	}
	if res.FreedBytes != 42 {
		t.Fatalf("FreedBytes = %d, want 42", res.FreedBytes)
	}
	if len(fr.removed) != 1 || fr.removed[0] != file {
		t.Fatalf("remover.Remove calls = %v, want [%s]", fr.removed, file)
	}
	// The fake never actually unlinked anything — proves DeletePath trusts
	// the remover's success rather than re-checking the filesystem itself.
	if _, statErr := os.Stat(file); statErr != nil {
		t.Fatalf("fixture file should still exist (fake remover didn't touch it): %v", statErr)
	}

	fr2 := &fakeRemover{removeErr: fmt.Errorf("storage: privileged delete of %q: sudo: a password is required", file)}
	m.remover = fr2
	if _, err := m.DeletePath(context.Background(), file, false); err == nil || !strings.Contains(err.Error(), "password is required") {
		t.Fatalf("DeletePath err = %v, want the remover's escalation failure surfaced", err)
	}
}

// AC: DeletePath routes a directory delete through m.remover.RemoveAll.
func TestDeletePath_DelegatesDirectoryRemovalToRemover(t *testing.T) {
	home := t.TempDir()
	m := newTestManager(t, Config{HomeDir: home})
	dir := filepath.Join(home, "old-project")
	writeFile(t, filepath.Join(dir, "a.txt"), 100)
	writeFile(t, filepath.Join(dir, "b.txt"), 200)

	fr := &fakeRemover{}
	m.remover = fr
	res, err := m.DeletePath(context.Background(), dir, true)
	if err != nil {
		t.Fatalf("DeletePath: %v", err)
	}
	if res.FreedBytes != 300 {
		t.Fatalf("FreedBytes = %d, want 300", res.FreedBytes)
	}
	if len(fr.removedAll) != 1 || fr.removedAll[0] != dir {
		t.Fatalf("remover.RemoveAll calls = %v, want [%s]", fr.removedAll, dir)
	}
}

// AC: clearGlobFiles (backing the apt_cache category) removes every match
// through m.remover.Remove, so a root-owned /var/cache/apt/archives on the
// deployed agent gets the same escalation path as an explicit delete.
func TestClearGlobFiles_RemovesEachMatchViaRemover(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.deb"), 100)
	writeFile(t, filepath.Join(dir, "b.deb"), 200)
	writeFile(t, filepath.Join(dir, "c.txt"), 999) // must not match *.deb

	m := newTestManager(t, Config{HomeDir: t.TempDir()})
	fr := &fakeRemover{}
	m.remover = fr
	freed, count, err := m.clearGlobFiles(context.Background(), filepath.Join(dir, "*.deb"))
	if err != nil {
		t.Fatalf("clearGlobFiles: %v", err)
	}
	if freed != 300 || count != 2 {
		t.Fatalf("freed=%d count=%d, want 300/2", freed, count)
	}
	sort.Strings(fr.removed)
	want := []string{filepath.Join(dir, "a.deb"), filepath.Join(dir, "b.deb")}
	if !reflect.DeepEqual(fr.removed, want) {
		t.Fatalf("removed = %v, want %v", fr.removed, want)
	}
}

// AC: vacuumJournal runs `journalctl --vacuum-size=<floor>` through
// m.remover.Run (not a raw execCommand), and surfaces a Run failure —
// journalctl writes under /var/log/journal, outside
// rootmote-agent.service's ReadWritePaths, so this needs the exact same
// escalation fallback as an explicit file delete.
func TestVacuumJournal_DelegatesToRemoverRun(t *testing.T) {
	m := newTestManager(t, Config{
		HomeDir: t.TempDir(),
		LookPath: func(name string) (string, error) {
			if name == "journalctl" {
				return "/usr/bin/journalctl", nil
			}
			return "", exec.ErrNotFound
		},
		ExecCommand: func(name string, args ...string) *exec.Cmd {
			// Only the --disk-usage reads (before/after) go through the
			// plain execCommand path; --vacuum-size is routed through the
			// fake remover below and must never reach here.
			return exec.Command("echo", "Archived and active journals take up 512.0M in the file system.")
		},
	})
	fr := &fakeRemover{}
	m.remover = fr
	res, err := m.vacuumJournal(context.Background())
	if err != nil {
		t.Fatalf("vacuumJournal: %v", err)
	}
	if res.Category != CategoryJournalLogs {
		t.Fatalf("category = %q", res.Category)
	}
	want := []string{"journalctl", "--vacuum-size=" + journalVacuumFloor}
	if len(fr.ranCmds) != 1 || !reflect.DeepEqual(fr.ranCmds[0], want) {
		t.Fatalf("ranCmds = %v, want exactly [%v]", fr.ranCmds, want)
	}
}

func TestVacuumJournal_SurfacesRemoverRunError(t *testing.T) {
	m := newTestManager(t, Config{
		HomeDir: t.TempDir(),
		LookPath: func(name string) (string, error) {
			if name == "journalctl" {
				return "/usr/bin/journalctl", nil
			}
			return "", exec.ErrNotFound
		},
	})
	m.remover = &fakeRemover{runErr: errors.New("journalctl: Read-only file system")}
	if _, err := m.vacuumJournal(context.Background()); err == nil || !strings.Contains(err.Error(), "Read-only file system") {
		t.Fatalf("vacuumJournal err = %v, want the underlying failure surfaced", err)
	}
}

// AC: needsEscalation fires for exactly the two errno classes that mean
// "an unprivileged, sandboxed remove failed but root has a path around it"
// (EACCES/EPERM, and EROFS from ProtectSystem=strict's read-only bind
// mounts) — never for an unrelated failure, and never when already root.
func TestDefaultRemoverNeedsEscalation(t *testing.T) {
	unprivileged := defaultRemover{geteuid: func() int { return 1000 }}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"permission denied", &fs.PathError{Op: "remove", Path: "/x", Err: syscall.EACCES}, true},
		{"operation not permitted", &fs.PathError{Op: "remove", Path: "/x", Err: syscall.EPERM}, true},
		{"read-only filesystem", &fs.PathError{Op: "remove", Path: "/x", Err: syscall.EROFS}, true},
		{"unrelated error", errors.New("boom"), false},
		{"not exist", &fs.PathError{Op: "remove", Path: "/x", Err: syscall.ENOENT}, false},
	}
	for _, tc := range cases {
		if got := unprivileged.needsEscalation(tc.err); got != tc.want {
			t.Errorf("%s: needsEscalation = %v, want %v", tc.name, got, tc.want)
		}
	}

	root := defaultRemover{geteuid: func() int { return 0 }}
	if root.needsEscalation(&fs.PathError{Op: "remove", Path: "/x", Err: syscall.EACCES}) {
		t.Fatal("already root: must never escalate")
	}
}

// AC: when a real, unprivileged os.Remove hits a genuine permission error,
// defaultRemover.Remove escalates by shelling to
// `sudo -n nsenter --mount=/proc/1/ns/mnt -- rm -f <path>` — the technique
// that reaches past rootmote-agent.service's ProtectSystem=strict mount
// namespace even for a sudo-escalated root child. Skips if the test
// process itself is root, since root can't produce a real EACCES to prove
// the fallback ever triggers.
func TestDefaultRemover_EscalatesOnRealPermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: cannot produce a real permission error")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	path := filepath.Join(locked, "file")
	writeFile(t, path, 10)
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	var gotName string
	var gotArgs []string
	r := defaultRemover{
		execCommand: func(name string, args ...string) *exec.Cmd {
			gotName = name
			gotArgs = args
			return exec.Command("true")
		},
		lookPath: func(string) (string, error) { return "", exec.ErrNotFound },
		geteuid:  func() int { return 1000 },
	}
	if err := r.Remove(context.Background(), path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if gotName != "sudo" {
		t.Fatalf("escalated command = %q, want sudo", gotName)
	}
	want := []string{"-n", "/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--", "/bin/rm", "-f", path}
	if !reflect.DeepEqual(gotArgs, want) {
		t.Fatalf("escalated args = %v, want %v", gotArgs, want)
	}
}

// AC: a failed escalation attempt (e.g. sudo prompting for a password
// because the sudoers fragment isn't installed) surfaces the real command
// output/error, not a bare "exit status 1".
func TestDefaultRemover_SurfacesEscalationFailureMessage(t *testing.T) {
	r := defaultRemover{
		execCommand: func(name string, args ...string) *exec.Cmd {
			return exec.Command("sh", "-c", "echo 'sudo: a password is required' >&2; exit 1")
		},
		lookPath: func(string) (string, error) { return "", exec.ErrNotFound },
		geteuid:  func() int { return 1000 },
	}
	_, err := r.escalate(context.Background(), "rm", "-f", "/some/path")
	if err == nil || !strings.Contains(err.Error(), "password is required") {
		t.Fatalf("escalate err = %v, want the sudo failure message surfaced", err)
	}
}
