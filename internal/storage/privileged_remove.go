package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PrivilegedHelperPath is the installed agent binary the sudoers fragment
// allows `rootmote` to run as root (inside PID 1's mount namespace) for the
// `storage-rm` subcommand. It is a fixed path so the sudoers rule never has to
// grant a generic `rm`.
const PrivilegedHelperPath = "/usr/local/bin/rootmote-agent"

// PrivilegedRemoveSubcommand is the argv[1] that selects the helper mode.
const PrivilegedRemoveSubcommand = "storage-rm"

// RunPrivilegedRemove implements `rootmote-agent storage-rm <-f|-rf> <path>`.
// It runs as root, so it re-validates everything instead of trusting the
// unprivileged caller: exactly two arguments, a known flag, an absolute clean
// path with no traversal, and a target that is neither a system directory nor
// an ancestor of one (after resolving symlinks in the parent directory). It
// deletes with the os package directly; no external `rm` or shell is involved.
func RunPrivilegedRemove(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: storage-rm <-f|-rf> <absolute-path>")
	}
	recursive := false
	switch args[0] {
	case "-f":
	case "-rf":
		recursive = true
	default:
		return fmt.Errorf("storage-rm: unsupported flag %q", args[0])
	}
	path, err := validatePrivilegedRemovePath(args[1])
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // rm -f semantics
		}
		return err
	}
	if info.IsDir() && !recursive {
		return fmt.Errorf("storage-rm: %q is a directory; -rf required", path)
	}
	if recursive {
		return os.RemoveAll(path)
	}
	return os.Remove(path)
}

func validatePrivilegedRemovePath(raw string) (string, error) {
	if raw == "" || !filepath.IsAbs(raw) {
		return "", fmt.Errorf("storage-rm: path must be absolute, got %q", raw)
	}
	if strings.ContainsRune(raw, 0) {
		return "", errors.New("storage-rm: path contains NUL")
	}
	for _, seg := range strings.Split(raw, "/") {
		if seg == ".." {
			return "", fmt.Errorf("storage-rm: path %q contains '..'", raw)
		}
	}
	clean := filepath.Clean(raw)
	// Resolve symlinks in the parent only: the final component is removed as a
	// link, never followed, but a symlinked parent could otherwise smuggle the
	// delete into a protected directory.
	resolved := clean
	if parent, err := filepath.EvalSymlinks(filepath.Dir(clean)); err == nil {
		resolved = filepath.Join(parent, filepath.Base(clean))
	}
	for _, candidate := range []string{clean, resolved} {
		for _, p := range protectedSystemDirs {
			if candidate == p || isAncestor(candidate, p) {
				return "", fmt.Errorf("storage-rm: refusing to delete system directory %q", candidate)
			}
			if r, err := filepath.EvalSymlinks(p); err == nil && (candidate == r || isAncestor(candidate, r)) {
				return "", fmt.Errorf("storage-rm: refusing to delete system directory %q", candidate)
			}
		}
	}
	return clean, nil
}

// isAncestor reports whether dir contains target (dir != target).
func isAncestor(dir, target string) bool {
	if dir == target {
		return false
	}
	prefix := strings.TrimSuffix(dir, "/") + "/"
	return strings.HasPrefix(target, prefix)
}
