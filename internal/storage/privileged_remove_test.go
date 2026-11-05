package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunPrivilegedRemove_RefusesUnsafeArguments(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"no args":             nil,
		"extra args":          {"-f", file, "/etc/passwd"},
		"bad flag":            {"-r", file},
		"relative":            {"-f", "rel/path"},
		"traversal":           {"-rf", dir + "/../" + filepath.Base(dir)},
		"root":                {"-rf", "/"},
		"system dir":          {"-rf", "/etc"},
		"system dir trailing": {"-rf", "/usr/"},
		"ancestor of system":  {"-rf", "/"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if err := RunPrivilegedRemove(args); err == nil {
				t.Fatalf("RunPrivilegedRemove(%v) succeeded, want refusal", args)
			}
		})
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("refused calls must not delete the file: %v", err)
	}
}

func TestRunPrivilegedRemove_FileAndDirectorySemantics(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	sub := filepath.Join(dir, "sub")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sub, "deep"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := RunPrivilegedRemove([]string{"-f", sub}); err == nil {
		t.Fatal("-f on a directory must be refused")
	}
	if err := RunPrivilegedRemove([]string{"-f", file}); err != nil {
		t.Fatalf("-f file: %v", err)
	}
	if _, err := os.Lstat(file); !os.IsNotExist(err) {
		t.Fatalf("file still present: %v", err)
	}
	if err := RunPrivilegedRemove([]string{"-f", file}); err != nil {
		t.Fatalf("-f on a missing path must succeed like rm -f: %v", err)
	}
	if err := RunPrivilegedRemove([]string{"-rf", sub}); err != nil {
		t.Fatalf("-rf dir: %v", err)
	}
	if _, err := os.Lstat(sub); !os.IsNotExist(err) {
		t.Fatalf("dir still present: %v", err)
	}
}

func TestRunPrivilegedRemove_SymlinkedParentCannotReachSystemDir(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "etc-link")
	if err := os.Symlink("/etc", link); err != nil {
		t.Skip("symlink unsupported")
	}
	// Deleting the link itself is fine; deleting through it into /etc is not
	// reachable because /etc/<name> resolves under a protected parent only
	// when the final component is a protected dir.
	if err := RunPrivilegedRemove([]string{"-rf", link}); err != nil {
		t.Fatalf("removing the symlink itself must work: %v", err)
	}
	if _, err := os.Stat("/etc"); err != nil {
		t.Fatalf("/etc must be untouched: %v", err)
	}
}
