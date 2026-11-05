package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateControlPlaneKey_GeneratesStablePersistentKey(t *testing.T) {
	dir := t.TempDir()
	k1, err := loadOrCreateControlPlaneKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 64 { // 32 random bytes, hex-encoded
		t.Fatalf("key length = %d, want 64 hex chars", len(k1))
	}
	k2, err := loadOrCreateControlPlaneKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatalf("key not stable across calls: %q != %q", k1, k2)
	}
	info, err := os.Stat(controlPlaneKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file perms = %o, want 600", perm)
	}
}

func TestLoadOrCreateControlPlaneKey_TightensLoosePerms(t *testing.T) {
	dir := t.TempDir()
	path := controlPlaneKeyPath(dir)
	if err := os.WriteFile(path, []byte("deadbeef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	key, err := loadOrCreateControlPlaneKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if key != "deadbeef" {
		t.Fatalf("key = %q, want deadbeef", key)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perms after load = %o, want 600 (loose perms must be tightened)", perm)
	}
}

func writeKey(t *testing.T, dir, key string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(controlPlaneKeyPath(dir), []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A root shell has its own ~/rootmote. On Linux the key of the running
// service (its data dir exists) wins over it.
func TestPairingKey_LinuxServiceDirWinsOverHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeKey(t, filepath.Join(home, "rootmote"), "key-from-root-home")
	service := filepath.Join(t.TempDir(), "rootmote")
	writeKey(t, service, "key-from-service")

	key, ok := readPairingKey(pairingKeyDirs("", "linux", service))
	if !ok || key != "key-from-service" {
		t.Fatalf("key = %q, %v; want the service key", key, ok)
	}
	// The service dir exists but has no key yet: the home key must not be used.
	if err := os.Remove(controlPlaneKeyPath(service)); err != nil {
		t.Fatal(err)
	}
	if key, ok := readPairingKey(pairingKeyDirs("", "linux", service)); ok {
		t.Fatalf("fell back to %q although the service dir exists", key)
	}
	// An explicit --data-dir still comes first.
	writeKey(t, service, "key-from-service")
	other := t.TempDir()
	writeKey(t, other, "key-from-flag")
	if key, _ := readPairingKey(pairingKeyDirs(other, "linux", service)); key != "key-from-flag" {
		t.Fatalf("key = %q, want the --data-dir key", key)
	}
}

// Without a service dir (a manual run, or macOS) the user's own data dir is used.
func TestPairingKey_WithoutServiceDirUsesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeKey(t, filepath.Join(home, "rootmote"), "key-from-home")
	missing := filepath.Join(t.TempDir(), "nope")
	for _, goos := range []string{"linux", "darwin"} {
		if key, ok := readPairingKey(pairingKeyDirs("", goos, missing)); !ok || key != "key-from-home" {
			t.Errorf("%s: key = %q, %v", goos, key, ok)
		}
	}
	// macOS never uses the Linux service dir.
	service := t.TempDir()
	writeKey(t, service, "key-from-service")
	if key, _ := readPairingKey(pairingKeyDirs("", "darwin", service)); key != "key-from-home" {
		t.Errorf("darwin key = %q, want the home key", key)
	}
}
