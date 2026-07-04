package main

import (
	"os"
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
