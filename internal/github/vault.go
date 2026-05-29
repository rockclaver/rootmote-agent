// Package github implements GitHub OAuth, repository, commit, push, and pull
// request operations for the agent.
package github

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

const keyBytes = 32

// TokenVault encrypts GitHub OAuth tokens into per-account blobs. SQLite stores
// only blob paths; the plaintext token is returned only at call time.
type TokenVault struct {
	KeyPath          string
	BlobDir          string
	RequireRootOwner bool
}

func NewTokenVault(keyPath, blobDir string) *TokenVault {
	return &TokenVault{KeyPath: keyPath, BlobDir: blobDir, RequireRootOwner: os.Geteuid() == 0}
}

func (v *TokenVault) Seal(accountLogin, token string) (string, error) {
	if accountLogin == "" || token == "" {
		return "", errors.New("account_login and token required")
	}
	key, err := v.key()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	raw := append(nonce, gcm.Seal(nil, nonce, []byte(token), []byte(accountLogin))...)
	if err := os.MkdirAll(v.BlobDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(v.BlobDir, base64.RawURLEncoding.EncodeToString([]byte(accountLogin))+".token")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (v *TokenVault) Open(accountLogin, path string) (string, error) {
	key, err := v.key()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("github token blob is truncated")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(accountLogin))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (v *TokenVault) Delete(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (v *TokenVault) key() ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(v.KeyPath), 0o700); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(v.KeyPath)
	if errors.Is(err, os.ErrNotExist) {
		raw = make([]byte, keyBytes)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return nil, err
		}
		if err := os.WriteFile(v.KeyPath, raw, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(raw) != keyBytes {
		return nil, fmt.Errorf("github token key must be %d bytes", keyBytes)
	}
	if err := v.validateKeyFile(); err != nil {
		return nil, err
	}
	return raw, nil
}

func (v *TokenVault) validateKeyFile() error {
	info, err := os.Stat(v.KeyPath)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("github token key permissions must be 0600, got %03o", info.Mode().Perm())
	}
	if v.RequireRootOwner && runtime.GOOS != "windows" {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot inspect github token key owner")
		}
		if st.Uid != 0 {
			return fmt.Errorf("github token key must be root-owned, got uid %d", st.Uid)
		}
	}
	return nil
}
