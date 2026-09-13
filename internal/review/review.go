// Package review provides the durable confirmation-token and audit boundary
// used by reviewed host remediation.
package review

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/rockclaver/rootmote-agent/internal/store"
)

var (
	ErrTokenInvalid  = errors.New("confirmation_token is invalid")
	ErrTokenExpired  = errors.New("confirmation_token is expired")
	ErrTokenUsed     = errors.New("confirmation_token has already been used")
	ErrTokenMismatch = errors.New("confirmation_token does not match this action")
)

// Manager owns confirmation tokens and the audit trail. Scope values remain
// opaque labels so existing audit records continue to be readable.
type Manager struct {
	Store     *store.Store
	Now       func() time.Time
	TokenTTL  time.Duration
	randToken func() string
}

func New(first any, rest ...any) *Manager {
	var s *store.Store
	for _, value := range append([]any{first}, rest...) {
		if candidate, ok := value.(*store.Store); ok {
			s = candidate
			break
		}
	}
	return &Manager{Store: s, Now: time.Now, TokenTTL: 5 * time.Minute, randToken: randomToken}
}

// HeuristicSummarizer remains as an empty compatibility type for callers that
// persisted older construction paths. Diff generation is no longer supported.
type HeuristicSummarizer struct{}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (m *Manager) MintConfirmationToken(action, scope string, files []string, comment string) (store.ConfirmationToken, error) {
	tok := store.ConfirmationToken{Token: m.randToken(), ActionHash: ActionHash(action, scope, files, comment), ProjectID: scope, CreatedAt: m.Now(), ExpiresAt: m.Now().Add(m.TokenTTL)}
	if err := m.Store.CreateConfirmationToken(tok); err != nil {
		return store.ConfirmationToken{}, err
	}
	return tok, nil
}

func (m *Manager) ConsumeToken(token, action, scope string, files []string, comment string) error {
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
	if row.ActionHash != ActionHash(action, scope, files, comment) {
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

func (m *Manager) LogAudit(e store.AuditEntry) (store.AuditEntry, error) {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = m.Now()
	}
	return m.Store.AppendAudit(e)
}

func (m *Manager) ListAudit(filterType, scope string, limit int) ([]store.AuditEntry, error) {
	return m.Store.ListAudit(filterType, scope, limit)
}

func ActionHash(action, scope string, files []string, comment string) string {
	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	h := sha256.New()
	h.Write([]byte(action))
	h.Write([]byte{0})
	h.Write([]byte(scope))
	h.Write([]byte{0})
	for _, f := range sorted {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	h.Write([]byte(comment))
	return hex.EncodeToString(h.Sum(nil))
}
