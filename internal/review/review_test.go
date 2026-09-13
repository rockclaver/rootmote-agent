package review

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/rockclaver/rootmote-agent/internal/store"
)

func TestConfirmationTokenIsSingleUseAndScopeBound(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := New(st)
	tok, err := m.MintConfirmationToken("incident.runbook.execute", "incident-1", []string{"restart:api"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConsumeToken(tok.Token, "incident.runbook.execute", "incident-1", []string{"restart:api"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.ConsumeToken(tok.Token, "incident.runbook.execute", "incident-1", []string{"restart:api"}, ""); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second consume = %v", err)
	}
}
