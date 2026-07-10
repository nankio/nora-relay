package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// TestRebindAPIKey verifies that moving a connection between a user's own
// accounts keeps the key usable: the same secret still authenticates, the id and
// CORS origins survive, and only the bound account changes.
//
// This is the whole point of rebinding. Changing which of your own accounts a
// connection spends from is not a reason to make callers re-authenticate, so it
// must not behave like a rotation.
func TestRebindAPIKey(t *testing.T) {
	ctx := context.Background()
	backends := map[string]func() Store{
		"mem": func() Store { return newMemStore() },
		"sqlite": func() Store {
			s, err := newSQLiteStore(ctx, filepath.Join(t.TempDir(), "rebind.db"))
			if err != nil {
				t.Fatalf("newSQLiteStore: %v", err)
			}
			return s
		},
	}

	const (
		keyID   = "ak_1"
		accA    = "nano_aaa"
		accB    = "nano_bbb"
		secret  = "nora_secret"
		origin  = "https://nora-control.fly.dev"
		foreign = "nano_zzz"
	)

	for name, mk := range backends {
		t.Run(name, func(t *testing.T) {
			s := mk()
			defer s.Close()

			if err := s.RegisterAPIKey(ctx, keyID, accA, hashSecret(secret)); err != nil {
				t.Fatalf("RegisterAPIKey: %v", err)
			}
			if err := s.UpdateKeyOrigins(ctx, keyID, accA, []string{origin}); err != nil {
				t.Fatalf("UpdateKeyOrigins: %v", err)
			}

			if err := s.RebindAPIKey(ctx, keyID, accA, accB); err != nil {
				t.Fatalf("RebindAPIKey: %v", err)
			}

			// The token the caller already holds must keep working, now
			// pointing at the new account.
			k, err := s.ResolveAPIKey(ctx, secret)
			if err != nil {
				t.Fatalf("the existing secret stopped authenticating: %v", err)
			}
			if k.OwnerAccount != accB {
				t.Errorf("OwnerAccount = %q, want %q", k.OwnerAccount, accB)
			}
			if k.ID != keyID {
				t.Errorf("ID = %q, want %q — rebinding must not mint a new connection", k.ID, keyID)
			}
			if len(k.AllowedOrigins) != 1 || k.AllowedOrigins[0] != origin {
				t.Errorf("AllowedOrigins = %v, want them preserved", k.AllowedOrigins)
			}

			// Origins are updated against the new owner, which is what a
			// subsequent edit in the app does.
			if err := s.UpdateKeyOrigins(ctx, keyID, accB, []string{origin}); err != nil {
				t.Errorf("UpdateKeyOrigins after rebind: %v", err)
			}

			// Rebinding from an account that does not own the key must fail:
			// this search is the relay's authorisation check.
			if err := s.RebindAPIKey(ctx, keyID, foreign, foreign); !errors.Is(err, ErrNotFound) {
				t.Errorf("rebind from a foreign account: err = %v, want ErrNotFound", err)
			}
			if err := s.RebindAPIKey(ctx, "ak_missing", accB, accA); !errors.Is(err, ErrNotFound) {
				t.Errorf("rebind of an unknown key: err = %v, want ErrNotFound", err)
			}

			// The failed attempts changed nothing.
			if k, err := s.ResolveAPIKey(ctx, secret); err != nil || k.OwnerAccount != accB {
				t.Errorf("after failed rebinds: account = %q, err = %v", k.OwnerAccount, err)
			}
		})
	}
}

// A no-op rebind onto the account the key already has must succeed, because the
// device re-asserts its policy on every save and should not see spurious errors.
func TestRebindAPIKeyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newMemStore()
	defer s.Close()

	if err := s.RegisterAPIKey(ctx, "ak_1", "nano_aaa", hashSecret("nora_secret")); err != nil {
		t.Fatalf("RegisterAPIKey: %v", err)
	}
	if err := s.RebindAPIKey(ctx, "ak_1", "nano_aaa", "nano_aaa"); err != nil {
		t.Fatalf("self-rebind: %v", err)
	}
	if k, err := s.ResolveAPIKey(ctx, "nora_secret"); err != nil || k.OwnerAccount != "nano_aaa" {
		t.Fatalf("account = %q, err = %v", k.OwnerAccount, err)
	}
}
