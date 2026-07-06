package main

import (
	"context"
	"path/filepath"
	"testing"
)

// TestRegisterAPIKeyRotation verifies in-place key rotation: re-registering an
// existing key id with a new hash invalidates the old plaintext, activates the
// new one, and preserves the key's id, account, and CORS origins. Runs against
// both store backends (dev in-memory and production SQLite).
func TestRegisterAPIKeyRotation(t *testing.T) {
	ctx := context.Background()
	backends := map[string]func() Store{
		"mem": func() Store { return newMemStore() },
		"sqlite": func() Store {
			s, err := newSQLiteStore(ctx, filepath.Join(t.TempDir(), "rotate.db"))
			if err != nil {
				t.Fatalf("newSQLiteStore: %v", err)
			}
			return s
		},
	}

	for name, mk := range backends {
		t.Run(name, func(t *testing.T) {
			s := mk()
			defer s.Close()

			const (
				keyID   = "ak_rotate"
				account = "nano_1owner"
				oldKey  = "nora_oldsecret"
				newKey  = "nora_freshsecret"
				origin  = "https://app.example"
			)

			if err := s.RegisterAPIKey(ctx, keyID, account, hashSecret(oldKey)); err != nil {
				t.Fatalf("register old: %v", err)
			}
			if err := s.UpdateKeyOrigins(ctx, keyID, account, []string{origin}); err != nil {
				t.Fatalf("set origins: %v", err)
			}
			if k, err := s.ResolveAPIKey(ctx, oldKey); err != nil || k.ID != keyID {
				t.Fatalf("resolve old before rotate: k=%+v err=%v", k, err)
			}

			// Rotate: same key id, new hash.
			if err := s.RegisterAPIKey(ctx, keyID, account, hashSecret(newKey)); err != nil {
				t.Fatalf("register new: %v", err)
			}

			// Old secret must no longer authenticate.
			if _, err := s.ResolveAPIKey(ctx, oldKey); err != ErrNotFound {
				t.Fatalf("old secret still resolves after rotation (err=%v)", err)
			}
			// New secret resolves to the same connection.
			k, err := s.ResolveAPIKey(ctx, newKey)
			if err != nil || k.ID != keyID || k.OwnerAccount != account {
				t.Fatalf("resolve new after rotate: k=%+v err=%v", k, err)
			}
			// CORS origins survive the rotation.
			if ok, err := s.OriginAllowed(ctx, origin); err != nil || !ok {
				t.Fatalf("origin not preserved across rotation: ok=%v err=%v", ok, err)
			}
		})
	}
}
