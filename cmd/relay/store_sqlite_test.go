package main

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSQLiteStore(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := newSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("newSQLiteStore: %v", err)
	}
	defer s.Close()

	const (
		keyID   = "key_1"
		account = "nano_1abc"
		secret  = "nora_secretplaintext"
	)

	// Register then resolve by plaintext.
	if err := s.RegisterAPIKey(ctx, keyID, account, hashSecret(secret)); err != nil {
		t.Fatalf("RegisterAPIKey: %v", err)
	}
	k, err := s.ResolveAPIKey(ctx, secret)
	if err != nil {
		t.Fatalf("ResolveAPIKey: %v", err)
	}
	if k.ID != keyID || k.OwnerAccount != account {
		t.Fatalf("resolved %+v, want id=%s account=%s", k, keyID, account)
	}

	// Unknown secret resolves to ErrNotFound.
	if _, err := s.ResolveAPIKey(ctx, "wrong"); err != ErrNotFound {
		t.Fatalf("ResolveAPIKey(wrong) = %v, want ErrNotFound", err)
	}

	// Origins round-trip and feed OriginAllowed.
	if err := s.UpdateKeyOrigins(ctx, keyID, account, []string{"https://app.example"}); err != nil {
		t.Fatalf("UpdateKeyOrigins: %v", err)
	}
	if ok, err := s.OriginAllowed(ctx, "https://app.example"); err != nil || !ok {
		t.Fatalf("OriginAllowed(known) = %v,%v want true,nil", ok, err)
	}
	if ok, _ := s.OriginAllowed(ctx, "https://evil.example"); ok {
		t.Fatal("OriginAllowed(unknown) = true, want false")
	}
	if k, _ := s.ResolveAPIKey(ctx, secret); len(k.AllowedOrigins) != 1 || k.AllowedOrigins[0] != "https://app.example" {
		t.Fatalf("AllowedOrigins = %v", k.AllowedOrigins)
	}

	// Policy blobs: newer versions win, stale versions ignored.
	if err := s.PutPolicy(ctx, account, 2, []byte("v2")); err != nil {
		t.Fatalf("PutPolicy v2: %v", err)
	}
	if err := s.PutPolicy(ctx, account, 1, []byte("v1-stale")); err != nil {
		t.Fatalf("PutPolicy v1: %v", err)
	}
	ver, blob, found, err := s.GetPolicy(ctx, account)
	if err != nil || !found || ver != 2 || string(blob) != "v2" {
		t.Fatalf("GetPolicy = ver%d %q found=%v err=%v, want ver2 v2", ver, blob, found, err)
	}

	// Revocation removes the key; wrong owner cannot revoke.
	if err := s.RevokeAPIKey(ctx, "nano_other", keyID); err != ErrNotFound {
		t.Fatalf("RevokeAPIKey(wrong owner) = %v, want ErrNotFound", err)
	}
	if err := s.RevokeAPIKey(ctx, account, keyID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, err := s.ResolveAPIKey(ctx, secret); err != ErrNotFound {
		t.Fatalf("ResolveAPIKey after revoke = %v, want ErrNotFound", err)
	}

	// Persistence: reopen the same file and confirm the policy blob survived.
	s.Close()
	s2, err := newSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if _, _, found, _ := s2.GetPolicy(ctx, account); !found {
		t.Fatal("policy blob did not persist across reopen")
	}
}
