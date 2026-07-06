package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// ErrNotFound is returned when an API key or record does not exist.
var ErrNotFound = errors.New("not found")

// APIKey is the minimal index the relay keeps for a caller credential: its id
// (used as the request's contact id, for policy routing), the account it acts
// on, and the web origins allowed to use it from a browser.
type APIKey struct {
	ID             string
	OwnerAccount   string   // the user's nano_ account this key signs for
	AllowedOrigins []string // CORS: web origins permitted to call this key
}

// Store is the relay's persistence boundary. The in-memory and SQLite
// implementations are interchangeable; production uses SQLite.
type Store interface {
	// RegisterAPIKey records a device-minted key: the relay stores only its hash
	// and the account it acts on, so it can authenticate inbound requests.
	RegisterAPIKey(ctx context.Context, keyID, ownerAccount, hash string) error
	RevokeAPIKey(ctx context.Context, ownerAccount, id string) error
	ResolveAPIKey(ctx context.Context, plaintext string) (APIKey, error)

	// UpdateKeyOrigins sets the CORS allowed-origins list for a single API key.
	// Only the owning account may update its own keys.
	UpdateKeyOrigins(ctx context.Context, keyID, ownerAccount string, origins []string) error

	// OriginAllowed reports whether any key belonging to any account has listed
	// origin in its allowed-origins set. Used to answer OPTIONS preflight before
	// authentication is possible.
	OriginAllowed(ctx context.Context, origin string) (bool, error)

	// Encrypted policy blobs, keyed by account. The relay stores opaque
	// ciphertext and only accepts strictly newer versions (last-write-wins).
	PutPolicy(ctx context.Context, account string, version int, blob []byte) error
	GetPolicy(ctx context.Context, account string) (version int, blob []byte, found bool, err error)

	Close()
}

type policyBlob struct {
	version int
	blob    []byte
}

// --- in-memory implementation (default; also used by tests) ---

type memStore struct {
	mu     sync.RWMutex
	keys   map[string]APIKey     // id -> key
	byHash map[string]string     // key hash -> id
	policy map[string]policyBlob // account -> encrypted policy
}

func newMemStore() *memStore {
	return &memStore{
		keys:   map[string]APIKey{},
		byHash: map[string]string{},
		policy: map[string]policyBlob{},
	}
}

func (s *memStore) PutPolicy(_ context.Context, account string, version int, blob []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.policy[account]; ok && version <= cur.version {
		return nil // ignore stale or duplicate versions
	}
	s.policy[account] = policyBlob{version: version, blob: blob}
	return nil
}

func (s *memStore) GetPolicy(_ context.Context, account string) (int, []byte, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policy[account]
	if !ok {
		return 0, nil, false, nil
	}
	return p.version, p.blob, true, nil
}

func (s *memStore) RegisterAPIKey(_ context.Context, keyID, ownerAccount, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-registering an existing key id rotates its secret: drop any previous
	// hash(es) pointing at this key so the old plaintext stops resolving. This
	// mirrors the SQLite store, whose UNIQUE key_hash column is replaced by the
	// ON CONFLICT(id) DO UPDATE upsert.
	for h, kid := range s.byHash {
		if kid == keyID {
			delete(s.byHash, h)
		}
	}
	// Preserve the key's existing CORS origins across a rotation (a brand-new
	// key starts with none).
	k := s.keys[keyID]
	k.ID = keyID
	k.OwnerAccount = ownerAccount
	s.keys[keyID] = k
	s.byHash[hash] = keyID
	return nil
}

func (s *memStore) UpdateKeyOrigins(_ context.Context, keyID, ownerAccount string, origins []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok || k.OwnerAccount != ownerAccount {
		return ErrNotFound
	}
	k.AllowedOrigins = origins
	s.keys[keyID] = k
	return nil
}

func (s *memStore) OriginAllowed(_ context.Context, origin string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.keys {
		for _, o := range k.AllowedOrigins {
			if o == origin {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *memStore) RevokeAPIKey(_ context.Context, ownerAccount, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok || k.OwnerAccount != ownerAccount {
		return ErrNotFound
	}
	delete(s.keys, id)
	for h, kid := range s.byHash {
		if kid == id {
			delete(s.byHash, h)
		}
	}
	return nil
}

func (s *memStore) ResolveAPIKey(_ context.Context, plaintext string) (APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byHash[hashSecret(plaintext)]
	if !ok {
		return APIKey{}, ErrNotFound
	}
	return s.keys[id], nil
}

func (s *memStore) Close() {}

func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
