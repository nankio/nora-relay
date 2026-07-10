package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go driver, no CGo (keeps CGO_ENABLED=0 builds working)
)

// sqliteSchema defines the relay's tables. SQLite has no array type, so
// allowed_origins is stored as a JSON-encoded text array; the blob is a BLOB.
const sqliteSchema = `
CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    owner_account   TEXT NOT NULL,
    key_hash        TEXT NOT NULL UNIQUE,
    allowed_origins TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS api_keys_owner_idx ON api_keys (owner_account);
CREATE INDEX IF NOT EXISTS api_keys_hash_idx  ON api_keys (key_hash);

CREATE TABLE IF NOT EXISTS policy_blobs (
    account    TEXT PRIMARY KEY,
    version    INTEGER NOT NULL,
    blob       BLOB NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`

// sqliteStore is the file-backed Store for single-instance (self-hosted) relays.
type sqliteStore struct {
	db *sql.DB
}

// newSQLiteStore opens (creating if needed) the SQLite database at path and
// ensures the schema exists. WAL mode is enabled for better read/write
// concurrency under the relay's mixed load.
func newSQLiteStore(ctx context.Context, path string) (*sqliteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("relay: opening sqlite: %w", err)
	}
	// A single writer connection avoids "database is locked" under concurrent
	// writes; SQLite serializes writers anyway and our write volume is tiny.
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("relay: sqlite pragma %q: %w", pragma, err)
		}
	}
	if _, err := db.ExecContext(ctx, sqliteSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("relay: applying sqlite schema: %w", err)
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) RegisterAPIKey(ctx context.Context, keyID, ownerAccount, hash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (id, owner_account, key_hash) VALUES (?,?,?)
		 ON CONFLICT(id) DO UPDATE SET owner_account=excluded.owner_account, key_hash=excluded.key_hash`,
		keyID, ownerAccount, hash)
	return err
}

func (s *sqliteStore) RebindAPIKey(ctx context.Context, keyID, oldAccount, newAccount string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET owner_account=? WHERE id=? AND owner_account=?`,
		newAccount, keyID, oldAccount)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStore) RevokeAPIKey(ctx context.Context, ownerAccount, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id=? AND owner_account=?`, id, ownerAccount)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStore) ResolveAPIKey(ctx context.Context, plaintext string) (APIKey, error) {
	var k APIKey
	var originsJSON string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, owner_account, allowed_origins FROM api_keys WHERE key_hash=?`,
		hashSecret(plaintext)).Scan(&k.ID, &k.OwnerAccount, &originsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return APIKey{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, err
	}
	k.AllowedOrigins = decodeOrigins(originsJSON)
	return k, nil
}

func (s *sqliteStore) UpdateKeyOrigins(ctx context.Context, keyID, ownerAccount string, origins []string) error {
	if origins == nil {
		origins = []string{}
	}
	blob, err := json.Marshal(origins)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET allowed_origins=? WHERE id=? AND owner_account=?`,
		string(blob), keyID, ownerAccount)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStore) OriginAllowed(ctx context.Context, origin string) (bool, error) {
	// allowed_origins is small per row and the table is tiny; scan and decode.
	rows, err := s.db.QueryContext(ctx, `SELECT allowed_origins FROM api_keys WHERE allowed_origins <> '[]'`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var originsJSON string
		if err := rows.Scan(&originsJSON); err != nil {
			return false, err
		}
		for _, o := range decodeOrigins(originsJSON) {
			if o == origin {
				return true, nil
			}
		}
	}
	return false, rows.Err()
}

func (s *sqliteStore) PutPolicy(ctx context.Context, account string, version int, blob []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO policy_blobs (account, version, blob) VALUES (?,?,?)
		 ON CONFLICT(account) DO UPDATE SET version=excluded.version, blob=excluded.blob, updated_at=datetime('now')
		 WHERE excluded.version > policy_blobs.version`,
		account, version, blob)
	return err
}

func (s *sqliteStore) GetPolicy(ctx context.Context, account string) (int, []byte, bool, error) {
	var version int
	var blob []byte
	err := s.db.QueryRowContext(ctx, `SELECT version, blob FROM policy_blobs WHERE account=?`, account).Scan(&version, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, false, nil
	}
	if err != nil {
		return 0, nil, false, err
	}
	return version, blob, true, nil
}

func (s *sqliteStore) Close() { _ = s.db.Close() }

// decodeOrigins parses a JSON text array, tolerating empty/invalid as no origins.
func decodeOrigins(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
