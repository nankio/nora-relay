// Command migrate copies the relay's persistent state from Postgres into a
// SQLite file. It is a one-shot tool for moving a hosted relay (Cloud Run +
// Postgres) onto a single self-hosted instance (VM + SQLite).
//
// Usage:
//
//	DATABASE_URL=postgres://... SQLITE_PATH=./nora.db go run ./cmd/migrate
//
// It is idempotent: rows are upserted, so re-running tops up the SQLite copy
// without duplicating. It never writes to Postgres.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"
)

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

func main() {
	pgURL := os.Getenv("DATABASE_URL")
	sqlitePath := os.Getenv("SQLITE_PATH")
	if pgURL == "" || sqlitePath == "" {
		log.Fatal("set both DATABASE_URL (source) and SQLITE_PATH (destination)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("ping postgres: %v", err)
	}

	sqlite, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer sqlite.Close()
	sqlite.SetMaxOpenConns(1)
	if _, err := sqlite.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		log.Fatalf("sqlite wal: %v", err)
	}
	if _, err := sqlite.ExecContext(ctx, sqliteSchema); err != nil {
		log.Fatalf("sqlite schema: %v", err)
	}

	keys, err := migrateAPIKeys(ctx, pool, sqlite)
	if err != nil {
		log.Fatalf("migrate api_keys: %v", err)
	}
	blobs, err := migratePolicyBlobs(ctx, pool, sqlite)
	if err != nil {
		log.Fatalf("migrate policy_blobs: %v", err)
	}

	log.Printf("done: %d api_keys, %d policy_blobs -> %s", keys, blobs, sqlitePath)
}

func migrateAPIKeys(ctx context.Context, pool *pgxpool.Pool, dst *sql.DB) (int, error) {
	rows, err := pool.Query(ctx, `SELECT id, owner_account, key_hash, allowed_origins FROM api_keys`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id, owner, hash string
		var origins []string
		if err := rows.Scan(&id, &owner, &hash, &origins); err != nil {
			return n, err
		}
		if origins == nil {
			origins = []string{}
		}
		blob, _ := json.Marshal(origins)
		if _, err := dst.ExecContext(ctx,
			`INSERT INTO api_keys (id, owner_account, key_hash, allowed_origins) VALUES (?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET owner_account=excluded.owner_account, key_hash=excluded.key_hash, allowed_origins=excluded.allowed_origins`,
			id, owner, hash, string(blob)); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migratePolicyBlobs(ctx context.Context, pool *pgxpool.Pool, dst *sql.DB) (int, error) {
	rows, err := pool.Query(ctx, `SELECT account, version, blob FROM policy_blobs`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var account string
		var version int
		var blob []byte
		if err := rows.Scan(&account, &version, &blob); err != nil {
			return n, err
		}
		if _, err := dst.ExecContext(ctx,
			`INSERT INTO policy_blobs (account, version, blob) VALUES (?,?,?)
			 ON CONFLICT(account) DO UPDATE SET version=excluded.version, blob=excluded.blob
			 WHERE excluded.version > policy_blobs.version`,
			account, version, blob); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}
