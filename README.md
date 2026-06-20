# Nora Relay

The hosted hub for [Nora](https://github.com/nankio/nora), the non-custodial Nano
(XNO) signer. The relay routes transaction requests from external callers to the
user's desktop agent over a persistent WebSocket. **It never sees a private key**,
and it never sees a connection's policy (those are end-to-end encrypted).

This repository is self-contained and depends on nothing from the desktop app —
the only shared contract is the versioned wire protocol in `internal/protocol`.

```
  External service ──POST /v1/requests──►  ┌───────────────┐
   (API key, bound to one account)          │     relay     │
                                            │  • authenticates the caller
                                            │  • routes over a persistent
                                            │    outbound WebSocket
                                            │  • idempotency by nonce
                                            └───────┬───────┘
                                                    │ WebSocket (agent dials out — works behind NAT)
                                                    ▼
                                             desktop agent (holds the seed, signs locally)
```

Devices self-enroll by proving control of their Nano accounts (challenge /
signature), so there are no device tokens or config files. External callers
authenticate with an API key minted in-app by the account owner.

## Run locally

Requires **Go 1.25+**.

```bash
go build -o relay ./cmd/relay
./relay                              # :8080, in-memory store (dev only)

# Persistent SQLite (the schema is auto-applied on boot):
SQLITE_PATH=./nora.db ./relay
```

When `SQLITE_PATH` is unset, the relay uses an in-memory store (development only).

## Configuration

| Env | Description |
|-----|-------------|
| `SQLITE_PATH` | SQLite file path. When unset, an in-memory store is used. |
| `LISTEN` | Listen address (default `:8080`). |

On startup the relay auto-loads `.env.local`, then `.env`, from the working
directory. See [`.env.example`](.env.example).

## Deploy (Fly.io)

Runs as a single always-on instance with SQLite on a persistent volume (see
[`fly.toml`](fly.toml)). Fly terminates TLS and provides a stable
`wss://<app>.fly.dev/agent` endpoint.

```bash
fly apps create nora-relay
fly volumes create nora_data --size 1 --region gru   # match primary_region
fly deploy
```

Then point the agent's **Relay URL** setting at `wss://<app>.fly.dev/agent`.

## Migrating from Postgres to SQLite

`cmd/migrate` copies the relay's state (API-key hashes + encrypted policy blobs)
from Postgres into a SQLite file. It is idempotent and never writes to Postgres.

```bash
DATABASE_URL=postgres://... SQLITE_PATH=./nora.db go run ./cmd/migrate
```

The binary is also bundled in the Docker image as `/migrate`, so it can run as a
one-off Fly machine with the volume mounted.

## Layout

| Path | What it is |
|------|------------|
| `cmd/relay` | The hub: caller API + WebSocket enrollment + account routing + Store. |
| `cmd/migrate` | One-off Postgres → SQLite importer. |
| `internal/protocol` | Wire types shared with the agent (challenge/auth/control/query). |
| `internal/nano` | Nano crypto subset: address parsing, ed25519-blake2b verify, challenge digest. |
