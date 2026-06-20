// Package protocol defines the wire types shared by the relay, the desktop
// agent, and external callers. The model is a "live chat": each Contact is a
// service, agent, or human that can request transactions, and every Contact
// carries its own Permission describing what may be auto-approved.
//
// Amounts are encoded as decimal raw strings (never floats) to preserve the
// full 128-bit precision of Nano balances.
package protocol

import (
	"encoding/json"
	"time"
)

// ProtocolVersion is bumped on incompatible wire changes.
const ProtocolVersion = 2

// EnvelopeType discriminates messages on the agent<->relay WebSocket.
type EnvelopeType string

const (
	TypeHello       EnvelopeType = "hello"        // agent -> relay: announce device + accounts
	TypeChallenge   EnvelopeType = "challenge"    // relay -> agent: nonce to sign
	TypeAuth        EnvelopeType = "auth"         // agent -> relay: signatures proving account control
	TypeWelcome     EnvelopeType = "welcome"      // relay -> agent: accepted, lists proven accounts
	TypeRequest     EnvelopeType = "request"      // relay -> agent: a transaction request
	TypeResult      EnvelopeType = "result"       // agent -> relay: outcome of a request
	TypeWithdraw    EnvelopeType = "withdraw"     // relay -> agents: another device handled request (Envelope.ID)
	TypeControl     EnvelopeType = "control"      // either direction: API-key management (correlated)
	TypeQuery       EnvelopeType = "query"        // relay -> agent: read-only query (correlated by Envelope.ID)
	TypeQueryResult EnvelopeType = "query_result" // agent -> relay: query reply
	TypeError       EnvelopeType = "error"        // either direction: protocol-level error
)

// Envelope is the outer frame for every WebSocket message. Exactly one of the
// typed payload fields is populated, matching Type.
type Envelope struct {
	Version int          `json:"version"`
	Type    EnvelopeType `json:"type"`
	ID      string       `json:"id,omitempty"` // correlation id (request id)

	Hello       *Hello       `json:"hello,omitempty"`
	Challenge   *Challenge   `json:"challenge,omitempty"`
	Auth        *Auth        `json:"auth,omitempty"`
	Welcome     *Welcome     `json:"welcome,omitempty"`
	Request     *TxRequest   `json:"request,omitempty"`
	Result      *TxResult    `json:"result,omitempty"`
	Control     *Control     `json:"control,omitempty"`
	Query       *Query       `json:"query,omitempty"`
	QueryResult *QueryResult `json:"query_result,omitempty"`
	Error       string       `json:"error,omitempty"`
}

// Query is a request the relay forwards to the device on behalf of an
// authenticated API key (connection). The device answers with a QueryResult.
type Query struct {
	Op        string `json:"op"`              // settings | balance | activity | request_status | broadcast_nonce
	ContactID string `json:"contact_id"`      // the connection (API key id)
	Account   string `json:"account"`         // the connection's bound account
	Nonce     string `json:"nonce,omitempty"` // for request_status / broadcast_nonce
}

// QueryResult carries the device's answer. Data is the op-specific JSON payload,
// opaque to the relay, which forwards it to the caller verbatim.
type QueryResult struct {
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Hello announces a device and the accounts it wants to serve. Identity is not a
// shared token: the device proves it controls each account by signing the
// relay's challenge (see Auth).
type Hello struct {
	DeviceID string   `json:"device_id"`          // stable per-install id, for logging only
	Accounts []string `json:"accounts,omitempty"` // nano_ addresses to prove control of
}

// Challenge is a random nonce the agent must sign with each announced account's
// private key.
type Challenge struct {
	Nonce []byte `json:"nonce"`
}

// Auth carries one signature per account over the challenge digest.
type Auth struct {
	Signatures map[string]string `json:"signatures"` // account address -> hex signature
}

// Welcome confirms which accounts were successfully proven and bound.
type Welcome struct {
	Accounts []string `json:"accounts"`
}

// Control is a correlated request/response for API-key registration and policy
// sync over the already-authenticated WebSocket. Keys are minted and labelled on
// the device; the relay only learns a key's hash and the account it acts on, so
// the plaintext never reaches the relay.
type Control struct {
	Op      string `json:"op"`      // register_key | revoke_key | update_origins | put_policy | get_policy | result
	CorrID  string `json:"corr_id"` // correlates a response to its request
	Account string `json:"account,omitempty"`
	KeyID   string `json:"key_id,omitempty"`
	Hash    string `json:"hash,omitempty"` // sha256(plaintext) the relay stores for auth

	// AllowedOrigins is the list of web origins permitted to call this key's
	// endpoints from a browser (CORS). Sent on register_key and update_origins.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`

	// Encrypted policy sync (blob is opaque ciphertext to the relay).
	Version int    `json:"version,omitempty"`
	Blob    []byte `json:"blob,omitempty"`

	Error string `json:"error,omitempty"`
}

// TxKind is the kind of transaction a Contact may request.
type TxKind string

const (
	KindSend TxKind = "send"
)

// TxRequest is a request to move funds, originating from a Contact and routed by
// the relay to the agent. Nonce makes each request idempotent and replay-safe.
type TxRequest struct {
	ID          string `json:"id"`
	ContactID   string `json:"contact_id"`
	ContactName string `json:"contact_name,omitempty"` // default display name (from API-key label)
	Kind        TxKind `json:"kind"`

	// Account is the user's own account (nano_ address) that should sign. It is
	// optional from the caller; the agent falls back to the contact's default.
	Account string `json:"account,omitempty"`

	// Counterparty is the contact's address involved, used for grouping the
	// conversation. For sends it defaults to Destination.
	Counterparty string `json:"counterparty,omitempty"`

	// Send fields.
	Destination string `json:"destination,omitempty"` // nano_ address
	AmountRaw   string `json:"amount_raw,omitempty"`  // decimal raw

	Memo      string `json:"memo,omitempty"`
	Nonce     string `json:"nonce"`
	CreatedAt time.Time `json:"created_at"`

	// ActionOverride lets the caller request sign-only mode on a per-request
	// basis. The device honours it only as a downgrade (sign_only is always
	// accepted; sign_and_broadcast is rejected if the matched rule says sign_only).
	ActionOverride string `json:"action_override,omitempty"`
}

// TxStatus is the terminal (or pending) state of a request.
type TxStatus string

const (
	StatusPending   TxStatus = "pending"   // awaiting user approval in the agent UI
	StatusSigned    TxStatus = "signed"    // signed; not broadcast (sign-only mode)
	StatusBroadcast TxStatus = "broadcast" // signed and published to the network
	StatusRejected  TxStatus = "rejected"  // denied by policy or the user
	StatusFailed    TxStatus = "failed"    // an error occurred while processing
)

// TxResult reports the outcome of a TxRequest back to the relay/Contact.
type TxResult struct {
	RequestID   string       `json:"request_id"`
	Status      TxStatus     `json:"status"`
	BlockHash   string       `json:"block_hash,omitempty"`
	SignedBlock *SignedBlock `json:"signed_block,omitempty"` // present for signed/broadcast
	Reason      string       `json:"reason,omitempty"`       // why rejected/failed
	DecidedAt   time.Time    `json:"decided_at"`
}

// SignedBlock is a fully-formed, signed state block in Nano's json_block format,
// suitable for the caller to broadcast itself when the agent runs in sign-only
// mode.
type SignedBlock struct {
	Type           string `json:"type"` // always "state"
	Account        string `json:"account"`
	Previous       string `json:"previous"`
	Representative string `json:"representative"`
	Balance        string `json:"balance"`
	Link           string `json:"link"`
	Signature      string `json:"signature"`
	Work           string `json:"work"`
	Subtype        string `json:"subtype"`
}
