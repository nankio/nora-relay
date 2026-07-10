package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/nankio/nora-relay/internal/nano"
	"github.com/nankio/nora-relay/internal/protocol"
	"github.com/gorilla/websocket"
)

// maxRequestBodyBytes caps inbound JSON on the request-creation endpoint.
const maxRequestBodyBytes = 1 << 16 // 64 KiB

type server struct {
	cfg   *Config
	hub   *Hub
	store Store
	up    websocket.Upgrader
	rl    *rateLimiter
}

func newServer(cfg *Config, store Store) *server {
	s := &server{
		cfg:   cfg,
		hub:   newHub(),
		store: store,
		// 5 requests/sec sustained, burst of 20, stale entries pruned after 1 hour.
		rl: newRateLimiter(5, 20, time.Hour),
		up: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			// Origin checking is intentionally disabled: the only clients that
			// connect to /agent are the desktop agent (not a browser) and
			// server-side callers using API keys on /v1/*. A browser
			// connecting here would be a misconfiguration, not an attack vector.
			CheckOrigin: func(*http.Request) bool { return true },
		},
	}
	// Prune idle rate-limiter entries every 30 minutes so the map stays bounded.
	go func() {
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		for range t.C {
			s.rl.prune()
		}
	}()
	return s
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/agent", s.handleAgent)
	mux.HandleFunc("/v1/requests", s.handleCreateRequest)
	mux.HandleFunc("/v1/requests/status", s.handleRequestStatus)
	mux.HandleFunc("/v1/broadcast", s.handleBroadcast)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/settings", s.handleSettings)
	mux.HandleFunc("/v1/balance", s.handleBalance)
	mux.HandleFunc("/v1/activity", s.handleActivity)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return s.corsMiddleware(mux)
}

// corsMiddleware handles browser CORS preflights and adds Access-Control-Allow-Origin
// headers to /v1/* responses. OPTIONS requests are answered from the origin allowlist
// without requiring authentication (since credentials aren't available during preflight).
func (s *server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || !strings.HasPrefix(r.URL.Path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		allowed, err := s.store.OriginAllowed(ctx, origin)
		if err != nil {
			log.Printf("corsMiddleware: OriginAllowed: %v", err)
		}

		if r.Method == http.MethodOptions {
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}
		next.ServeHTTP(w, r)
	})
}

// handleAgent runs the challenge/response enrollment, then serves the connection.
func (s *server) handleAgent(w http.ResponseWriter, r *http.Request) {
	ws, err := s.up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	a, err := s.enroll(ws)
	if err != nil {
		writeWSError(ws, err.Error())
		_ = ws.Close()
		return
	}

	s.hub.bind(a)
	defer func() {
		s.hub.unbind(a)
		_ = ws.Close()
	}()
	_ = a.writeJSON(protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeWelcome, Welcome: &protocol.Welcome{Accounts: a.accounts}})

	s.agentReadLoop(a)
}

// enroll performs: Hello -> Challenge -> Auth -> verify signatures.
func (s *server) enroll(ws *websocket.Conn) (*agentConn, error) {
	_ = ws.SetReadDeadline(time.Now().Add(15 * time.Second))

	var hello protocol.Envelope
	if err := ws.ReadJSON(&hello); err != nil || hello.Type != protocol.TypeHello || hello.Hello == nil {
		return nil, errString("expected hello")
	}
	if len(hello.Hello.Accounts) == 0 {
		return nil, errString("hello announced no accounts")
	}

	nonce := randomBytes(32)
	if err := ws.WriteJSON(protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeChallenge, Challenge: &protocol.Challenge{Nonce: nonce}}); err != nil {
		return nil, err
	}

	var auth protocol.Envelope
	if err := ws.ReadJSON(&auth); err != nil || auth.Type != protocol.TypeAuth || auth.Auth == nil {
		return nil, errString("expected auth")
	}

	// Verify each announced account proved control by signing the nonce.
	var proven []string
	for _, addr := range hello.Hello.Accounts {
		sigHex, ok := auth.Auth.Signatures[addr]
		if !ok {
			continue
		}
		if verifyAccountSig(addr, nonce, sigHex) {
			proven = append(proven, addr)
		}
	}
	if len(proven) == 0 {
		return nil, errString("no account proved control")
	}

	return &agentConn{
		deviceID: hello.Hello.DeviceID,
		accounts: proven,
		ws:       ws,
		control:  map[string]chan *protocol.Control{},
	}, nil
}

func verifyAccountSig(addr string, nonce []byte, sigHex string) bool {
	pub, err := nano.ParseAddress(addr)
	if err != nil {
		return false
	}
	raw, err := hex.DecodeString(sigHex)
	if err != nil || len(raw) != 64 {
		return false
	}
	var sig nano.Signature
	copy(sig[:], raw)
	return nano.VerifyChallenge(pub, nonce, sig)
}

func (s *server) agentReadLoop(a *agentConn) {
	a.ws.SetReadLimit(1 << 20)
	_ = a.ws.SetReadDeadline(time.Now().Add(60 * time.Second))
	a.ws.SetPongHandler(func(string) error { return a.ws.SetReadDeadline(time.Now().Add(60 * time.Second)) })

	stop := make(chan struct{})
	defer close(stop)
	go s.pinger(a, stop)

	for {
		var env protocol.Envelope
		if err := a.ws.ReadJSON(&env); err != nil {
			return
		}
		_ = a.ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		switch env.Type {
		case protocol.TypeResult:
			if env.Result != nil {
				s.hub.deliverResult(env.Result)
			}
		case protocol.TypeControl:
			if env.Control != nil {
				s.handleControl(a, env.Control)
			}
		case protocol.TypeQueryResult:
			if env.QueryResult != nil {
				s.hub.deliverQueryResult(env.ID, env.QueryResult)
			}
		}
	}
}

func (s *server) pinger(a *agentConn, stop <-chan struct{}) {
	t := time.NewTicker(25 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			a.writeMu.Lock()
			_ = a.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := a.ws.WriteMessage(websocket.PingMessage, nil)
			a.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

// handleControl serves API-key management requested by an authenticated agent.
func (s *server) handleControl(a *agentConn, c *protocol.Control) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reply := &protocol.Control{Op: "result", CorrID: c.CorrID}

	switch c.Op {
	case "register_key":
		// The device minted the key and owns its label; the relay records only the
		// hash and the account so it can authenticate inbound requests.
		if !contains(a.accounts, c.Account) {
			reply.Error = "you do not control that account on this device"
			break
		}
		if c.KeyID == "" || c.Hash == "" {
			reply.Error = "register_key requires key_id and hash"
			break
		}
		if err := s.store.RegisterAPIKey(ctx, c.KeyID, c.Account, c.Hash); err != nil {
			reply.Error = err.Error()
			break
		}
		if len(c.AllowedOrigins) > 0 {
			_ = s.store.UpdateKeyOrigins(ctx, c.KeyID, c.Account, c.AllowedOrigins)
		}
		reply.KeyID = c.KeyID
		reply.Account = c.Account

	case "rebind_key":
		// Move a connection to another of the user's accounts. The key's secret,
		// id and origins survive, so a caller holding the token keeps working:
		// the bound account is routing information, not a credential.
		//
		// The old owner is not supplied — it is discovered among the accounts
		// this device has proven, and that search *is* the authorisation check.
		// A device may only rebind a key that already belongs to one of its own
		// accounts, and only onto another account it controls.
		if !contains(a.accounts, c.Account) {
			reply.Error = "you do not control that account on this device"
			break
		}
		if c.KeyID == "" {
			reply.Error = "rebind_key requires key_id"
			break
		}
		rebound := false
		for _, acc := range a.accounts {
			// Rebinding onto the account it already has is a no-op that
			// succeeds: the device re-asserts its policy on every save.
			if e := s.store.RebindAPIKey(ctx, c.KeyID, acc, c.Account); e == nil {
				rebound = true
				break
			}
		}
		if !rebound {
			reply.Error = "key not found"
			break
		}
		reply.KeyID = c.KeyID
		reply.Account = c.Account

	case "revoke_key":
		var err error = ErrNotFound
		for _, acc := range a.accounts {
			if e := s.store.RevokeAPIKey(ctx, acc, c.KeyID); e == nil {
				err = nil
				break
			}
		}
		if err != nil {
			reply.Error = "key not found"
		}

	case "update_origins":
		if !contains(a.accounts, c.Account) {
			reply.Error = "you do not control that account on this device"
			break
		}
		if c.KeyID == "" {
			reply.Error = "update_origins requires key_id"
			break
		}
		if err := s.store.UpdateKeyOrigins(ctx, c.KeyID, c.Account, c.AllowedOrigins); err != nil {
			reply.Error = err.Error()
			break
		}
		reply.KeyID = c.KeyID

	case "put_policy":
		if !contains(a.accounts, c.Account) {
			reply.Error = "you do not control that account on this device"
			break
		}
		if err := s.store.PutPolicy(ctx, c.Account, c.Version, c.Blob); err != nil {
			reply.Error = err.Error()
		}

	case "get_policy":
		if !contains(a.accounts, c.Account) {
			reply.Error = "you do not control that account on this device"
			break
		}
		version, blob, found, err := s.store.GetPolicy(ctx, c.Account)
		if err != nil {
			reply.Error = err.Error()
			break
		}
		if found {
			reply.Version = version
			reply.Blob = blob
		}
		reply.Account = c.Account

	default:
		reply.Error = "unknown control op"
	}

	_ = a.writeJSON(protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeControl, Control: reply})
}

// --- external caller API ---

type createRequestBody struct {
	Kind         string `json:"kind"`
	Destination  string `json:"destination,omitempty"`
	AmountRaw    string `json:"amount_raw,omitempty"`
	Amount       string `json:"amount,omitempty"`
	Counterparty string `json:"counterparty,omitempty"`
	Memo         string `json:"memo,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	// Action optionally overrides the rule action: "sign_only" requests that the
	// device signs but does not broadcast (x402 mode). "sign_and_broadcast" is
	// silently ignored if the matched rule says sign_only.
	Action string `json:"action,omitempty"`
}

func (s *server) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	key, ok := s.authKey(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	if !s.rl.allow(key.ID) {
		w.Header().Set("Retry-After", "1")
		writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	var body createRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req, err := buildTxRequest(key, body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !s.hub.accountOnline(key.OwnerAccount) {
		writeJSONError(w, http.StatusServiceUnavailable, "the account's device is offline")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.RequestTimeoutSeconds)*time.Second)
	defer cancel()

	// Idempotency lives on the device now: a retry with the same nonce is
	// recognized there and the original outcome is returned without re-signing,
	// so the relay forwards every request and stores no transaction results.
	res, err := s.hub.sendRequest(ctx, key.OwnerAccount, req)
	if err != nil {
		if err == errAccountOffline {
			writeJSONError(w, http.StatusServiceUnavailable, "the account's device is offline")
			return
		}
		writeJSONError(w, http.StatusGatewayTimeout, "timed out waiting for the device")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleBroadcast submits a previously signed (but not yet broadcast) block to
// the Nano network. It is the second phase of the x402 sign-then-broadcast flow:
// the caller obtained a signed_block via a sign_only request and now instructs
// the device to publish it. The device verifies the block is still in its cache
// (idempotency guard) before broadcasting.
//
// POST /v1/broadcast   body: { "nonce": "<original request nonce>" }
// Response: same TxResult shape as POST /v1/requests.
func (s *server) handleBroadcast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	key, ok := s.authKey(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	if !s.rl.allow(key.ID) {
		w.Header().Set("Retry-After", "1")
		writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	var body struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Nonce == "" {
		writeJSONError(w, http.StatusBadRequest, `"nonce" is required`)
		return
	}

	if !s.hub.accountOnline(key.OwnerAccount) {
		writeJSONError(w, http.StatusServiceUnavailable, "the account's device is offline")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.RequestTimeoutSeconds)*time.Second)
	defer cancel()

	qr, err := s.hub.sendQuery(ctx, key.OwnerAccount, &protocol.Query{
		Op:        "broadcast_nonce",
		ContactID: key.ID,
		Account:   key.OwnerAccount,
		Nonce:     body.Nonce,
	})
	if err != nil {
		if err == errAccountOffline {
			writeJSONError(w, http.StatusServiceUnavailable, "the account's device is offline")
			return
		}
		writeJSONError(w, http.StatusGatewayTimeout, "timed out waiting for the device")
		return
	}
	if qr.Error == "not_found" {
		writeJSONError(w, http.StatusNotFound, "no signed block found for that nonce — it may have already been broadcast, rejected, or never signed")
		return
	}
	if qr.Error != "" {
		writeJSONError(w, http.StatusBadGateway, qr.Error)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(qr.Data)
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	key, ok := s.authKey(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"contact_id":    key.ID,
		"account":       key.OwnerAccount,
		"device_online": s.hub.accountOnline(key.OwnerAccount),
	})
}

// handleSettings / handleBalance / handleActivity are read-only views answered
// by the device, since the connection's policy is end-to-end encrypted and the
// relay cannot read it.
func (s *server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.deviceQuery(w, r, "settings")
}

func (s *server) handleBalance(w http.ResponseWriter, r *http.Request) {
	s.deviceQuery(w, r, "balance")
}

func (s *server) handleActivity(w http.ResponseWriter, r *http.Request) {
	s.deviceQuery(w, r, "activity")
}

// deviceQuery authenticates the key, forwards a read-only query to the device,
// and streams back the device's JSON payload verbatim.
func (s *server) deviceQuery(w http.ResponseWriter, r *http.Request, op string) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	key, ok := s.authKey(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	if !s.hub.accountOnline(key.OwnerAccount) {
		writeJSONError(w, http.StatusServiceUnavailable, "the account's device is offline")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.RequestTimeoutSeconds)*time.Second)
	defer cancel()

	qr, err := s.hub.sendQuery(ctx, key.OwnerAccount, &protocol.Query{Op: op, ContactID: key.ID, Account: key.OwnerAccount})
	if err != nil {
		if err == errAccountOffline {
			writeJSONError(w, http.StatusServiceUnavailable, "the account's device is offline")
			return
		}
		writeJSONError(w, http.StatusGatewayTimeout, "timed out waiting for the device")
		return
	}
	if qr.Error != "" {
		writeJSONError(w, http.StatusBadGateway, qr.Error)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(qr.Data)
}

// handleRequestStatus returns a previously completed request's result by nonce.
// Idempotency now lives on the device, so this is a device-backed query. Only
// broadcast/signed results are cached, so a pending, rejected, or never-submitted
// nonce returns 404 — resubmit the same nonce to (idempotently) learn the current
// outcome.
func (s *server) handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	key, ok := s.authKey(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	nonce := strings.TrimSpace(r.URL.Query().Get("nonce"))
	if nonce == "" {
		writeJSONError(w, http.StatusBadRequest, "nonce query parameter is required")
		return
	}
	if !s.hub.accountOnline(key.OwnerAccount) {
		writeJSONError(w, http.StatusServiceUnavailable, "the account's device is offline")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.RequestTimeoutSeconds)*time.Second)
	defer cancel()

	qr, err := s.hub.sendQuery(ctx, key.OwnerAccount, &protocol.Query{Op: "request_status", ContactID: key.ID, Account: key.OwnerAccount, Nonce: nonce})
	if err != nil {
		if err == errAccountOffline {
			writeJSONError(w, http.StatusServiceUnavailable, "the account's device is offline")
			return
		}
		writeJSONError(w, http.StatusGatewayTimeout, "timed out waiting for the device")
		return
	}
	if qr.Error == "not_found" {
		writeJSONError(w, http.StatusNotFound, "no completed request with that nonce (it may be pending, rejected, or never submitted)")
		return
	}
	if qr.Error != "" {
		writeJSONError(w, http.StatusBadGateway, qr.Error)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(qr.Data)
}

func (s *server) authKey(r *http.Request) (APIKey, bool) {
	auth := r.Header.Get("Authorization")
	plaintext := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if plaintext == "" || plaintext == auth {
		return APIKey{}, false
	}
	key, err := s.store.ResolveAPIKey(r.Context(), plaintext)
	if err != nil {
		return APIKey{}, false
	}
	return key, true
}

// buildTxRequest binds the request to the key's owner account; callers cannot
// target arbitrary accounts.
func buildTxRequest(key APIKey, body createRequestBody) (*protocol.TxRequest, error) {
	req := &protocol.TxRequest{
		ID:        "req_" + randomSecret(12),
		ContactID: key.ID,
		// ContactName is left empty: the device owns the key's label and resolves
		// the display name from its local contact for this ContactID.
		Account:      key.OwnerAccount,
		Counterparty: body.Counterparty,
		Memo:         body.Memo,
		Nonce:        body.Nonce,
		CreatedAt:    time.Now().UTC(),
	}
	if req.Nonce == "" {
		req.Nonce = req.ID
	}

	if protocol.TxKind(body.Kind) != protocol.KindSend {
		return nil, errString(`kind must be "send"`)
	}
	req.Kind = protocol.KindSend
	if _, err := nano.ParseAddress(body.Destination); err != nil {
		return nil, errString("destination is not a valid nano_ address")
	}
	req.Destination = body.Destination
	amount, err := resolveAmount(body)
	if err != nil {
		return nil, err
	}
	req.AmountRaw = amount

	if body.Action == "sign_only" {
		req.ActionOverride = "sign_only"
	}
	return req, nil
}

func resolveAmount(body createRequestBody) (string, error) {
	if body.AmountRaw != "" {
		return body.AmountRaw, nil
	}
	if body.Amount != "" {
		raw, err := nano.ParseNanoAmount(body.Amount)
		if err != nil {
			return "", errString("invalid amount")
		}
		return raw.String(), nil
	}
	return "", errString("amount_raw or amount is required")
}

// --- helpers ---

type strErr string

func (e strErr) Error() string { return string(e) }
func errString(s string) error { return strErr(s) }

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("relay: out of randomness")
	}
	return b
}

func writeWSError(ws *websocket.Conn, msg string) {
	_ = ws.WriteJSON(protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeError, Error: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
