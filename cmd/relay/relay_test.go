package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nankio/nora-relay/internal/nano"
	"github.com/nankio/nora-relay/internal/protocol"
	"github.com/gorilla/websocket"
)

// testAccount returns a deterministic private key + address for the mock agent.
func testAccount(t *testing.T) (nano.PrivateKey, string) {
	t.Helper()
	seed, err := nano.ParseSeed("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	pk := seed.DeriveKey(0)
	return pk, pk.Public().Address()
}

func newTestServer(t *testing.T) (*server, *httptest.Server, string) {
	t.Helper()
	srv := newServer(&Config{RequestTimeoutSeconds: 5}, newMemStore())
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/agent"
	return srv, ts, wsURL
}

// connectMockAgent completes the challenge/signature enrollment for one account.
func connectMockAgent(t *testing.T, wsURL string, pk nano.PrivateKey, addr string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	must(t, conn.WriteJSON(protocol.Envelope{Type: protocol.TypeHello, Hello: &protocol.Hello{DeviceID: "d1", Accounts: []string{addr}}}))

	var ch protocol.Envelope
	must(t, conn.ReadJSON(&ch))
	if ch.Type != protocol.TypeChallenge || ch.Challenge == nil {
		t.Fatalf("expected challenge, got %q", ch.Type)
	}
	sig := nano.SignChallenge(pk, ch.Challenge.Nonce)
	must(t, conn.WriteJSON(protocol.Envelope{Type: protocol.TypeAuth, Auth: &protocol.Auth{Signatures: map[string]string{addr: hex.EncodeToString(sig[:])}}}))

	var wel protocol.Envelope
	must(t, conn.ReadJSON(&wel))
	if wel.Type != protocol.TypeWelcome {
		t.Fatalf("expected welcome, got %q (%s)", wel.Type, wel.Error)
	}
	return conn
}

// serveBroadcast auto-answers any incoming request with a broadcast result,
// deduping by nonce like the real device: a repeated nonce returns the same
// on-chain block (assigned once) rather than executing again.
func serveBroadcast(conn *websocket.Conn) {
	go func() {
		seen := map[string]string{} // nonce -> block hash
		n := 0
		for {
			var env protocol.Envelope
			if conn.ReadJSON(&env) != nil {
				return
			}
			if env.Type == protocol.TypeRequest {
				hash, ok := seen[env.Request.Nonce]
				if !ok {
					n++
					hash = fmt.Sprintf("BLOCK%04d", n)
					seen[env.Request.Nonce] = hash
				}
				_ = conn.WriteJSON(protocol.Envelope{Type: protocol.TypeResult, ID: env.Request.ID, Result: &protocol.TxResult{
					RequestID: env.Request.ID, Status: protocol.StatusBroadcast, BlockHash: hash, DecidedAt: time.Now(),
				}})
			}
		}
	}()
}

func TestEnrollAndRouteByAccount(t *testing.T) {
	srv, ts, wsURL := newTestServer(t)
	pk, addr := testAccount(t)

	// Mint a key bound to the account (as the app would).
	_, plaintext := registerTestKey(t, srv.store, addr)

	conn := connectMockAgent(t, wsURL, pk, addr)
	defer conn.Close()
	serveBroadcast(conn)
	time.Sleep(80 * time.Millisecond)

	body := `{"kind":"send","destination":"nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7","amount":"0.01","nonce":"n1"}`
	res := postReq(t, ts.URL, plaintext, body)
	if res.Status != protocol.StatusBroadcast {
		t.Fatalf("status=%q want broadcast", res.Status)
	}

	// Idempotency now lives on the device: a retry with the same nonce returns
	// the same on-chain block (it was not re-executed).
	res2 := postReq(t, ts.URL, plaintext, body)
	if res2.BlockHash != res.BlockHash {
		t.Errorf("idempotency failed: %s vs %s", res2.BlockHash, res.BlockHash)
	}
}

func TestMultiDeviceSameAccount(t *testing.T) {
	srv, ts, wsURL := newTestServer(t)
	pk, addr := testAccount(t)
	_, plaintext := registerTestKey(t, srv.store, addr)

	// Same wallet imported on two devices — neither displaces the other.
	a := connectMockAgent(t, wsURL, pk, addr)
	defer a.Close()
	b := connectMockAgent(t, wsURL, pk, addr)
	defer b.Close()
	serveBroadcast(a)
	serveBroadcast(b)
	time.Sleep(80 * time.Millisecond)

	send := `{"kind":"send","destination":"nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7","amount":"0.01","nonce":"%s"}`
	if res := postReq(t, ts.URL, plaintext, fmt.Sprintf(send, "d1")); res.Status != protocol.StatusBroadcast {
		t.Fatalf("with two devices: status=%q", res.Status)
	}

	// Failover: drop the most-recent device; the other still serves.
	b.Close()
	time.Sleep(120 * time.Millisecond)
	if res := postReq(t, ts.URL, plaintext, fmt.Sprintf(send, "d2")); res.Status != protocol.StatusBroadcast {
		t.Fatalf("after failover: status=%q", res.Status)
	}
}

func TestFanoutAndWithdraw(t *testing.T) {
	srv, ts, wsURL := newTestServer(t)
	pk, addr := testAccount(t)
	_, plaintext := registerTestKey(t, srv.store, addr)

	// Device A stays silent (as if awaiting manual approval); device B answers.
	a := connectMockAgent(t, wsURL, pk, addr)
	defer a.Close()
	b := connectMockAgent(t, wsURL, pk, addr)
	defer b.Close()
	serveBroadcast(b)

	gotReq := make(chan string, 4)
	gotWithdraw := make(chan string, 4)
	go func() {
		for {
			var e protocol.Envelope
			if a.ReadJSON(&e) != nil {
				return
			}
			switch e.Type {
			case protocol.TypeRequest:
				gotReq <- e.Request.ID
			case protocol.TypeWithdraw:
				gotWithdraw <- e.ID
			}
		}
	}()
	time.Sleep(80 * time.Millisecond)

	res := postReq(t, ts.URL, plaintext, `{"kind":"send","destination":"nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7","amount":"0.01","nonce":"f1"}`)
	if res.Status != protocol.StatusBroadcast {
		t.Fatalf("status=%q", res.Status)
	}

	// The silent device must have seen the request, then a withdraw for it.
	reqID := recvStr(t, gotReq, "request on device A")
	wID := recvStr(t, gotWithdraw, "withdraw on device A")
	if reqID != wID {
		t.Errorf("withdraw id %q != request id %q", wID, reqID)
	}
}

func recvStr(t *testing.T, ch chan string, what string) string {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return ""
	}
}

func TestRegisterKeyViaControlThenUse(t *testing.T) {
	_, ts, wsURL := newTestServer(t)
	pk, addr := testAccount(t)
	conn := connectMockAgent(t, wsURL, pk, addr)
	defer conn.Close()

	// The device mints the key locally and registers only its hash + account.
	plaintext := "nora_" + hex.EncodeToString(randomBytes(16))
	keyID := "ak_" + hex.EncodeToString(randomBytes(6))
	must(t, conn.WriteJSON(protocol.Envelope{Type: protocol.TypeControl, Control: &protocol.Control{
		Op: "register_key", CorrID: "c1", Account: addr, KeyID: keyID, Hash: hashSecret(plaintext),
	}}))
	var reply protocol.Envelope
	must(t, conn.ReadJSON(&reply))
	if reply.Control == nil || reply.Control.Error != "" {
		t.Fatalf("register_key failed: %+v", reply.Control)
	}

	serveBroadcast(conn)
	time.Sleep(80 * time.Millisecond)

	res := postReq(t, ts.URL, plaintext, `{"kind":"send","destination":"nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7","amount":"0.01","nonce":"m1"}`)
	if res.Status != protocol.StatusBroadcast {
		t.Fatalf("status=%q want broadcast", res.Status)
	}
}

func TestBadSignatureRejected(t *testing.T) {
	_, _, wsURL := newTestServer(t)
	_, addr := testAccount(t)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	must(t, err)
	defer conn.Close()
	must(t, conn.WriteJSON(protocol.Envelope{Type: protocol.TypeHello, Hello: &protocol.Hello{DeviceID: "d1", Accounts: []string{addr}}}))

	var ch protocol.Envelope
	must(t, conn.ReadJSON(&ch))
	// Sign with the WRONG key (a different account).
	wrong, _ := nano.ParseSeed("1111111111111111111111111111111111111111111111111111111111111111")
	bad := nano.SignChallenge(wrong.DeriveKey(0), ch.Challenge.Nonce)
	must(t, conn.WriteJSON(protocol.Envelope{Type: protocol.TypeAuth, Auth: &protocol.Auth{Signatures: map[string]string{addr: hex.EncodeToString(bad[:])}}}))

	var resp protocol.Envelope
	must(t, conn.ReadJSON(&resp))
	if resp.Type != protocol.TypeError {
		t.Fatalf("expected error for bad signature, got %q", resp.Type)
	}
}

func TestPolicyBlobSync(t *testing.T) {
	_, _, wsURL := newTestServer(t)
	pk, addr := testAccount(t)
	conn := connectMockAgent(t, wsURL, pk, addr)
	defer conn.Close()

	put := func(version int, blob string) {
		must(t, conn.WriteJSON(protocol.Envelope{Type: protocol.TypeControl, Control: &protocol.Control{Op: "put_policy", CorrID: "p", Account: addr, Version: version, Blob: []byte(blob)}}))
		var r protocol.Envelope
		must(t, conn.ReadJSON(&r))
		if r.Control.Error != "" {
			t.Fatalf("put_policy error: %s", r.Control.Error)
		}
	}
	get := func() (int, string) {
		must(t, conn.WriteJSON(protocol.Envelope{Type: protocol.TypeControl, Control: &protocol.Control{Op: "get_policy", CorrID: "g", Account: addr}}))
		var r protocol.Envelope
		must(t, conn.ReadJSON(&r))
		return r.Control.Version, string(r.Control.Blob)
	}

	put(1, "v1-ciphertext")
	if v, b := get(); v != 1 || b != "v1-ciphertext" {
		t.Fatalf("after v1: %d %q", v, b)
	}
	put(2, "v2-ciphertext")
	if v, _ := get(); v != 2 {
		t.Fatalf("after v2: got version %d", v)
	}
	put(1, "stale") // older version must be ignored
	if v, b := get(); v != 2 || b != "v2-ciphertext" {
		t.Fatalf("stale overwrote newer: %d %q", v, b)
	}
}

func TestUnknownAPIKeyRejected(t *testing.T) {
	_, ts, _ := newTestServer(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/requests", strings.NewReader(`{"kind":"send"}`))
	req.Header.Set("Authorization", "Bearer nope")
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
}

func postReq(t *testing.T, base, apiKey, body string) protocol.TxResult {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/requests", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	var res protocol.TxResult
	must(t, json.NewDecoder(resp.Body).Decode(&res))
	return res
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// registerTestKey mints a key the way the device does — generating the plaintext
// locally and registering only its hash + account with the relay — and returns
// the key id and plaintext.
func registerTestKey(t *testing.T, st Store, account string) (keyID, plaintext string) {
	t.Helper()
	plaintext = "nora_" + hex.EncodeToString(randomBytes(16))
	keyID = "ak_" + hex.EncodeToString(randomBytes(6))
	must(t, st.RegisterAPIKey(context.Background(), keyID, account, hashSecret(plaintext)))
	return keyID, plaintext
}

func getReq(t *testing.T, url, apiKey string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer resp.Body.Close()
	b := new(bytes.Buffer)
	_, _ = b.ReadFrom(resp.Body)
	return resp.StatusCode, b.Bytes()
}

func TestDeviceQueryForwardedAndAnswered(t *testing.T) {
	srv, ts, wsURL := newTestServer(t)
	pk, addr := testAccount(t)
	keyID, plaintext := registerTestKey(t, srv.store, addr)

	// Offline: no device bound yet → 503.
	if code, _ := getReq(t, ts.URL+"/v1/settings", plaintext); code != http.StatusServiceUnavailable {
		t.Fatalf("offline want 503, got %d", code)
	}

	conn := connectMockAgent(t, wsURL, pk, addr)
	defer conn.Close()

	// Mock device echoes the query it received and returns a canned payload.
	gotQuery := make(chan protocol.Query, 1)
	go func() {
		for {
			var env protocol.Envelope
			if conn.ReadJSON(&env) != nil {
				return
			}
			if env.Type == protocol.TypeQuery && env.Query != nil {
				gotQuery <- *env.Query
				_ = conn.WriteJSON(protocol.Envelope{
					Type: protocol.TypeQueryResult, ID: env.ID,
					QueryResult: &protocol.QueryResult{Data: json.RawMessage(`{"enabled":true,"daily_remaining_raw":"42"}`)},
				})
			}
		}
	}()
	time.Sleep(80 * time.Millisecond)

	code, body := getReq(t, ts.URL+"/v1/settings", plaintext)
	if code != http.StatusOK {
		t.Fatalf("settings want 200, got %d (%s)", code, body)
	}

	// The query must be scoped to this connection's key + account.
	q := recvQuery(t, gotQuery)
	if q.Op != "settings" || q.ContactID != keyID || q.Account != addr {
		t.Fatalf("query mis-scoped: %+v (key=%s addr=%s)", q, keyID, addr)
	}

	// The device's payload is forwarded verbatim.
	var got map[string]any
	must(t, json.Unmarshal(body, &got))
	if got["daily_remaining_raw"] != "42" || got["enabled"] != true {
		t.Fatalf("payload not forwarded verbatim: %s", body)
	}
}

func recvQuery(t *testing.T, ch chan protocol.Query) protocol.Query {
	t.Helper()
	select {
	case q := <-ch:
		return q
	case <-time.After(2 * time.Second):
		t.Fatal("device never received the query")
		return protocol.Query{}
	}
}
