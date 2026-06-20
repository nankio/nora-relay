package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nankio/nora-relay/internal/protocol"
	"github.com/gorilla/websocket"
)

// serveDevice is a mock desktop agent. It broadcasts any request (deduping by
// nonce like the real device), answers read-only queries with op-specific
// payloads, and answers request_status from its per-nonce result cache —
// mirroring the real agent's handleRequest/handleQuery.
func serveDevice(conn *websocket.Conn) {
	go func() {
		results := map[string]*protocol.TxResult{} // nonce -> cached result
		n := 0
		for {
			var env protocol.Envelope
			if conn.ReadJSON(&env) != nil {
				return
			}
			switch env.Type {
			case protocol.TypeRequest:
				res, ok := results[env.Request.Nonce]
				if !ok {
					n++
					res = &protocol.TxResult{RequestID: env.Request.ID, Status: protocol.StatusBroadcast, BlockHash: fmt.Sprintf("BLOCK%04d", n), DecidedAt: time.Now()}
					results[env.Request.Nonce] = res
				}
				out := *res
				out.RequestID = env.Request.ID
				_ = conn.WriteJSON(protocol.Envelope{Type: protocol.TypeResult, ID: env.Request.ID, Result: &out})
			case protocol.TypeQuery:
				qr := &protocol.QueryResult{}
				switch env.Query.Op {
				case "settings":
					qr.Data = json.RawMessage(`{"enabled":true,"auto_approve":false,"allow_send":true,"per_tx_limit_raw":"100","daily_limit_raw":"500","spent_today_raw":"120","daily_remaining_raw":"380"}`)
				case "balance":
					qr.Data = json.RawMessage(`{"account":"` + env.Query.Account + `","balance_raw":"1000000000000000000000000000000","balance_xno":"1","receivable_raw":"0","receivable_xno":"0","receivable_count":0}`)
				case "activity":
					qr.Data = json.RawMessage(`[{"type":"receive","amount_raw":"500000000000000000000000000000","amount_xno":"0.5","hash":"ABC","timestamp":1700000000}]`)
				case "request_status":
					if res, ok := results[env.Query.Nonce]; ok {
						b, _ := json.Marshal(res)
						qr.Data = b
					} else {
						qr.Error = "not_found"
					}
				default:
					qr.Data = json.RawMessage(`null`)
				}
				_ = conn.WriteJSON(protocol.Envelope{Type: protocol.TypeQueryResult, ID: env.ID, QueryResult: qr})
			}
		}
	}()
}

func httpDo(t *testing.T, method, url, apiKey, body string) (int, []byte) {
	t.Helper()
	var rdr *bytes.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, url, rdr)
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func TestEndpointSweep(t *testing.T) {
	srv, ts, wsURL := newTestServer(t)
	pk, addr := testAccount(t)
	_, plaintext := registerTestKey(t, srv.store, addr)

	// --- before any device connects: reads should be 503, not 404 ---
	for _, path := range []string{"/v1/settings", "/v1/balance", "/v1/activity"} {
		if code, _ := httpDo(t, "GET", ts.URL+path, plaintext, ""); code != http.StatusServiceUnavailable {
			t.Fatalf("%s offline: want 503, got %d", path, code)
		}
	}

	// --- auth: missing/invalid key is 401 on every endpoint ---
	for _, path := range []string{"/v1/settings", "/v1/balance", "/v1/activity", "/v1/status", "/v1/requests/status?nonce=x"} {
		if code, _ := httpDo(t, "GET", ts.URL+path, "", ""); code != http.StatusUnauthorized {
			t.Fatalf("%s without key: want 401, got %d", path, code)
		}
		if code, _ := httpDo(t, "GET", ts.URL+path, "nora_bogus", ""); code != http.StatusUnauthorized {
			t.Fatalf("%s with bad key: want 401, got %d", path, code)
		}
	}

	// --- method guards ---
	if code, _ := httpDo(t, "POST", ts.URL+"/v1/settings", plaintext, ""); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/settings: want 405, got %d", code)
	}

	// --- bring a device online ---
	conn := connectMockAgent(t, wsURL, pk, addr)
	defer conn.Close()
	serveDevice(conn)
	time.Sleep(80 * time.Millisecond)

	// GET /v1/status
	code, body := httpDo(t, "GET", ts.URL+"/v1/status", plaintext, "")
	if code != http.StatusOK {
		t.Fatalf("status: %d %s", code, body)
	}
	t.Logf("GET /v1/status -> %s", body)

	// GET /v1/settings (device-backed) — verify daily_remaining is forwarded
	code, body = httpDo(t, "GET", ts.URL+"/v1/settings", plaintext, "")
	if code != http.StatusOK {
		t.Fatalf("settings: %d %s", code, body)
	}
	var settings map[string]any
	must(t, json.Unmarshal(body, &settings))
	if settings["daily_remaining_raw"] != "380" {
		t.Fatalf("settings.daily_remaining_raw: want 380, got %v", settings["daily_remaining_raw"])
	}
	t.Logf("GET /v1/settings -> %s", body)

	// GET /v1/balance
	code, body = httpDo(t, "GET", ts.URL+"/v1/balance", plaintext, "")
	if code != http.StatusOK {
		t.Fatalf("balance: %d %s", code, body)
	}
	t.Logf("GET /v1/balance -> %s", body)

	// GET /v1/activity
	code, body = httpDo(t, "GET", ts.URL+"/v1/activity", plaintext, "")
	if code != http.StatusOK {
		t.Fatalf("activity: %d %s", code, body)
	}
	t.Logf("GET /v1/activity -> %s", body)

	// POST /v1/requests (send) then poll its status by nonce
	send := `{"kind":"send","destination":"nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7","amount":"0.000001","nonce":"sweep-1","memo":"Order #4821"}`
	code, body = httpDo(t, "POST", ts.URL+"/v1/requests", plaintext, send)
	if code != http.StatusOK {
		t.Fatalf("create request: %d %s", code, body)
	}
	t.Logf("POST /v1/requests -> %s", body)

	// GET /v1/requests/status?nonce=sweep-1 -> the cached result
	code, body = httpDo(t, "GET", ts.URL+"/v1/requests/status?nonce=sweep-1", plaintext, "")
	if code != http.StatusOK {
		t.Fatalf("request status: %d %s", code, body)
	}
	t.Logf("GET /v1/requests/status?nonce=sweep-1 -> %s", body)

	// Unknown nonce -> 404; missing nonce -> 400
	if c, _ := httpDo(t, "GET", ts.URL+"/v1/requests/status?nonce=nope", plaintext, ""); c != http.StatusNotFound {
		t.Fatalf("unknown nonce: want 404, got %d", c)
	}
	if c, _ := httpDo(t, "GET", ts.URL+"/v1/requests/status", plaintext, ""); c != http.StatusBadRequest {
		t.Fatalf("missing nonce: want 400, got %d", c)
	}
}
