package main

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/nankio/nora-relay/internal/protocol"
	"github.com/gorilla/websocket"
)

var errAccountOffline = errors.New("no device is online for this account")

// agentConn is a connected, authenticated desktop agent. It is bound to the set
// of accounts it cryptographically proved control of. All writes go through
// writeJSON because gorilla permits only one concurrent writer.
type agentConn struct {
	deviceID string
	accounts []string // proven accounts (nano_ addresses)
	ws       *websocket.Conn
	writeMu  sync.Mutex

	// control correlates API-key management responses by CorrID.
	cmu     sync.Mutex
	control map[string]chan *protocol.Control
}

func (a *agentConn) writeJSON(v any) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	_ = a.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return a.ws.WriteJSON(v)
}

// Hub maps each proven account to the SET of devices that control it (the same
// seed can be imported on several devices), and correlates outbound requests
// with the results agents return.
type Hub struct {
	mu       sync.RWMutex
	bindings map[string][]*agentConn // account address -> devices (most-recent last)

	pmu     sync.Mutex
	pending map[string]chan *protocol.TxResult // requestID -> waiter

	qmu          sync.Mutex
	queryPending map[string]chan *protocol.QueryResult // queryID -> waiter
}

func newHub() *Hub {
	return &Hub{
		bindings:     make(map[string][]*agentConn),
		pending:      make(map[string]chan *protocol.TxResult),
		queryPending: make(map[string]chan *protocol.QueryResult),
	}
}

// bind adds a connection to each of its proven accounts' device sets. Multiple
// devices may hold the same account at once; none is displaced.
func (h *Hub) bind(a *agentConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, acc := range a.accounts {
		h.bindings[acc] = append(removeConn(h.bindings[acc], a), a)
	}
	log.Printf("agent bound: device=%s accounts=%d", a.deviceID, len(a.accounts))
}

// unbind removes a connection from every account set it belonged to.
func (h *Hub) unbind(a *agentConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, acc := range a.accounts {
		rest := removeConn(h.bindings[acc], a)
		if len(rest) == 0 {
			delete(h.bindings, acc)
		} else {
			h.bindings[acc] = rest
		}
	}
	log.Printf("agent unbound: device=%s", a.deviceID)
}

func (h *Hub) accountOnline(account string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.bindings[account]) > 0
}

// devicesForAccount returns the account's devices, most-recently-connected first.
func (h *Hub) devicesForAccount(account string) []*agentConn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	list := h.bindings[account]
	out := make([]*agentConn, len(list))
	for i, c := range list {
		out[len(list)-1-i] = c // reverse: most recent first
	}
	return out
}

// sendRequest fans req out to every device controlling account, waits for the
// first result, then withdraws the request from the other devices so a manual
// approval can be actioned from any device while the rest dismiss it.
//
// Fan-out is safe against double-execution: Nano block construction and signing
// are deterministic, so if two devices both auto-approve they produce the
// identical block (the network dedupes it), and the relay returns the first
// result and ignores the rest.
func (h *Hub) sendRequest(ctx context.Context, account string, req *protocol.TxRequest) (*protocol.TxResult, error) {
	devices := h.devicesForAccount(account)
	if len(devices) == 0 {
		return nil, errAccountOffline
	}

	waiter := make(chan *protocol.TxResult, 1)
	h.pmu.Lock()
	h.pending[req.ID] = waiter
	h.pmu.Unlock()
	defer func() {
		h.pmu.Lock()
		delete(h.pending, req.ID)
		h.pmu.Unlock()
		h.withdraw(account, req.ID) // cancel on the devices that didn't answer
	}()

	env := protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeRequest, ID: req.ID, Request: req}
	delivered := 0
	for _, d := range devices {
		if err := d.writeJSON(env); err == nil {
			delivered++
		}
	}
	if delivered == 0 {
		return nil, errAccountOffline
	}

	select {
	case res := <-waiter:
		return res, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// withdraw tells every device controlling account to drop a pending request.
func (h *Hub) withdraw(account, reqID string) {
	env := protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeWithdraw, ID: reqID}
	for _, d := range h.devicesForAccount(account) {
		_ = d.writeJSON(env)
	}
}

// removeConn returns list without c (preserving order).
func removeConn(list []*agentConn, c *agentConn) []*agentConn {
	out := list[:0:0]
	for _, x := range list {
		if x != c {
			out = append(out, x)
		}
	}
	return out
}

func (h *Hub) deliverResult(res *protocol.TxResult) {
	h.pmu.Lock()
	waiter := h.pending[res.RequestID]
	h.pmu.Unlock()
	if waiter != nil {
		select {
		case waiter <- res:
		default:
		}
	}
}

// sendQuery forwards a read-only query to one device controlling the account
// (the most-recently-connected that accepts the write) and waits for its reply.
// Unlike sendRequest there is no fan-out: queries are idempotent reads, so a
// single device answering is enough and avoids duplicate node lookups.
func (h *Hub) sendQuery(ctx context.Context, account string, q *protocol.Query) (*protocol.QueryResult, error) {
	devices := h.devicesForAccount(account)
	if len(devices) == 0 {
		return nil, errAccountOffline
	}

	id := "qry_" + randomSecret(12)
	waiter := make(chan *protocol.QueryResult, 1)
	h.qmu.Lock()
	h.queryPending[id] = waiter
	h.qmu.Unlock()
	defer func() {
		h.qmu.Lock()
		delete(h.queryPending, id)
		h.qmu.Unlock()
	}()

	env := protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeQuery, ID: id, Query: q}
	sent := false
	for _, d := range devices {
		if err := d.writeJSON(env); err == nil {
			sent = true
			break
		}
	}
	if !sent {
		return nil, errAccountOffline
	}

	select {
	case qr := <-waiter:
		return qr, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *Hub) deliverQueryResult(id string, qr *protocol.QueryResult) {
	h.qmu.Lock()
	waiter := h.queryPending[id]
	h.qmu.Unlock()
	if waiter != nil {
		select {
		case waiter <- qr:
		default:
		}
	}
}
