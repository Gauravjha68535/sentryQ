package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"SentryQ/utils"

	"github.com/gorilla/websocket"
)

// WSMessage is a structured message sent over WebSocket
type WSMessage struct {
	Type    string `json:"type"` // "log", "progress", "findings_update", "complete", "error"
	Message string `json:"message,omitempty"`
	Level   string `json:"level,omitempty"`   // "info", "success", "warning", "error", "phase"
	Percent int    `json:"percent,omitempty"` // 0-100
	Phase   string `json:"phase,omitempty"`
	Count   int    `json:"count,omitempty"`
}

// WSClient wraps a websocket connection with separate mutexes for thread-safe
// reads and writes. gorilla/websocket allows one concurrent reader + one
// concurrent writer, but not two of the same kind. Keeping write and close
// under writeMu, and reads under readMu, prevents any concurrent access of
// the same kind from racing.
type WSClient struct {
	conn    *websocket.Conn
	writeMu sync.Mutex // guards WriteMessage and Close
	readMu  sync.Mutex // guards ReadMessage (only one goroutine reads, but mutex keeps SetReadDeadline safe)
	closed  bool       // guarded by writeMu; makes Close() idempotent
}

// wsWriteTimeout is the maximum time allowed for a single WebSocket write.
// A slow or stalled client must not block broadcast delivery to all other clients.
const wsWriteTimeout = 5 * time.Second

// WriteMessage is a thread-safe wrapper for writing text messages.
// It sets a per-write deadline so a stalled client cannot block the caller indefinitely.
func (c *WSClient) WriteMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout)) //nolint:errcheck
	return c.conn.WriteMessage(messageType, data)
}

// Close gracefully closes the connection. It is idempotent — calling it more
// than once (e.g. from both Broadcast's error path and the read goroutine's
// defer) is safe and returns nil on the second call.
func (c *WSClient) Close() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// ReadMessage reads from the connection under the read mutex so that
// SetReadDeadline (called in the same goroutine) cannot race with a
// concurrent Close from the write side.
func (c *WSClient) ReadMessage() (messageType int, p []byte, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.conn.ReadMessage()
}

// WebSocketHub manages all WebSocket connections grouped by scan ID
type WebSocketHub struct {
	mu      sync.RWMutex
	clients map[string]map[*WSClient]bool // scanID -> set of connections
}

var (
	wsHub    *WebSocketHub
	upgrader = websocket.Upgrader{
		// Only accept WebSocket connections from localhost — same policy as corsMiddleware.
		// We parse the Origin header with url.Parse so that a hostname like
		// "localhostevil.com" or "127.0.0.1.attacker.com" cannot slip through a
		// naive HasPrefix check.
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true // same-origin / direct connection (no Origin header)
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			host := u.Hostname() // strips port; returns bare IP or hostname
			return host == "localhost" || host == "127.0.0.1" || host == "::1"
		},
	}
)

// NewWebSocketHub creates a new hub
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients: make(map[string]map[*WSClient]bool),
	}
}

const maxWSClientsPerScan = 10

// HandleWS upgrades an HTTP connection to WebSocket for a specific scan
func (h *WebSocketHub) HandleWS(w http.ResponseWriter, r *http.Request, scanID string) {
	// Check-and-add under a single write lock to avoid TOCTOU race.
	h.mu.Lock()
	if h.clients[scanID] == nil {
		h.clients[scanID] = make(map[*WSClient]bool)
	}
	if len(h.clients[scanID]) >= maxWSClientsPerScan {
		h.mu.Unlock()
		http.Error(w, "too many connections for this scan", http.StatusTooManyRequests)
		return
	}
	// Reserve the slot before releasing the lock so no other goroutine
	// can slip in between the upgrade and the registration.
	placeholder := &WSClient{}
	h.clients[scanID][placeholder] = true
	h.mu.Unlock()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Remove the reserved placeholder since upgrade failed.
		h.mu.Lock()
		delete(h.clients[scanID], placeholder)
		h.mu.Unlock()
		utils.LogError("WebSocket upgrade failed", err)
		return
	}

	wsClient := &WSClient{conn: conn}

	// Replace placeholder with real client.
	h.mu.Lock()
	delete(h.clients[scanID], placeholder)
	h.clients[scanID][wsClient] = true
	h.mu.Unlock()

	// Send a welcome message
	welcome := WSMessage{Type: "log", Message: "Connected to WebSocket", Level: "info"}
	if data, err := json.Marshal(welcome); err == nil {
		wsClient.WriteMessage(websocket.TextMessage, data) //nolint:errcheck
	}

	// Keep connection alive; read pump (just drain incoming messages)
	go func() {
		defer func() {
			h.mu.Lock()
			delete(h.clients[scanID], wsClient)
			if len(h.clients[scanID]) == 0 {
				delete(h.clients, scanID)
			}
			h.mu.Unlock()
			wsClient.Close()
		}()
		for {
			// Refresh read deadline and read under the same readMu so that
			// SetReadDeadline cannot race with concurrent Close on the write side.
			wsClient.readMu.Lock()
			wsClient.conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
			wsClient.readMu.Unlock()
			_, _, err := wsClient.ReadMessage()
			if err != nil {
				return
			}
		}
	}()
}

// Broadcast sends a message to all clients watching a specific scan
func (h *WebSocketHub) Broadcast(scanID string, msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.mu.RLock()
	conns, ok := h.clients[scanID]
	if !ok || len(conns) == 0 {
		h.mu.RUnlock()
		return
	}
	// Copy connections to avoid holding RLock during network writes
	connSlice := make([]*WSClient, 0, len(conns))
	for c := range conns {
		connSlice = append(connSlice, c)
	}
	h.mu.RUnlock()

	for _, wsClient := range connSlice {
		err := wsClient.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			h.mu.Lock()
			wsClient.Close()
			delete(h.clients[scanID], wsClient)
			if len(h.clients[scanID]) == 0 {
				delete(h.clients, scanID)
			}
			h.mu.Unlock()
		}
	}
}

// BroadcastLog is a convenience for sending a log message
func (h *WebSocketHub) BroadcastLog(scanID, message, level string) {
	h.Broadcast(scanID, WSMessage{Type: "log", Message: message, Level: level})
}

// BroadcastProgress sends a progress update
func (h *WebSocketHub) BroadcastProgress(scanID, phase string, percent int) {
	h.Broadcast(scanID, WSMessage{Type: "progress", Phase: phase, Percent: percent})
}

// BroadcastComplete sends the completion signal
func (h *WebSocketHub) BroadcastComplete(scanID string) {
	h.Broadcast(scanID, WSMessage{Type: "complete"})
}

// BroadcastError sends an error signal
func (h *WebSocketHub) BroadcastError(scanID, message string) {
	h.Broadcast(scanID, WSMessage{Type: "error", Message: message})
}

func init() {
	wsHub = NewWebSocketHub()
}
