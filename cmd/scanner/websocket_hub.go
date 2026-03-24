package main

import (
	"encoding/json"
	"net/http"
	"sync"

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

// WSClient wraps a websocket connection with a mutex for thread-safe writes
type WSClient struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

// WriteMessage is a thread-safe wrapper for writing text messages
func (c *WSClient) WriteMessage(messageType int, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(messageType, data)
}

// Close gracefully closes the connection
func (c *WSClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Close()
}

// ReadMessage reads from the connection
func (c *WSClient) ReadMessage() (messageType int, p []byte, err error) {
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
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

// NewWebSocketHub creates a new hub
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients: make(map[string]map[*WSClient]bool),
	}
}

// HandleWS upgrades an HTTP connection to WebSocket for a specific scan
func (h *WebSocketHub) HandleWS(w http.ResponseWriter, r *http.Request, scanID string) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		utils.LogError("WebSocket upgrade failed", err)
		return
	}

	wsClient := &WSClient{conn: conn}

	h.mu.Lock()
	if h.clients[scanID] == nil {
		h.clients[scanID] = make(map[*WSClient]bool)
	}
	h.clients[scanID][wsClient] = true
	h.mu.Unlock()

	// Send a welcome message
	welcome := WSMessage{Type: "log", Message: "Connected to WebSocket", Level: "info"}
	data, _ := json.Marshal(welcome)
	wsClient.WriteMessage(websocket.TextMessage, data)

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
