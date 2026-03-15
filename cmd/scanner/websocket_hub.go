package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"QWEN_SCR_24_FEB_2026/utils"

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

// WebSocketHub manages all WebSocket connections grouped by scan ID
type WebSocketHub struct {
	mu      sync.RWMutex
	clients map[string]map[*websocket.Conn]bool // scanID -> set of connections
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
		clients: make(map[string]map[*websocket.Conn]bool),
	}
}

// HandleWS upgrades an HTTP connection to WebSocket for a specific scan
func (h *WebSocketHub) HandleWS(w http.ResponseWriter, r *http.Request, scanID string) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		utils.LogError("WebSocket upgrade failed", err)
		return
	}

	h.mu.Lock()
	if h.clients[scanID] == nil {
		h.clients[scanID] = make(map[*websocket.Conn]bool)
	}
	h.clients[scanID][conn] = true
	h.mu.Unlock()

	// Send a welcome message
	welcome := WSMessage{Type: "log", Message: fmt.Sprintf("Connected to scan %s", scanID), Level: "info"}
	data, _ := json.Marshal(welcome)
	conn.WriteMessage(websocket.TextMessage, data)

	// Keep connection alive; read pump (just drain incoming messages)
	go func() {
		defer func() {
			h.mu.Lock()
			delete(h.clients[scanID], conn)
			if len(h.clients[scanID]) == 0 {
				delete(h.clients, scanID)
			}
			h.mu.Unlock()
			conn.Close()
		}()
		for {
			_, _, err := conn.ReadMessage()
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

	// Copy client references under the lock to avoid concurrent map iteration/write panic
	h.mu.RLock()
	conns := make([]*websocket.Conn, 0, len(h.clients[scanID]))
	for conn := range h.clients[scanID] {
		conns = append(conns, conn)
	}
	h.mu.RUnlock()

	for _, conn := range conns {
		err := conn.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			conn.Close()
			h.mu.Lock()
			delete(h.clients[scanID], conn)
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
