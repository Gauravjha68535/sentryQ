package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SentryQ/utils"
)

// UserRole defines permission level.
type UserRole string

const (
	RoleAdmin    UserRole = "admin"
	RoleAnalyst  UserRole = "analyst" // can scan and triage
	RoleViewer   UserRole = "viewer"  // read-only
)

// User represents a SentryQ user account.
type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"` // bcrypt in prod; sha256 for simplicity here
	Role         UserRole `json:"role"`
	CreatedAt    string   `json:"created_at"`
	LastLoginAt  string   `json:"last_login_at,omitempty"`
}

// Session is an in-memory session token (survives process restarts via file).
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Role      UserRole  `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

var (
	usersMu  sync.RWMutex
	users    = make(map[string]*User)   // username → User
	sessions = make(map[string]*Session) // token → Session
	usersFile string
)

func initMultiUser() {
	home, _ := os.UserHomeDir()
	usersFile = filepath.Join(home, ".sentryq", "users.json")
	loadUsers()

	// Bootstrap: create default admin if no users exist
	usersMu.RLock()
	count := len(users)
	usersMu.RUnlock()
	if count == 0 {
		pwd := os.Getenv("SENTRYQ_ADMIN_PASSWORD")
		if pwd == "" {
			pwd = generateToken(8)
			fmt.Printf("\n🔐 SentryQ multi-user mode: default admin password = %s\n   (set SENTRYQ_ADMIN_PASSWORD to override)\n\n", pwd)
		}
		_ = CreateUser("admin", pwd, RoleAdmin)
	}

	// Background session pruner
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			pruneExpiredSessions()
		}
	}()
}

func loadUsers() {
	data, err := os.ReadFile(usersFile)
	if err != nil {
		return
	}
	var list []*User
	if err := json.Unmarshal(data, &list); err != nil {
		utils.LogWarn("multi-user: failed to parse users.json: " + err.Error())
		return
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	for _, u := range list {
		users[u.Username] = u
	}
}

func saveUsers() {
	usersMu.RLock()
	list := make([]*User, 0, len(users))
	for _, u := range users {
		list = append(list, u)
	}
	usersMu.RUnlock()

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(usersFile), 0700)
	_ = os.WriteFile(usersFile, data, 0600)
}

// CreateUser adds a new user. Returns error if username already exists.
func CreateUser(username, password string, role UserRole) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	if _, exists := users[username]; exists {
		return fmt.Errorf("user %q already exists", username)
	}
	u := &User{
		ID:           generateToken(8),
		Username:     username,
		PasswordHash: hashPassword(password),
		Role:         role,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	users[username] = u
	go saveUsers()
	return nil
}

// Login validates credentials and returns a session token. Returns "" on failure.
func Login(username, password string) string {
	usersMu.RLock()
	u, ok := users[username]
	usersMu.RUnlock()
	if !ok || u.PasswordHash != hashPassword(password) {
		return ""
	}

	token := generateToken(32)
	sess := &Session{
		Token:     token,
		UserID:    u.ID,
		Username:  u.Username,
		Role:      u.Role,
		ExpiresAt: time.Now().Add(12 * time.Hour),
	}

	usersMu.Lock()
	sessions[token] = sess
	u.LastLoginAt = time.Now().UTC().Format(time.RFC3339)
	usersMu.Unlock()

	go saveUsers()
	return token
}

// SessionFromRequest extracts and validates the session from the request.
// Returns nil when no valid session is found.
func SessionFromRequest(r *http.Request) *Session {
	// Try Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	token := ""
	if strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimPrefix(auth, "Bearer ")
	}
	// Fall back to X-Auth-Token header
	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}
	// Fall back to cookie
	if token == "" {
		if c, err := r.Cookie("sentryq_token"); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		return nil
	}

	usersMu.RLock()
	sess, ok := sessions[token]
	usersMu.RUnlock()
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil
	}
	return sess
}

// RequireRole is an HTTP middleware that enforces a minimum role.
// When multi-user mode is off (SENTRYQ_MULTI_USER != "1"), passes through.
func RequireRole(role UserRole, next http.HandlerFunc) http.HandlerFunc {
	if os.Getenv("SENTRYQ_MULTI_USER") != "1" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromRequest(r)
		if sess == nil {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}
		if !hasRole(sess.Role, role) {
			http.Error(w, `{"error":"insufficient permissions"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func hasRole(userRole, required UserRole) bool {
	order := map[UserRole]int{RoleViewer: 1, RoleAnalyst: 2, RoleAdmin: 3}
	return order[userRole] >= order[required]
}

func pruneExpiredSessions() {
	usersMu.Lock()
	defer usersMu.Unlock()
	now := time.Now()
	for tok, sess := range sessions {
		if now.After(sess.ExpiresAt) {
			delete(sessions, tok)
		}
	}
}

func generateToken(bytes int) string {
	b := make([]byte, bytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashPassword(password string) string {
	// SHA-256 hex hash. Sufficient for local-first self-hosted use.
	// For internet-facing deployments, replace with bcrypt (golang.org/x/crypto/bcrypt).
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

// ── Auth API handlers ─────────────────────────────────────────────────────────

// handleLogin handles POST /api/auth/login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	token := Login(body.Username, body.Password)
	if token == "" {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sentryq_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   43200, // 12 hours
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// handleCreateUser handles POST /api/auth/users (admin only)
func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		Role     UserRole `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if body.Role == "" {
		body.Role = RoleAnalyst
	}
	if err := CreateUser(body.Username, body.Password, body.Role); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "created"})
}

// handleListUsers handles GET /api/auth/users (admin only)
func handleListUsers(w http.ResponseWriter, r *http.Request) {
	usersMu.RLock()
	list := make([]map[string]interface{}, 0, len(users))
	for _, u := range users {
		list = append(list, map[string]interface{}{
			"id":            u.ID,
			"username":      u.Username,
			"role":          u.Role,
			"created_at":    u.CreatedAt,
			"last_login_at": u.LastLoginAt,
		})
	}
	usersMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}
