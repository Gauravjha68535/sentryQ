package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"SentryQ/utils"
)

// allowedOrigin returns true for origins that SentryQ (a local tool) should accept.
// We parse the Origin header with url.Parse so that hostnames like "localhostevil.com"
// or "127.0.0.1.attacker.com" cannot bypass a naive HasPrefix check.
// We also restrict to http/https schemes — other schemes (ftp, file, data, etc.)
// are never legitimate browser origins for a local web app.
func allowedOrigin(origin string) bool {
	if origin == "" {
		return true // same-origin requests have no Origin header
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	// Reject non-HTTP schemes (e.g., ftp://, file://, javascript://)
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	host := u.Hostname() // strips port; returns bare hostname or IP
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowedOrigin(origin) && origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		// Include auth headers so the browser doesn't block preflight for authenticated requests.
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfMiddleware protects against Cross-Site Request Forgery on state-changing API endpoints.
// It requires that POST/PUT/DELETE requests specify Content-Type: application/json.
// Because browsers do not allow cross-origin requests with this Content-Type without
// a successful CORS preflight, this simple check prevents CSRF attacks via <form> or text/plain POSTs.
func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			// Skip CSRF check for websocket upgrade requests which use GET but can mutate state
			if r.Header.Get("Upgrade") == "websocket" {
				next.ServeHTTP(w, r)
				return
			}
			contentType := r.Header.Get("Content-Type")
			// Allow application/json (all API endpoints) and multipart/form-data (file upload).
			// Browsers cannot cross-origin-submit file inputs, so multipart/form-data is safe here.
			if !strings.HasPrefix(contentType, "application/json") && !strings.HasPrefix(contentType, "multipart/form-data") {
				utils.LogWarn(fmt.Sprintf("CSRF block: Missing/invalid Content-Type from %s: %s %s", r.RemoteAddr, r.Method, r.URL.Path))
				http.Error(w, "CSRF protection: Content-Type must be application/json", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// authMiddleware enforces SENTRYQ_AUTH_TOKEN single-token protection on /api/* and /ws/* routes.
// If SENTRYQ_AUTH_TOKEN is not set, all requests pass through (open mode).
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/ws/") {
			next.ServeHTTP(w, r)
			return
		}
		if serverAuthToken == "" {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get("X-Auth-Token")
		if token == "" {
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(serverAuthToken)) != 1 {
			utils.LogWarn(fmt.Sprintf("Unauthorized API request from %s: %s %s", r.RemoteAddr, r.Method, r.URL.Path))
			http.Error(w, "Unauthorized: set X-Auth-Token header with the value of SENTRYQ_AUTH_TOKEN", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func httpJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		utils.LogWarn(fmt.Sprintf("httpJSON: failed to encode response (status %d): %v", status, err))
	}
}

func openBrowser(url string) {
	time.Sleep(800 * time.Millisecond)
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		utils.LogInfo(fmt.Sprintf("Open %s in your browser", url))
	}
}
