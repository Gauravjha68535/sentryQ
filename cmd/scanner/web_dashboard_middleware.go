package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
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

// securityHeadersMiddleware adds defence-in-depth HTTP headers to every response.
// CSP is especially important because the HTML report embeds AI-generated content
// (ExploitPoC, FixedCode fields) — without it, any XSS in those fields executes.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// CSP: self-contained UI + API; no inline scripts beyond what we control.
		// Reports are served as downloads (Content-Disposition: attachment), not rendered here.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'")
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

// validateOllamaHost checks that a user-supplied Ollama host is safe to connect to.
// Unlike rejectPrivateURL (which blocks all RFC1918), this function allows LAN addresses
// because remote Ollama servers on local networks are a documented use case.
// It blocks only cloud IMDS ranges (169.254.x.x, link-local) which have no
// legitimate use as an Ollama host and are the primary SSRF target.
func validateOllamaHost(hostPort string) error {
	if hostPort == "" {
		return nil // empty = use default, which is localhost — safe
	}
	host := hostPort
	if strings.Contains(hostPort, ":") {
		var err error
		host, _, err = net.SplitHostPort(hostPort)
		if err != nil {
			// Might be a bare IPv6 address without port; try as-is
			host = hostPort
		}
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("cannot resolve Ollama host %q: %w", host, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		// Block link-local (169.254.x.x, fe80::/10) — the cloud IMDS range.
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("Ollama host %q resolves to a cloud metadata address (%s)", host, addr)
		}
		// Block the specific AWS/GCP IPv6 metadata address.
		if addr == "fd00:ec2::254" {
			return fmt.Errorf("Ollama host %q resolves to cloud metadata (%s)", host, addr)
		}
	}
	return nil
}

// rejectPrivateURL parses rawURL and rejects any host that resolves to a
// private, loopback, or link-local IP. This prevents SSRF via crafted
// ?url= parameters on the custom-endpoint and similar API handlers.
func rejectPrivateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("only http/https URLs are permitted")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		// Treat unresolvable hosts as invalid to prevent DNS-rebinding bypass.
		return fmt.Errorf("cannot resolve host %q: %w", host, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("host %q resolves to a reserved address (%s)", host, addr)
		}
		// RFC1918 private ranges
		privateRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "169.254.0.0/16"}
		for _, cidr := range privateRanges {
			_, block, _ := net.ParseCIDR(cidr)
			if block != nil && block.Contains(ip) {
				return fmt.Errorf("host %q resolves to a private address (%s)", host, addr)
			}
		}
	}
	return nil
}
