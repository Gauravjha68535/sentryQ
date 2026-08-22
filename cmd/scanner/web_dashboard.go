package main

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"SentryQ/internal/ui"
	"SentryQ/utils"
)

// staticFS is the embedded React build output (lazy initialized)
var staticFS fs.FS
var staticFSOnce sync.Once
var staticFSError error

// serverAuthToken is loaded from SENTRYQ_AUTH_TOKEN at startup.
// When non-empty, every /api/* and /ws/* request must supply the matching
// token via "X-Auth-Token: <token>" or "Authorization: Bearer <token>".
// If the env var is unset, the server operates in open mode (backward compatible).
var serverAuthToken string

// ──────────────────────────────────────────────────────────

// StartWebServer starts the full web application server
func StartWebServer(port int) {
	if err := InitDB(); err != nil {
		utils.LogError("Failed to initialize database", err)
		return
	}

	// Initialize embedded static filesystem (lazy, with graceful fallback)
	staticFSOnce.Do(func() {
		staticFS, staticFSError = ui.StaticFS()
	})
	if staticFSError != nil {
		utils.LogWarn("⚠ Web UI not embedded. Running in API-only mode.")
		utils.LogWarn("   Run './build.sh' to embed the web UI.")
	}

	mux := http.NewServeMux()

	// Liveness probe — no auth required (excluded in authMiddleware as well).
	// Returns 200 OK for container orchestrators (Kubernetes, Docker, etc.).
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// API Routes
	mux.HandleFunc("/api/scans", handleListScans)
	mux.HandleFunc("/api/scan/upload", handleUploadScan)
	mux.HandleFunc("/api/scan/git", handleGitScan)
	mux.HandleFunc("/api/settings", handleSettings)
	mux.HandleFunc("/api/system/status", handleSystemStatus)
	mux.HandleFunc("/api/models", handleModels)
	mux.HandleFunc("/api/rules", handleRulesList)
	mux.HandleFunc("/api/rules/test", handleRulesTest)
	mux.HandleFunc("/api/rules/", handleRulesFile)
	mux.HandleFunc("/api/custom-endpoint/test", handleCustomEndpointTest)
	mux.HandleFunc("/api/custom-endpoint/models", handleCustomEndpointModels)

	// Dynamic scan routes (manual routing for path params)
	mux.HandleFunc("/api/scan/compliance", handleScanCompliance)
	mux.HandleFunc("/api/scans/diff", handleScansDiff)
	mux.HandleFunc("/api/scan/", handleScanRoutes)
	mux.HandleFunc("/ws/scan/", handleWebSocketRoute)

	// Serve React SPA (embedded static files)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If embedded UI is not available, return API-only mode message
		if staticFS == nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "SentryQ API Only Mode\n\nWeb UI not embedded.\nRun './build.sh' to embed the web UI.")
			return
		}

		// Check if the file exists in the embedded FS
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		f, err := staticFS.Open(path)
		if err != nil {
			// SPA fallback: serve index.html for all non-API routes
			index, err := staticFS.Open("index.html")
			if err != nil {
				http.Error(w, "Web UI dist not found. Run 'cd web && npm run build' first.", http.StatusNotFound)
				return
			}
			defer index.Close()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if _, err := io.Copy(w, index); err != nil {
				utils.LogWarn("Failed to serve index.html: " + err.Error())
			}
			return
		}
		f.Close()
		http.FileServer(http.FS(staticFS)).ServeHTTP(w, r)
	})

	// Default to localhost to prevent accidental LAN exposure.
	// Set SENTRYQ_BIND=0.0.0.0 to explicitly allow network access.
	bindAddr := "127.0.0.1"
	if envBind := os.Getenv("SENTRYQ_BIND"); envBind != "" {
		bindAddr = envBind
	}
	addr := fmt.Sprintf("%s:%d", bindAddr, port)
	localAddr := fmt.Sprintf("localhost:%d", port)
	server := &http.Server{
		Addr:         addr,
		Handler:      securityHeadersMiddleware(corsMiddleware(csrfMiddleware(authMiddleware(mux)))),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 10 * time.Minute, // generous but bounded; WebSocket connections bypass this after the protocol upgrade
		IdleTimeout:  120 * time.Second,
	}

	utils.LogInfo(fmt.Sprintf("🌐 SentryQ Web UI starting on http://%s", localAddr))

	// ── Startup Dependency Checks ──
	checkStartupDependencies()

	// Background goroutine lifetime is tied to a cancel context so it stops cleanly
	// when the server receives a shutdown signal.
	bgCtx, bgCancel := context.WithCancel(context.Background())

	// ── Background Report Cleanup (every 6 hours, delete reports older than 48h) ──
	go startReportCleanup(bgCtx)

	// Auto-open browser
	go openBrowser("http://" + localAddr)

	// Setup graceful shutdown.
	// SIGTERM is defined on Windows but never delivered by the OS — only SIGINT (Ctrl+C)
	// is reliably sent on Windows. Using a runtime check avoids silently broken shutdown
	// on Windows when a process manager sends SIGTERM.
	stop := make(chan os.Signal, 1)
	sigs := []os.Signal{os.Interrupt}
	if runtime.GOOS != "windows" {
		sigs = append(sigs, syscall.SIGTERM)
	}
	signal.Notify(stop, sigs...)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			if strings.Contains(err.Error(), "address already in use") {
				utils.LogError(fmt.Sprintf("Port %d is already in use. Please stop the other process or use a different port with: ./sentryq --port <new-port>", port), err)
			} else {
				utils.LogError("Web server failed", err)
			}
		}
	}()

	<-stop // Wait for OS signal
	utils.LogInfo("\nShutting down gracefully...")

	// Stop background goroutines before shutting down the HTTP server.
	bgCancel()

	// Give active connections 5 seconds to finish
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		utils.LogError("Server forced to shutdown", err)
	}

	CloseDB()

	utils.LogInfo("SentryQ stopped.")
}


func init() {
	// Load auth token from environment.  When set, all /api/* and /ws/* routes
	// require an X-Auth-Token (or Authorization: Bearer) header with this value.
	serverAuthToken = os.Getenv("SENTRYQ_AUTH_TOKEN")
	if serverAuthToken != "" {
		utils.LogInfo("API authentication enabled — requests require X-Auth-Token header (SENTRYQ_AUTH_TOKEN is set)")
	}

	// Compute settings path in the user's home directory so the file is not
	// written to whatever the current working directory happens to be, and is
	// only readable by the current user (0600).
	if home, err := os.UserHomeDir(); err == nil {
		settingsPath = filepath.Join(home, ".sentryq", "settings.json")
	} else {
		// Home directory is unavailable (e.g. container with no /etc/passwd entry).
		// Fall back to a subdirectory of the OS temp dir so the file is never
		// written to the current working directory, which may be shared or world-readable.
		settingsPath = filepath.Join(os.TempDir(), "sentryq", "settings.json")
	}
	loadSettings()
	startTime = time.Now()
}

