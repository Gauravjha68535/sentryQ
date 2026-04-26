package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"SentryQ/ai"
	"SentryQ/internal/ui"
	"SentryQ/reporter"
	"SentryQ/utils"

	"gopkg.in/yaml.v3"
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

// ipRateLimiter is a simple sliding-window rate limiter keyed by client IP.
type ipRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
}

// allow returns true when the IP has fewer than maxReqs requests in the last window.
func (rl *ipRateLimiter) allow(ip string, maxReqs int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	prev := rl.requests[ip]
	var valid []time.Time
	for _, t := range prev {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= maxReqs {
		rl.requests[ip] = valid
		return false
	}
	rl.requests[ip] = append(valid, now)
	return true
}

// cleanup removes entries older than maxAge from the rate limiter map,
// preventing unbounded memory growth on long-running servers.
func (rl *ipRateLimiter) cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for ip, times := range rl.requests {
		var valid []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

// scanRateLimiter limits scan-triggering endpoints to 10 requests/min per IP.
var scanRateLimiter = &ipRateLimiter{requests: make(map[string][]time.Time)}

// reportRateLimiter limits report download endpoints to 30 requests/min per IP.
// Report generation (PDF/HTML/SARIF) is CPU-heavy; this prevents DoS via
// repeated regeneration requests.
var reportRateLimiter = &ipRateLimiter{requests: make(map[string][]time.Time)}

func init() {
	// Background cleanup every 5 minutes to prevent unbounded memory growth
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			scanRateLimiter.cleanup(2 * time.Minute)
			reportRateLimiter.cleanup(2 * time.Minute)
		}
	}()
}

// ollamaStatusCache holds the last Ollama reachability result so that
// /api/status does not make a live HTTP call on every frontend poll.
var ollamaStatusCache struct {
	sync.Mutex
	status    string
	checkedAt time.Time
}

const ollamaStatusTTL = 10 * time.Second

// getOllamaStatus returns a cached Ollama reachability result, refreshing at most
// once per ollamaStatusTTL to avoid blocking every /api/status request.
func getOllamaStatus(host string) string {
	ollamaStatusCache.Lock()
	defer ollamaStatusCache.Unlock()
	if time.Since(ollamaStatusCache.checkedAt) < ollamaStatusTTL {
		return ollamaStatusCache.status
	}
	status := "unreachable"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/api/version", host))
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			status = "connected"
		}
	}
	ollamaStatusCache.status = status
	ollamaStatusCache.checkedAt = time.Now()
	return status
}

var (
	startTime    time.Time
	settingsPath string // initialized in init() to ~/.sentryq/settings.json
	appSettings  = struct {
		sync.RWMutex
		OllamaHost   string `json:"ollama_host"`
		DefaultModel string `json:"default_model"`
		AIProvider   string `json:"ai_provider"`
		CustomAPIURL string `json:"custom_api_url"`
		CustomAPIKey string `json:"custom_api_key"`
		CustomModel  string `json:"custom_model"`
	}{
		OllamaHost:   "localhost:11434",
		DefaultModel: "qwen2.5-coder:7b",
		AIProvider:   "ollama",
	}
)

func loadSettings() {
	data, err := os.ReadFile(settingsPath)
	if err == nil {
		var s struct {
			OllamaHost   string `json:"ollama_host"`
			DefaultModel string `json:"default_model"`
			AIProvider   string `json:"ai_provider"`
			CustomAPIURL string `json:"custom_api_url"`
			CustomAPIKey string `json:"custom_api_key"`
			CustomModel  string `json:"custom_model"`
		}
		if err := json.Unmarshal(data, &s); err == nil {
			// Environment variable takes precedence over the stored key so that
			// users can inject credentials via the process environment without
			// ever writing them to disk.
			if envKey := os.Getenv("SENTRYQ_CUSTOM_API_KEY"); envKey != "" {
				s.CustomAPIKey = envKey
			}

			appSettings.Lock()
			appSettings.OllamaHost = s.OllamaHost
			appSettings.DefaultModel = s.DefaultModel
			if s.AIProvider != "" {
				appSettings.AIProvider = s.AIProvider
			}
			appSettings.CustomAPIURL = s.CustomAPIURL
			appSettings.CustomAPIKey = s.CustomAPIKey
			appSettings.CustomModel = s.CustomModel
			appSettings.Unlock()

			// Apply provider config to AI package
			ai.SetActiveProvider(s.AIProvider)
			if s.CustomAPIURL != "" {
				ai.SetCustomEndpoint(s.CustomAPIURL, s.CustomAPIKey, s.CustomModel)
			}
		}
	} else {
		// Settings file doesn't exist yet — still honour the env-var override.
		if envKey := os.Getenv("SENTRYQ_CUSTOM_API_KEY"); envKey != "" {
			appSettings.Lock()
			appSettings.CustomAPIKey = envKey
			appSettings.Unlock()
		}
	}
}

// recordMLFeedback records a user triage decision into the ML FP history file
// so the MLFPReducer can learn from it on future scans.
// Only "false_positive" and "resolved" statuses are meaningful signals;
// "open" and "ignored" are skipped since they carry no FP/TP information.
func recordMLFeedback(f reporter.Finding, status string) {
	isFP := status == "false_positive"
	isTP := status == "resolved"
	if !isFP && !isTP {
		return
	}

	mlCacheDir := ".sentryq-ml-cache"
	if homeDir, err := os.UserHomeDir(); err == nil {
		mlCacheDir = filepath.Join(homeDir, ".sentryq", "ml-cache")
	}

	reducer := ai.NewMLFPReducer(mlCacheDir)
	if err := reducer.LoadHistory(); err != nil {
		utils.LogWarn("ML feedback: failed to load history: " + err.Error())
		return
	}
	reducer.AddFeedback(f.RuleID, f.FilePath, f.Severity, isFP, "")
	if err := reducer.SaveHistory(); err != nil {
		utils.LogWarn("ML feedback: failed to save history: " + err.Error())
	}
}

// secureWriteFile writes data to path with owner-only permissions.
//
// Unix: uses os.WriteFile with mode 0600 — the OS enforces the permission bits.
//
// Windows: os.WriteFile permission bits are not enforced by NTFS, so we use an
// atomic write pattern:
//  1. Write data to a temporary file in the same directory.
//  2. Apply a restrictive ACL to the temp file via icacls (owner full control,
//     inheritance removed).
//  3. Rename the temp file to the final path — on Windows, os.Rename on the same
//     volume is atomic and replaces the destination.
//
// This guarantees the final file is never visible to other users with default ACLs.
func secureWriteFile(path string, data []byte) error {
	if runtime.GOOS == "windows" {
		dir := filepath.Dir(path)
		tmp, err := os.CreateTemp(dir, ".sentryq-tmp-*.json")
		if err != nil {
			return err
		}
		tmpPath := tmp.Name()
		removeTmp := func() { os.Remove(tmpPath) }

		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			removeTmp()
			return err
		}
		tmp.Close()

		// Apply restrictive ACL before exposing under the final name.
		if username := os.Getenv("USERNAME"); username != "" {
			if err := exec.Command(
				"icacls", tmpPath,
				"/inheritance:r",
				"/grant:r", username+":F",
			).Run(); err != nil {
				utils.LogWarn(fmt.Sprintf("secureWriteFile: icacls failed for %s: %v — file may be accessible to other users", tmpPath, err))
			}
		}

		// Atomic replace: rename is on the same drive so this is a single metadata op.
		if err := os.Rename(tmpPath, path); err != nil {
			removeTmp()
			return err
		}
		return nil
	}
	// Unix/macOS: the OS enforces 0600 permission bits directly.
	return os.WriteFile(path, data, 0600)
}

func saveSettings() error {
	// Hold the read lock for the full duration of marshal + file write so that
	// a concurrent PUT /api/settings cannot update appSettings between the
	// snapshot and the disk write (which would silently revert the new values).
	appSettings.RLock()
	defer appSettings.RUnlock()

	s := struct {
		OllamaHost   string `json:"ollama_host"`
		DefaultModel string `json:"default_model"`
		AIProvider   string `json:"ai_provider"`
		CustomAPIURL string `json:"custom_api_url"`
		CustomAPIKey string `json:"custom_api_key"`
		CustomModel  string `json:"custom_model"`
	}{
		OllamaHost:   appSettings.OllamaHost,
		DefaultModel: appSettings.DefaultModel,
		AIProvider:   appSettings.AIProvider,
		CustomAPIURL: appSettings.CustomAPIURL,
		CustomAPIKey: appSettings.CustomAPIKey,
		CustomModel:  appSettings.CustomModel,
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		utils.LogError("Failed to serialize settings", err)
		return err
	}
	// Ensure parent directory exists (first run, or settings moved to home dir).
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0700); err != nil {
		utils.LogError("Failed to create settings directory", err)
		return err
	}
	// secureWriteFile uses 0600 on Unix; on Windows it additionally calls
	// icacls to restrict the ACL to the current user (os.WriteFile alone
	// does not enforce permission bits on Windows NTFS).
	if err := secureWriteFile(settingsPath, data); err != nil {
		utils.LogError("Failed to save settings", err)
		return err
	}
	return nil
}

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

	// Bind to all interfaces (0.0.0.0) so the UI is reachable from other
	// machines on the same network, not just localhost.
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	localAddr := fmt.Sprintf("localhost:%d", port)
	server := &http.Server{
		Addr:         addr,
		Handler:      corsMiddleware(authMiddleware(mux)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // 0 = no write timeout — needed for long-running SSE/WebSocket upgrades and large report downloads
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

// ──────────────────────────────────────────────────────────
//  API Handlers
// ──────────────────────────────────────────────────────────

func handleListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := GetAllScans()
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if scans == nil {
		scans = []ScanRecord{}
	}
	httpJSON(w, http.StatusOK, scans)
}

func handleUploadScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit: 10 scan uploads per minute per IP.
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !scanRateLimiter.allow(clientIP, 10, time.Minute) {
		http.Error(w, "Too many scan requests. Try again in a minute.", http.StatusTooManyRequests)
		return
	}

	// Limit upload size to 100 MB — sufficient for any real project; prevents disk exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, 100<<20)

	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Failed to create multipart reader: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Save uploaded files to a temp directory
	tmpDir, err := os.MkdirTemp("", "sentryq-upload-")
	if err != nil {
		http.Error(w, "Failed to create temp directory", http.StatusInternalServerError)
		return
	}
	// cleanupTmp is called on any early-return error path. StartScanFromUpload
	// takes ownership of tmpDir on success and will remove it via defer.
	cleanupTmp := func() { os.RemoveAll(tmpDir) }

	var configJSON string
	fileCount := 0

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanupTmp()
			http.Error(w, "Error reading multipart part: "+err.Error(), http.StatusBadRequest)
			return
		}

		if part.FormName() == "config" {
			buf := new(strings.Builder)
			if _, err := io.Copy(buf, part); err != nil {
				part.Close()
				cleanupTmp()
				http.Error(w, "Failed to read config field", http.StatusBadRequest)
				return
			}
			configJSON = buf.String()
			part.Close()
			continue
		}

		if part.FormName() == "files" {
			filename := part.FileName()
			if filename == "" {
				part.Close()
				continue
			}

			// Preserve relative path structure with path traversal protection.
			// Use filepath.Abs for both sides so that cleaning, symlink-resolving
			// differences, and case-insensitive filesystems cannot bypass the check.
			relPath := filepath.Clean(filename)
			destPath := filepath.Join(tmpDir, relPath)

			absTmpDir, errAbs1 := filepath.Abs(tmpDir)
			absDestPath, errAbs2 := filepath.Abs(destPath)
			rel, relErr := filepath.Rel(absTmpDir, absDestPath)
			if errAbs1 != nil || errAbs2 != nil || relErr != nil ||
				strings.HasPrefix(rel, "..") || rel == ".." {
				utils.LogWarn(fmt.Sprintf("Path traversal attempt blocked: filename=%q from %s", filename, r.RemoteAddr))
				part.Close()
				continue
			}

			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				part.Close()
				utils.LogWarn("Failed to create upload subdirectory: " + err.Error())
				continue
			}
			// Wrap file creation + copy in a closure so defer always closes the
			// file descriptor — even when io.Copy or os.Create error mid-way.
			writeOK := func() bool {
				destFile, err := os.Create(destPath)
				if err != nil {
					return false
				}
				defer destFile.Close()
				if _, err := io.Copy(destFile, part); err != nil {
					os.Remove(destPath)
					utils.LogWarn("Failed to write uploaded file: " + err.Error())
					return false
				}
				return true
			}()
			part.Close()
			if writeOK {
				fileCount++
			}
		} else {
			part.Close()
		}
	}

	if fileCount == 0 && configJSON == "" {
		cleanupTmp()
		http.Error(w, "No files or config found in upload", http.StatusBadRequest)
		return
	}

	scanID, err := StartScanFromUpload(tmpDir, configJSON)
	if err != nil {
		cleanupTmp()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	httpJSON(w, http.StatusOK, map[string]string{"scan_id": scanID})
}

func handleGitScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit: 10 git scan requests per minute per IP.
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !scanRateLimiter.allow(clientIP, 10, time.Minute) {
		http.Error(w, "Too many scan requests. Try again in a minute.", http.StatusTooManyRequests)
		return
	}

	var req struct {
		URL    string        `json:"url"`
		Config WebScanConfig `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		http.Error(w, "Failed to serialize scan config", http.StatusInternalServerError)
		return
	}
	scanID, err := StartScanFromGit(req.URL, string(configJSON))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	httpJSON(w, http.StatusOK, map[string]string{"scan_id": scanID})
}

func handleScanRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	parts := strings.Split(path, "/")
	scanID := parts[0]
	if scanID == "" {
		http.NotFound(w, r)
		return
	}

	// DELETE /api/scan/:id
	if r.Method == http.MethodDelete {
		if err := DeleteScan(scanID); err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		return
	}

	// PATCH /api/scan/:id/finding/:findingId/status
	if len(parts) >= 4 && parts[1] == "finding" && parts[3] == "status" && r.Method == http.MethodPatch {
		findingID, err := strconv.Atoi(parts[2])
		if err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid finding ID: must be a number"})
			return
		}
		var req struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		// Fetch finding before update so we have ruleID/filePath/severity for ML feedback.
		finding, fetchErr := GetFindingByID(scanID, findingID)
		if err := UpdateFindingStatus(scanID, findingID, req.Status); err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if fetchErr == nil {
			recordMLFeedback(finding, req.Status)
		}
		httpJSON(w, http.StatusOK, map[string]string{"status": "updated"})
		return
	}

	// PATCH /api/scan/:id/findings/bulk-status
	if len(parts) >= 3 && parts[1] == "findings" && parts[2] == "bulk-status" && r.Method == http.MethodPatch {
		var req struct {
			IDs    []int  `json:"ids"`
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		var failed []int
		for _, dbID := range req.IDs {
			finding, fetchErr := GetFindingByID(scanID, dbID)
			if err := UpdateFindingStatus(scanID, dbID, req.Status); err != nil {
				utils.LogWarn(fmt.Sprintf("bulk-status: failed to update finding %d: %v", dbID, err))
				failed = append(failed, dbID)
				continue
			}
			if fetchErr == nil {
				recordMLFeedback(finding, req.Status)
			}
		}
		if len(failed) > 0 {
			httpJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error":  "some findings failed to update",
				"failed": failed,
			})
			return
		}
		httpJSON(w, http.StatusOK, map[string]string{"status": "updated"})
		return
	}

	// POST /api/scan/:id/stop
	if len(parts) >= 2 && parts[1] == "stop" && r.Method == http.MethodPost {
		handleStopScan(w, scanID)
		return
	}

	// POST /api/scan/:id/pause
	if len(parts) >= 2 && parts[1] == "pause" && r.Method == http.MethodPost {
		handlePauseScan(w, scanID)
		return
	}

	// POST /api/scan/:id/resume
	if len(parts) >= 2 && parts[1] == "resume" && r.Method == http.MethodPost {
		handleResumeScan(w, scanID)
		return
	}

	// GET /api/scan/:id/findings?phase=static|ai|final
	if len(parts) >= 2 && parts[1] == "findings" {
		phase := r.URL.Query().Get("phase")
		var findings []reporter.Finding
		var err error
		if phase != "" {
			findings, err = GetFindingsByPhase(scanID, phase)
		} else {
			findings, err = GetFindingsForScan(scanID)
		}
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if findings == nil {
			findings = []reporter.Finding{}
		}
		httpJSON(w, http.StatusOK, findings)
		return
	}

	// GET /api/scan/:id/report/html|csv|pdf
	if len(parts) >= 3 && parts[1] == "report" {
		// Rate limit: 30 report downloads per minute per IP.
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !reportRateLimiter.allow(clientIP, 30, time.Minute) {
			http.Error(w, "Too many report requests. Try again in a minute.", http.StatusTooManyRequests)
			return
		}

		format := parts[2]
		reportsDir := filepath.Join(os.TempDir(), "sentryQ", scanID)
		var filePath string
		var contentType string

		// Check for "all" format to return a ZIP of all reports
		if format == "all" {
			zipPath := filepath.Join(reportsDir, "reports_bundle.zip")

			// Create the zip file if it doesn't exist
			if _, err := os.Stat(zipPath); os.IsNotExist(err) {
				// Wrap in a function so defers execute immediately after creation,
				// before ServeFile is called.
				err = func() error {
					zipFile, err := os.Create(zipPath)
					if err != nil {
						return err
					}
					defer zipFile.Close()

					archive := zip.NewWriter(zipFile)
					defer archive.Close()

					filesToZip := []string{"report.html", "report.csv", "report.pdf", "report.sarif"}
					for _, fileName := range filesToZip {
						filePathToZip := filepath.Join(reportsDir, fileName)
						if _, err := os.Stat(filePathToZip); os.IsNotExist(err) {
							continue // skip missing files
						}

						f1, err := os.Open(filePathToZip)
						if err != nil {
							continue
						}

						w1, err := archive.Create(fileName)
						if err != nil {
							f1.Close()
							continue
						}

						if _, err := io.Copy(w1, f1); err != nil {
							utils.LogWarn("Failed to write zip entry: " + err.Error())
						}
						f1.Close()
					}
					return nil
				}()

				if err != nil {
					httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create zip file"})
					return
				}
			}

			// Resolve symlinks and verify the final path stays inside the reports
			// directory before serving, consistent with the per-format check below.
			resolvedZip, err := filepath.EvalSymlinks(zipPath)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			resolvedZipDir := filepath.Clean(reportsDir) + string(filepath.Separator)
			if !strings.HasPrefix(filepath.Clean(resolvedZip)+string(filepath.Separator), resolvedZipDir) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			// Open the file before serving to get a stable file descriptor —
			// eliminates the TOCTOU window between EvalSymlinks and the actual read.
			zipFD, err := os.Open(resolvedZip)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			defer zipFD.Close()
			zipStat, err := zipFD.Stat()
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sentryq_scan_%s.zip\"", scanID))
			w.Header().Set("Content-Type", "application/zip")
			http.ServeContent(w, r, zipStat.Name(), zipStat.ModTime(), zipFD)
			return
		}

		switch format {
		case "html":
			filePath = filepath.Join(reportsDir, "report.html")
			contentType = "text/html"
		case "csv":
			filePath = filepath.Join(reportsDir, "report.csv")
			contentType = "text/csv"
		case "pdf":
			filePath = filepath.Join(reportsDir, "report.pdf")
			contentType = "application/pdf"
		case "sarif":
			filePath = filepath.Join(reportsDir, "report.sarif")
			contentType = "application/json"
		default:
			http.NotFound(w, r)
			return
		}

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			// Report file missing — try to regenerate from DB.
			// Use the stored scan target name so the report shows the correct
			// project name, not the temporary reports directory.
			findings, dbErr := GetFindingsForScan(scanID)
			if dbErr != nil {
				utils.LogError(fmt.Sprintf("Failed to load findings for report regeneration (scan %s)", scanID), dbErr)
				httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "report not found and could not be regenerated"})
				return
			}
			if len(findings) > 0 {
				targetName := scanID
				if scanRec, recErr := GetScan(scanID); recErr == nil {
					targetName = scanRec.Target
				}
				webGenerateReportFiles(scanID, findings, targetName)
			}
		}

		// Resolve symlinks and verify the final path stays inside the expected
		// reports directory — prevents a crafted scan ID from escaping via symlink.
		resolvedPath, err := filepath.EvalSymlinks(filePath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		resolvedDir := filepath.Clean(reportsDir) + string(filepath.Separator)
		if !strings.HasPrefix(filepath.Clean(resolvedPath)+string(filepath.Separator), resolvedDir) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		// Open the file by its resolved path to obtain a stable file descriptor.
		// Serving from the fd (rather than the path) closes the TOCTOU window
		// between EvalSymlinks and the actual file read in http.ServeFile.
		reportFD, err := os.Open(resolvedPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer reportFD.Close()
		reportStat, err := reportFD.Stat()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=report.%s", format))
		http.ServeContent(w, r, reportStat.Name(), reportStat.ModTime(), reportFD)
		return
	}

	// GET /api/scan/:id (scan info)
	scan, err := GetScan(scanID)
	if err != nil {
		httpJSON(w, http.StatusNotFound, map[string]string{"error": "Scan not found"})
		return
	}
	httpJSON(w, http.StatusOK, scan)
}

func handleWebSocketRoute(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/ws/scan/")
	if scanID == "" {
		http.Error(w, "Missing scan ID", http.StatusBadRequest)
		return
	}
	wsHub.HandleWS(w, r, scanID)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var s struct {
			OllamaHost   string `json:"ollama_host"`
			DefaultModel string `json:"default_model"`
			AIProvider   string `json:"ai_provider"`
			CustomAPIURL string `json:"custom_api_url"`
			CustomAPIKey string `json:"custom_api_key"`
			CustomModel  string `json:"custom_model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		// Use defer-unlock so a panic inside the locked section never
		// causes a permanent deadlock. Capture values under the lock,
		// then apply side-effects (AI provider switch) outside it.
		var providerChanged bool
		func() {
			appSettings.Lock()
			defer appSettings.Unlock()
			if s.OllamaHost != "" {
				appSettings.OllamaHost = s.OllamaHost
			}
			if s.DefaultModel != "" {
				appSettings.DefaultModel = s.DefaultModel
			}
			if s.AIProvider != "" {
				appSettings.AIProvider = s.AIProvider
				providerChanged = true
			}
			// Only overwrite custom credentials when provided; an empty string
			// in the request body means "do not change", not "clear the value".
			if s.CustomAPIURL != "" {
				appSettings.CustomAPIURL = s.CustomAPIURL
			}
			if s.CustomAPIKey != "" {
				appSettings.CustomAPIKey = s.CustomAPIKey
			}
			if s.CustomModel != "" {
				appSettings.CustomModel = s.CustomModel
			}
		}()

		// Apply side-effects outside the lock to prevent deadlocking if the
		// AI package functions block or panic.
		if providerChanged {
			ai.SetActiveProvider(s.AIProvider)
		}
		if s.CustomAPIURL != "" {
			ai.SetCustomEndpoint(s.CustomAPIURL, s.CustomAPIKey, s.CustomModel)
		}

		if err := saveSettings(); err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to persist settings: " + err.Error()})
			return
		}
		httpJSON(w, http.StatusOK, map[string]string{"status": "saved"})
		return
	}

	appSettings.RLock()
	defer appSettings.RUnlock()
	maskedKey := ""
	if len(appSettings.CustomAPIKey) > 0 {
		maskedKey = "***"
	}
	httpJSON(w, http.StatusOK, map[string]interface{}{
		"ollama_host":        appSettings.OllamaHost,
		"default_model":      appSettings.DefaultModel,
		"ai_provider":        appSettings.AIProvider,
		"custom_api_url":     appSettings.CustomAPIURL,
		"custom_api_key":     maskedKey,
		"custom_api_key_set": len(appSettings.CustomAPIKey) > 0,
		"custom_model":       appSettings.CustomModel,
	})
}

func handleSystemStatus(w http.ResponseWriter, r *http.Request) {

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Check Ollama — use cached result to avoid blocking every status poll.
	appSettings.RLock()
	host := appSettings.OllamaHost
	appSettings.RUnlock()
	ollamaStatus := getOllamaStatus(host)

	// Check Go version
	goVersion := runtime.Version()

	// Check git
	gitStatus := "not found"
	if _, err := exec.LookPath(getGitBin()); err == nil {
		gitStatus = "available"
	}

	httpJSON(w, http.StatusOK, map[string]interface{}{
		"ollama":      ollamaStatus,
		"ollama_host": host,
		"go_version":  goVersion,
		"git":         gitStatus,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"memory_mb":   m.Alloc / 1024 / 1024,
		"uptime":      time.Since(startTime).Round(time.Second).String(),
	})
}

// isAllowedOllamaHost returns true if the host (host:port or bare host) is a
// loopback address. This prevents the ?host= query parameter from being used as
// an SSRF vector to reach internal network services or cloud metadata endpoints.
func isAllowedOllamaHost(host string) bool {
	// Strip port if present so we compare bare hostnames/IPs.
	h := host
	if strings.Contains(host, ":") {
		var err error
		h, _, err = net.SplitHostPort(host)
		if err != nil {
			return false
		}
	}
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func handleModels(w http.ResponseWriter, r *http.Request) {

	// Allow optional host parameter to fetch models from a different Ollama instance.
	// Restrict to loopback addresses to prevent SSRF via crafted ?host= values.
	host := r.URL.Query().Get("host")
	if host != "" && !isAllowedOllamaHost(host) {
		http.Error(w, "Invalid host: only loopback addresses are permitted", http.StatusBadRequest)
		return
	}
	if host == "" {
		appSettings.RLock()
		host = appSettings.OllamaHost
		appSettings.RUnlock()
	}

	models := ai.GetInstalledModels(host)
	if models == nil {
		models = []string{}
	}

	httpJSON(w, http.StatusOK, map[string]interface{}{
		"models": models,
	})
}

// ──────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────

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

// authMiddleware enforces token authentication on /api/* and /ws/* routes when
// SENTRYQ_AUTH_TOKEN is set. Static UI files always pass through so the
// frontend can load and display the auth token prompt to the user.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No token configured → open mode, pass through unchanged.
		if serverAuthToken == "" {
			next.ServeHTTP(w, r)
			return
		}
		// CORS preflight must bypass auth (browsers send OPTIONS before credentials).
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		// /health is a public liveness probe for container orchestrators — no auth.
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		// Only protect API and WebSocket routes; static UI files are public.
		if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/ws/") {
			next.ServeHTTP(w, r)
			return
		}
		// Accept X-Auth-Token header or Authorization: Bearer <token>.
		token := r.Header.Get("X-Auth-Token")
		if token == "" {
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if token != serverAuthToken {
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


func handleStopScan(w http.ResponseWriter, scanID string) {
	if err := StopScan(scanID); err != nil {
		httpJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	httpJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
}

func handlePauseScan(w http.ResponseWriter, scanID string) {
	if err := PauseScan(scanID); err != nil {
		httpJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	httpJSON(w, http.StatusOK, map[string]string{"status": "paused"})
}

func handleResumeScan(w http.ResponseWriter, scanID string) {
	if err := ResumeScan(scanID); err != nil {
		httpJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	httpJSON(w, http.StatusOK, map[string]string{"status": "running"})
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

// ──────────────────────────────────────────────────────────
//  Custom Endpoint API Handlers
// ──────────────────────────────────────────────────────────

func handleCustomEndpointTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL    string `json:"url"`
		APIKey string `json:"api_key"`
		Model  string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.URL == "" || req.Model == "" {
		httpJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"message": "URL and model name are required",
		})
		return
	}

	ok, msg := ai.TestOpenAIEndpoint(req.URL, req.APIKey, req.Model)
	httpJSON(w, http.StatusOK, map[string]interface{}{
		"success": ok,
		"message": msg,
	})
}

func handleCustomEndpointModels(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// Prefer the Authorization header to avoid exposing the key in URLs (which appear in
	// server logs, browser history, and proxy logs). Fall back to the query param for
	// backward compatibility with older frontend versions.
	apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if apiKey == "" {
		apiKey = r.URL.Query().Get("api_key")
	}

	if url == "" {
		httpJSON(w, http.StatusOK, map[string]interface{}{
			"models": []string{},
			"error":  "URL parameter is required",
		})
		return
	}

	models, err := ai.ListOpenAIModels(url, apiKey)
	if err != nil {
		httpJSON(w, http.StatusOK, map[string]interface{}{
			"models": []string{},
			"error":  err.Error(),
		})
		return
	}
	if models == nil {
		models = []string{}
	}

	httpJSON(w, http.StatusOK, map[string]interface{}{
		"models": models,
	})
}

// ──────────────────────────────────────────────────────────
//  Rules API Handlers
// ──────────────────────────────────────────────────────────

type YAMLRule struct {
	ID        string   `json:"id" yaml:"id"`
	Languages []string `json:"languages" yaml:"languages"`
	Patterns  []struct {
		Regex string `json:"regex" yaml:"regex"`
	} `json:"patterns" yaml:"patterns"`
	Severity    string `json:"severity" yaml:"severity"`
	Description string `json:"description" yaml:"description"`
	Remediation string `json:"remediation" yaml:"remediation"`
	CWE         string `json:"cwe" yaml:"cwe"`
	OWASP       string `json:"owasp" yaml:"owasp"`
}

func handleRulesList(w http.ResponseWriter, r *http.Request) {
	rulesDir := getDefaultRulesDir()
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			httpJSON(w, http.StatusOK, []interface{}{})
			return
		}
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "Cannot read rules directory"})
		return
	}
	type RuleFileSummary struct {
		Filename  string `json:"filename"`
		RuleCount int    `json:"rule_count"`
	}
	var files []RuleFileSummary
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(rulesDir, e.Name()))
		if err != nil {
			continue
		}
		var rules []YAMLRule
		if parseErr := yaml3Unmarshal(data, &rules); parseErr != nil {
			utils.LogWarn(fmt.Sprintf("handleRulesList: failed to parse %s: %v", e.Name(), parseErr))
		}
		files = append(files, RuleFileSummary{Filename: e.Name(), RuleCount: len(rules)})
	}
	if files == nil {
		files = []RuleFileSummary{}
	}
	httpJSON(w, http.StatusOK, files)
}

func handleRulesFile(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	if filename == "" || strings.Contains(filename, "..") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}
	rulesDir := getDefaultRulesDir()
	rulesPath := filepath.Join(rulesDir, filename)
	// Verify the resolved path is still inside the rules directory to prevent
	// path traversal via absolute paths or symlink chains.
	cleanedPath := filepath.Clean(rulesPath)
	cleanedDir := filepath.Clean(rulesDir) + string(filepath.Separator)
	if !strings.HasPrefix(cleanedPath+string(filepath.Separator), cleanedDir) {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(rulesPath)
		if err != nil {
			httpJSON(w, http.StatusNotFound, map[string]string{"error": "Rule file not found"})
			return
		}
		var rules []YAMLRule
		if parseErr := yaml3Unmarshal(data, &rules); parseErr != nil {
			utils.LogWarn(fmt.Sprintf("handleRulesFile GET: failed to parse %s: %v", filename, parseErr))
		}
		if rules == nil {
			rules = []YAMLRule{}
		}
		httpJSON(w, http.StatusOK, rules)

	case http.MethodPost:
		var newRule YAMLRule
		if err := json.NewDecoder(r.Body).Decode(&newRule); err != nil {
			http.Error(w, "Invalid rule JSON", http.StatusBadRequest)
			return
		}
		// Validate required fields
		if newRule.ID == "" || newRule.Severity == "" || len(newRule.Patterns) == 0 {
			http.Error(w, "id, severity, and patterns are required", http.StatusBadRequest)
			return
		}
		// Load existing
		var rules []YAMLRule
		data, err := os.ReadFile(rulesPath)
		if err == nil {
			if parseErr := yaml3Unmarshal(data, &rules); parseErr != nil {
				http.Error(w, "Failed to parse existing rules file: "+parseErr.Error(), http.StatusInternalServerError)
				return
			}
		}
		rules = append(rules, newRule)
		out, err := yaml3Marshal(rules)
		if err != nil {
			http.Error(w, "Failed to serialize rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(rulesPath, out, 0600); err != nil {
			http.Error(w, "Failed to write rules file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		httpJSON(w, http.StatusOK, map[string]string{"status": "added", "id": newRule.ID})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleRulesTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Pattern string `json:"pattern"`
		Code    string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	type MatchResult struct {
		Line    int    `json:"line"`
		Content string `json:"content"`
		Match   string `json:"match"`
	}

	// Reject patterns that are excessively long to guard against ReDoS.
	// Go's regexp package uses RE2 (no catastrophic backtracking), but very
	// long patterns can still cause high compile-time CPU usage.
	if len(req.Pattern) > 2048 {
		httpJSON(w, http.StatusOK, map[string]interface{}{
			"valid":   false,
			"error":   "pattern too long (max 2048 characters)",
			"matches": []MatchResult{},
		})
		return
	}
	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		httpJSON(w, http.StatusOK, map[string]interface{}{
			"valid":   false,
			"error":   err.Error(),
			"matches": []MatchResult{},
		})
		return
	}

	lines := strings.Split(req.Code, "\n")
	var matches []MatchResult
	for i, line := range lines {
		loc := re.FindString(line)
		if loc != "" {
			matches = append(matches, MatchResult{Line: i + 1, Content: line, Match: loc})
		}
	}
	if matches == nil {
		matches = []MatchResult{}
	}
	httpJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"matches": matches,
	})
}

// yaml3Unmarshal is a thin wrapper around gopkg.in/yaml.v3
func yaml3Unmarshal(data []byte, v interface{}) error {
	return yaml.Unmarshal(data, v)
}

func yaml3Marshal(v interface{}) ([]byte, error) {
	return yaml.Marshal(v)
}

// ──────────────────────────────────────────────────────────
//  Report Cleanup & Startup Checks
// ──────────────────────────────────────────────────────────

// startReportCleanup runs a background loop that deletes report directories older than 48 hours.
// It exits when ctx is cancelled (i.e. on server shutdown).
func startReportCleanup(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			utils.LogError("startReportCleanup: recovered from panic", fmt.Errorf("%v", r))
		}
	}()

	const maxAge = 48 * time.Hour
	const interval = 6 * time.Hour

	// Run once immediately on startup
	cleanOldReports(maxAge)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanOldReports(maxAge)
		case <-ctx.Done():
			return
		}
	}
}

// cleanOldReports deletes scan report directories older than maxAge and also
// removes any orphaned scan temp directories (sentryq-upload-*, sentryq-scan-*)
// that are older than 24 hours (these are normally removed by defer in the scan
// goroutine, but a hard crash can leave them behind).
func cleanOldReports(maxAge time.Duration) {
	reportsRoot := filepath.Join(os.TempDir(), "sentryQ")
	entries, err := os.ReadDir(reportsRoot)
	if err == nil {
		cutoff := time.Now().Add(-maxAge)
		cleaned := 0
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				dirPath := filepath.Join(reportsRoot, entry.Name())
				if err := os.RemoveAll(dirPath); err == nil {
					cleaned++
				}
			}
		}
		if cleaned > 0 {
			utils.LogInfo(fmt.Sprintf("🧹 Report cleanup: removed %d report directories older than %s", cleaned, maxAge))
		}
	}

	// Clean orphaned scan temp directories that survived a hard crash.
	cleanOrphanedScanDirs(24 * time.Hour)
}

// cleanOrphanedScanDirs removes sentryq-upload-* and sentryq-scan-* directories
// in os.TempDir() that are older than maxAge. Under normal operation these are
// removed by the defer in StartScanFromUpload/StartScanFromGit, but a SIGKILL or
// panic outside the deferred block can leave them behind.
func cleanOrphanedScanDirs(maxAge time.Duration) {
	tmpDir := os.TempDir()
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	cleaned := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "sentryq-upload-") && !strings.HasPrefix(name, "sentryq-scan-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			dirPath := filepath.Join(tmpDir, name)
			if err := os.RemoveAll(dirPath); err == nil {
				cleaned++
			}
		}
	}
	if cleaned > 0 {
		utils.LogInfo(fmt.Sprintf("🧹 Temp cleanup: removed %d orphaned scan directories older than %s", cleaned, maxAge))
	}
}

// checkStartupDependencies logs the availability of optional external tools.
func checkStartupDependencies() {
	deps := []struct {
		name    string
		bin     string
		purpose string
	}{
		{"Git", getGitBin(), "Repository cloning"},
		{"Semgrep", "semgrep", "Advanced static analysis"},
		{"OSV-Scanner", "osv-scanner", "SCA vulnerability scanning"},
		{"Trivy", "trivy", "Container image scanning"},
	}

	for _, dep := range deps {
		if _, err := exec.LookPath(dep.bin); err != nil {
			utils.LogWarn(fmt.Sprintf("⚠ %s not found — %s will be skipped", dep.name, dep.purpose))
		} else {
			utils.LogInfo(fmt.Sprintf("[✓] %s available (%s)", dep.name, dep.purpose))
		}
	}
}

