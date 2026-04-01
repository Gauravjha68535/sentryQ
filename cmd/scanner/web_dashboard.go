package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
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
	}
}

func saveSettings() {
	appSettings.RLock()
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
	appSettings.RUnlock()
	data, _ := json.MarshalIndent(s, "", "  ")
	// Ensure parent directory exists (first run, or settings moved to home dir).
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0700); err != nil {
		utils.LogError("Failed to create settings directory", err)
		return
	}
	// 0600: owner read/write only — the file contains API keys.
	if err := os.WriteFile(settingsPath, data, 0600); err != nil {
		utils.LogError("Failed to save settings", err)
	}
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
			io.Copy(w, index)
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
		Addr:    addr,
		Handler: corsMiddleware(mux),
	}

	utils.LogInfo(fmt.Sprintf("🌐 SentryQ Web UI starting on http://%s", localAddr))

	// ── Startup Dependency Checks ──
	checkStartupDependencies()

	// ── Background Report Cleanup (every 6 hours, delete reports older than 48h) ──
	go startReportCleanup()

	// Auto-open browser
	go openBrowser("http://" + localAddr)

	// Setup graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

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

	// Give active connections 5 seconds to finish
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		utils.LogError("Server forced to shutdown", err)
	}

	// Assume CloseDB exists (if not, OS handles it, but this prevents corruption)
	// We'll leave it out if we aren't absolutely sure it exists to prevent compile error,
	// but normally BadgerDB handles clean exits if closed correctly.
	// We'll call CloseDB() - let's add it to db.go next if missing.
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

	// Limit upload size to 10GB (10 << 30) for large projects
	r.Body = http.MaxBytesReader(w, r.Body, 10<<30)

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

	var configJSON string
	fileCount := 0

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Error reading multipart part: "+err.Error(), http.StatusBadRequest)
			return
		}

		if part.FormName() == "config" {
			buf := new(strings.Builder)
			io.Copy(buf, part)
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
			if errAbs1 != nil || errAbs2 != nil ||
				!strings.HasPrefix(absDestPath, absTmpDir+string(filepath.Separator)) {
				utils.LogWarn(fmt.Sprintf("Path traversal attempt blocked: filename=%q from %s", filename, r.RemoteAddr))
				part.Close()
				continue
			}

			os.MkdirAll(filepath.Dir(destPath), 0755)
			destFile, err := os.Create(destPath)
			if err != nil {
				part.Close()
				continue
			}

			io.Copy(destFile, part)
			destFile.Close()
			part.Close()
			fileCount++
		} else {
			part.Close()
		}
	}

	if fileCount == 0 && configJSON == "" {
		http.Error(w, "No files or config found in upload", http.StatusBadRequest)
		return
	}

	scanID, err := StartScanFromUpload(tmpDir, configJSON)
	if err != nil {
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

	var req struct {
		URL    string        `json:"url"`
		Config WebScanConfig `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	configJSON, _ := json.Marshal(req.Config)
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

	if len(parts) == 0 {
		http.NotFound(w, r)
		return
	}

	scanID := parts[0]

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
		if err := UpdateFindingStatus(scanID, findingID, req.Status); err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
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
		for _, dbID := range req.IDs {
			_ = UpdateFindingStatus(scanID, dbID, req.Status)
		}
		httpJSON(w, http.StatusOK, map[string]string{"status": "updated"})
		return
	}

	// POST /api/scan/:id/stop
	if len(parts) >= 2 && parts[1] == "stop" && r.Method == http.MethodPost {
		handleStopScan(w, r)
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

						io.Copy(w1, f1)
						f1.Close()
					}
					return nil
				}()

				if err != nil {
					httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create zip file"})
					return
				}
			}

			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sentryq_scan_%s.zip\"", scanID))
			w.Header().Set("Content-Type", "application/zip")
			http.ServeFile(w, r, zipPath)
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
			// Report file missing — try to regenerate from DB
			findings, dbErr := GetFindingsForScan(scanID)
			if dbErr != nil {
				utils.LogError(fmt.Sprintf("Failed to load findings for report regeneration (scan %s)", scanID), dbErr)
				httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "report not found and could not be regenerated"})
				return
			}
			if len(findings) > 0 {
				webGenerateReportFiles(scanID, findings, reportsDir)
			}
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=report.%s", format))
		http.ServeFile(w, r, filePath)
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
		appSettings.Lock()
		if s.OllamaHost != "" {
			appSettings.OllamaHost = s.OllamaHost
		}
		if s.DefaultModel != "" {
			appSettings.DefaultModel = s.DefaultModel
		}
		if s.AIProvider != "" {
			appSettings.AIProvider = s.AIProvider
			ai.SetActiveProvider(s.AIProvider)
		}
		appSettings.CustomAPIURL = s.CustomAPIURL
		appSettings.CustomAPIKey = s.CustomAPIKey
		appSettings.CustomModel = s.CustomModel
		appSettings.Unlock()

		// Apply custom endpoint to AI package
		if s.CustomAPIURL != "" {
			ai.SetCustomEndpoint(s.CustomAPIURL, s.CustomAPIKey, s.CustomModel)
		}

		saveSettings()
		httpJSON(w, http.StatusOK, map[string]string{"status": "saved"})
		return
	}

	appSettings.RLock()
	defer appSettings.RUnlock()
	httpJSON(w, http.StatusOK, map[string]interface{}{
		"ollama_host":    appSettings.OllamaHost,
		"default_model":  appSettings.DefaultModel,
		"ai_provider":    appSettings.AIProvider,
		"custom_api_url": appSettings.CustomAPIURL,
		"custom_api_key": appSettings.CustomAPIKey,
		"custom_model":   appSettings.CustomModel,
	})
}

func handleSystemStatus(w http.ResponseWriter, r *http.Request) {

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Check Ollama
	ollamaStatus := "unreachable"
	appSettings.RLock()
	host := appSettings.OllamaHost
	appSettings.RUnlock()
	ollamaClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := ollamaClient.Get(fmt.Sprintf("http://%s/api/version", host))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			ollamaStatus = "connected"
		}
	}

	// Check Go version
	goVersion := runtime.Version()

	// Check git
	gitStatus := "not found"
	if _, err := exec.LookPath("git"); err == nil {
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

func handleModels(w http.ResponseWriter, r *http.Request) {

	// Allow optional host parameter to fetch models from a different Ollama instance
	host := r.URL.Query().Get("host")
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
// We allow any localhost / 127.0.0.1 port so the built-in browser and dev servers work,
// but block cross-origin requests from arbitrary websites.
func allowedOrigin(origin string) bool {
	if origin == "" {
		return true // same-origin requests have no Origin header
	}
	return strings.HasPrefix(origin, "http://localhost:") ||
		strings.HasPrefix(origin, "http://127.0.0.1:") ||
		strings.HasPrefix(origin, "http://localhost") ||
		strings.HasPrefix(origin, "http://127.0.0.1")
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowedOrigin(origin) && origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func httpJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
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


func handleStopScan(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	parts := strings.Split(path, "/")
	scanID := parts[0]

	if err := StopScan(scanID); err != nil {
		httpJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	httpJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
}

func init() {
	// Compute settings path in the user's home directory so the file is not
	// written to whatever the current working directory happens to be, and is
	// only readable by the current user (0600).
	if home, err := os.UserHomeDir(); err == nil {
		settingsPath = filepath.Join(home, ".sentryq", "settings.json")
	} else {
		settingsPath = ".sentryq-settings.json" // fallback if home dir unavailable
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
	apiKey := r.URL.Query().Get("api_key")

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
	rulesDir := "rules"
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
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
		yaml3Unmarshal(data, &rules)
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
	rulesPath := filepath.Join("rules", filename)

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(rulesPath)
		if err != nil {
			httpJSON(w, http.StatusNotFound, map[string]string{"error": "Rule file not found"})
			return
		}
		var rules []YAMLRule
		yaml3Unmarshal(data, &rules)
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
			yaml3Unmarshal(data, &rules)
		}
		rules = append(rules, newRule)
		out, _ := yaml3Marshal(rules)
		os.WriteFile(rulesPath, out, 0644)
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
func yaml3Unmarshal(data []byte, v interface{}) {
	yaml.Unmarshal(data, v)
}

func yaml3Marshal(v interface{}) ([]byte, error) {
	return yaml.Marshal(v)
}

// ──────────────────────────────────────────────────────────
//  Report Cleanup & Startup Checks
// ──────────────────────────────────────────────────────────

// startReportCleanup runs a background loop that deletes report directories older than 48 hours.
func startReportCleanup() {
	const maxAge = 48 * time.Hour
	const interval = 6 * time.Hour

	// Run once immediately on startup
	cleanOldReports(maxAge)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		cleanOldReports(maxAge)
	}
}

// cleanOldReports deletes scan report directories older than maxAge.
func cleanOldReports(maxAge time.Duration) {
	reportsRoot := filepath.Join(os.TempDir(), "sentryQ")
	entries, err := os.ReadDir(reportsRoot)
	if err != nil {
		return // Directory might not exist yet
	}

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

// checkStartupDependencies logs the availability of optional external tools.
func checkStartupDependencies() {
	deps := []struct {
		name    string
		bin     string
		purpose string
	}{
		{"Git", "git", "Repository cloning"},
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

