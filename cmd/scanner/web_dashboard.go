package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"QWEN_SCR_24_FEB_2026/ai"
	"QWEN_SCR_24_FEB_2026/internal/ui"
	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
)

// staticFS is the embedded React build output (lazy initialized)
var staticFS fs.FS
var staticFSOnce sync.Once
var staticFSError error

var (
	startTime   time.Time
	appSettings = struct {
		sync.RWMutex
		OllamaHost   string `json:"ollama_host"`
		DefaultModel string `json:"default_model"`
	}{
		OllamaHost:   "localhost:11434",
		DefaultModel: "qwen2.5-coder:7b",
	}
)

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
	mux.HandleFunc("/api/chat", handleChat)

	// Dynamic scan routes (manual routing for path params)
	mux.HandleFunc("/api/scan/", handleScanRoutes)
	mux.HandleFunc("/ws/scan/", handleWebSocketRoute)

	// Serve React SPA (embedded static files)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If embedded UI is not available, return API-only mode message
		if staticFS == nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "QWEN Scanner API Only Mode\n\nWeb UI not embedded.\nRun './build.sh' to embed the web UI.")
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

	addr := fmt.Sprintf("localhost:%d", port)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	utils.LogInfo(fmt.Sprintf("🌐 QWEN Scanner Web UI starting on http://%s", addr))

	// Auto-open browser
	go openBrowser("http://" + addr)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		utils.LogError("Web server failed", err)
	}
}

// ──────────────────────────────────────────────────────────
//  API Handlers
// ──────────────────────────────────────────────────────────

func handleListScans(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
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
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart (max 500MB)
	r.ParseMultipartForm(500 << 20)

	configJSON := r.FormValue("config")

	// Save uploaded files to a temp directory
	tmpDir, err := os.MkdirTemp("", "qwen-upload-")
	if err != nil {
		http.Error(w, "Failed to create temp directory", http.StatusInternalServerError)
		return
	}

	files := r.MultipartForm.File["files"]
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			continue
		}

		// Preserve relative path structure with path traversal protection
		relPath := filepath.Clean(fileHeader.Filename)
		destPath := filepath.Join(tmpDir, relPath)
		// Ensure destPath stays within tmpDir
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(tmpDir)) {
			file.Close()
			continue // Skip files that would escape the temp directory
		}
		os.MkdirAll(filepath.Dir(destPath), 0755)

		destFile, err := os.Create(destPath)
		if err != nil {
			file.Close()
			continue
		}

		io.Copy(destFile, file)
		destFile.Close()
		file.Close()
	}

	scanID, err := StartScanFromUpload(tmpDir, configJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	httpJSON(w, http.StatusOK, map[string]string{"scan_id": scanID})
}

func handleGitScan(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
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
	setCORS(w)
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

	// GET /api/scan/:id/findings
	if len(parts) >= 2 && parts[1] == "findings" {
		findings, err := GetFindingsForScan(scanID)
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
		reportsDir := filepath.Join(os.TempDir(), "qwen-reports", scanID)
		var filePath string
		var contentType string

		// Check for "all" format to return a ZIP of all reports
		if format == "all" {
			zipPath := filepath.Join(reportsDir, "reports_bundle.zip")

			// Create the zip file if it doesn't exist
			if _, err := os.Stat(zipPath); os.IsNotExist(err) {
				zipFile, err := os.Create(zipPath)
				if err != nil {
					httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create zip file"})
					return
				}
				defer zipFile.Close()

				archive := zip.NewWriter(zipFile)
				defer archive.Close()

				filesToZip := []string{"report.html", "report.csv", "report.pdf"}
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
			}

			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"qwen_scan_%s.zip\"", scanID))
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
		default:
			http.NotFound(w, r)
			return
		}

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			// Try to regenerate
			findings, _ := GetFindingsForScan(scanID)
			if len(findings) > 0 {
				webGenerateReportFiles(scanID, findings, ".")
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
	setCORS(w)
	if r.Method == http.MethodPut {
		var s struct {
			OllamaHost   string `json:"ollama_host"`
			DefaultModel string `json:"default_model"`
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
		appSettings.Unlock()
		httpJSON(w, http.StatusOK, map[string]string{"status": "saved"})
		return
	}

	appSettings.RLock()
	defer appSettings.RUnlock()
	httpJSON(w, http.StatusOK, map[string]interface{}{
		"ollama_host":   appSettings.OllamaHost,
		"default_model": appSettings.DefaultModel,
	})
}

func handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	setCORS(w)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Check Ollama
	ollamaStatus := "unreachable"
	appSettings.RLock()
	host := appSettings.OllamaHost
	appSettings.RUnlock()
	resp, err := http.Get(fmt.Sprintf("http://%s/api/version", host))
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
	setCORS(w)

	appSettings.RLock()
	ai.SetOllamaHost(appSettings.OllamaHost)
	appSettings.RUnlock()

	models := ai.GetInstalledModels()
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

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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
		utils.LogInfo(fmt.Sprintf("Open http://%s in your browser", url))
	}
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Messages []ai.ChatMessage `json:"messages"`
		ScanID   string           `json:"scan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	appSettings.RLock()
	model := appSettings.DefaultModel
	host := appSettings.OllamaHost
	appSettings.RUnlock()

	ai.SetOllamaHost(host)

	// Add system context if this is the first message or if context is missing
	hasSystem := false
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			hasSystem = true
			break
		}
	}

	if !hasSystem {
		systemMsg := ai.ChatMessage{
			Role: "system",
			Content: `You are the QWEN Security Assistant, an elite cybersecurity expert. 
You are integrated into the QWEN Security Scanner. 
Your goal is to help the user understand security vulnerabilities, explain scan reports, and provide high-quality remediation advice.
When explaining a specific finding, be technical, precise, and provide clear code examples for fixes.
Assume the user is a developer or security engineer.`,
		}

		// Inject scan context if scanID is provided
		if req.ScanID != "" {
			findings, _ := GetFindingsForScan(req.ScanID)
			if len(findings) > 0 {
				contextPrefix := fmt.Sprintf("\nCONTEXT: The current scan (ID: %s) has found %d issues.", req.ScanID, len(findings))
				systemMsg.Content += contextPrefix
			}
		}

		req.Messages = append([]ai.ChatMessage{systemMsg}, req.Messages...)
	}

	resp, err := ai.GenerateChatResponse(model, req.Messages)
	if err != nil {
		http.Error(w, fmt.Sprintf("AI error: %v", err), http.StatusInternalServerError)
		return
	}

	httpJSON(w, http.StatusOK, resp)
}

func init() {
	startTime = time.Now()
}
