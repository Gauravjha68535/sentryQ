package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
)

// webDistDir is the path to the built React frontend.
// It is set at runtime to the correct location.
var webDistDir string

var (
	dashboardFindings []reporter.Finding
	findingsMutex     sync.RWMutex
	startTime         time.Time
	appSettings       = struct {
		sync.RWMutex
		OllamaHost   string `json:"ollama_host"`
		DefaultModel string `json:"default_model"`
	}{
		OllamaHost:   "localhost:11434",
		DefaultModel: "deepseek-r1:7b",
	}
)

// StartWebServer starts the full web application server
func StartWebServer(port int) {
	if err := InitDB(); err != nil {
		utils.LogError("Failed to initialize database", err)
		return
	}

	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/scans", handleListScans)
	mux.HandleFunc("/api/scan/upload", handleUploadScan)
	mux.HandleFunc("/api/scan/git", handleGitScan)
	mux.HandleFunc("/api/settings", handleSettings)
	mux.HandleFunc("/api/system/status", handleSystemStatus)

	// Dynamic scan routes (manual routing for path params)
	mux.HandleFunc("/api/scan/", handleScanRoutes)
	mux.HandleFunc("/ws/scan/", handleWebSocketRoute)

	// Legacy API (for old dashboard)
	mux.HandleFunc("/api/findings", handleGetFindingsLegacy)
	mux.HandleFunc("/api/summary", handleGetSummaryLegacy)
	mux.HandleFunc("/api/charts", handleGetChartDataLegacy)

	// Determine dist dir location
	exeDir, _ := os.Executable()
	baseDir := filepath.Dir(exeDir)
	// Try relative to working directory first (dev mode), then relative to binary
	candidates := []string{
		filepath.Join(".", "web", "dist"),
		filepath.Join(baseDir, "web", "dist"),
		filepath.Join(baseDir, "..", "..", "web", "dist"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			webDistDir = c
			break
		}
	}
	if webDistDir == "" {
		utils.LogWarn("⚠ Web UI dist not found. Run 'cd web && npm run build' first.")
		webDistDir = filepath.Join(".", "web", "dist") // fallback
	}
	utils.LogInfo(fmt.Sprintf("Serving frontend from: %s", webDistDir))

	// Serve React SPA (static files from disk)
	fileServer := http.FileServer(http.Dir(webDistDir))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check if the file exists on disk
		path := filepath.Join(webDistDir, r.URL.Path)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// SPA fallback: serve index.html for all non-API routes
			http.ServeFile(w, r, filepath.Join(webDistDir, "index.html"))
			return
		}
		fileServer.ServeHTTP(w, r)
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

		// Preserve relative path structure
		relPath := fileHeader.Filename
		destPath := filepath.Join(tmpDir, relPath)
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
	if err == nil && resp.StatusCode == 200 {
		ollamaStatus = "connected"
		resp.Body.Close()
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

// ──────────────────────────────────────────────────────────
//  Legacy API Handlers (for backward-compat with old dashboard)
// ──────────────────────────────────────────────────────────

func handleGetFindingsLegacy(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	findingsMutex.RLock()
	defer findingsMutex.RUnlock()
	json.NewEncoder(w).Encode(dashboardFindings)
}

func handleGetSummaryLegacy(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	findingsMutex.RLock()
	defer findingsMutex.RUnlock()
	summary := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(dashboardFindings)}
	for _, f := range dashboardFindings {
		summary[f.Severity]++
	}
	json.NewEncoder(w).Encode(summary)
}

func handleGetChartDataLegacy(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	findingsMutex.RLock()
	defer findingsMutex.RUnlock()
	sevDist := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range dashboardFindings {
		sevDist[f.Severity]++
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"severity": sevDist, "total": len(dashboardFindings)})
}

// UpdateDashboardFindings is called by the main scanner to push new findings (legacy)
func UpdateDashboardFindings(newFindings []reporter.Finding) {
	findingsMutex.Lock()
	defer findingsMutex.Unlock()
	dashboardFindings = make([]reporter.Finding, len(newFindings))
	copy(dashboardFindings, newFindings)
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

func generateChartDashboardHTML(findings []reporter.Finding) string {
	// Simplified chart generation for legacy dashboard
	sevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range findings {
		sevCounts[f.Severity]++
	}
	return fmt.Sprintf(`<div style="text-align:center;color:#94a3b8;padding:20px;">
		<p>Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d</p>
	</div>`, sevCounts["critical"], sevCounts["high"], sevCounts["medium"], sevCounts["low"], sevCounts["info"])
}

func serveDashboardHTML(w http.ResponseWriter, r *http.Request) {
	findingsMutex.RLock()
	findings := make([]reporter.Finding, len(dashboardFindings))
	copy(findings, dashboardFindings)
	findingsMutex.RUnlock()

	summary := reporter.GenerateReportSummary(findings, ".")
	var buf bytes.Buffer
	err := reporter.GenerateHTMLReportToWriter(&buf, findings, summary)
	if err != nil {
		http.Error(w, "Failed to generate report HTML", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

// StartWebDashboard starts the legacy dashboard (backward-compat)
func StartWebDashboard(port int) {
	StartWebServer(port)
}

func init() {
	startTime = time.Now()
}
