package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"SentryQ/reporter"
	"SentryQ/utils"
)

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

// validScanIDRe allows UUID v4 format AND the "cli-<uuid>" prefix used by CLI scans.
var validScanIDRe = regexp.MustCompile(`^(?:cli-)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func handleScanRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	parts := strings.Split(path, "/")
	scanID := parts[0]
	if scanID == "" {
		http.NotFound(w, r)
		return
	}
	// Validate scan ID format to prevent path traversal via crafted scan IDs.
	if !validScanIDRe.MatchString(scanID) {
		http.Error(w, "invalid scan ID format", http.StatusBadRequest)
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

	// validTriageStatuses is the closed set of allowed triage values.
	// Enforced here to prevent garbage data from reaching the DB and corrupting
	// report filtering, triage views, and the ML feedback system.
	validTriageStatuses := map[string]bool{
		"open": true, "resolved": true, "ignored": true, "false_positive": true,
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
		if !validTriageStatuses[req.Status] {
			httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status: must be open, resolved, ignored, or false_positive"})
			return
		}
		// Fetch finding before update so we have ruleID/filePath/severity for ML feedback.
		finding, fetchErr := GetFindingByID(scanID, findingID)
		if err := UpdateFindingStatus(scanID, findingID, req.Status); err != nil {
			// UpdateFindingStatus returns an error when 0 rows matched — this means
			// the finding ID does not belong to this scan (cross-scan ID attempt).
			httpJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
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
		if !validTriageStatuses[req.Status] {
			httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status: must be open, resolved, ignored, or false_positive"})
			return
		}
		// Collect successfully updated findings for a single batched ML feedback write.
		// Per-finding load+save in a loop causes a data race under concurrent bulk requests.
		var failed []int
		var feedbackFindings []reporter.Finding
		for _, dbID := range req.IDs {
			finding, fetchErr := GetFindingByID(scanID, dbID)
			if err := UpdateFindingStatus(scanID, dbID, req.Status); err != nil {
				utils.LogWarn(fmt.Sprintf("bulk-status: failed to update finding %d: %v", dbID, err))
				failed = append(failed, dbID)
				continue
			}
			if fetchErr == nil {
				feedbackFindings = append(feedbackFindings, finding)
			}
		}
		if len(feedbackFindings) > 0 {
			recordMLFeedbackBatch(feedbackFindings, req.Status)
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

					// compliance-nist.json is generated on-demand; pre-generate it here
				// so the "download all" bundle is complete.
				if nistFindings, nistErr := GetFindingsForScan(scanID); nistErr == nil {
					nistPath := filepath.Join(reportsDir, "compliance-nist.json")
					reporter.GenerateComplianceReport(nistPath, scanID, nistFindings, reporter.FrameworkNIST800) //nolint:errcheck
				}
				filesToZip := []string{"report.html", "report.csv", "report.pdf", "report.sarif", "sbom.cdx.json", "compliance-owasp.html", "compliance-pci.json", "compliance-nist.json"}
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
		case "sbom":
			filePath = filepath.Join(reportsDir, "sbom.cdx.json")
			contentType = "application/json"
		case "compliance-owasp":
			filePath = filepath.Join(reportsDir, "compliance-owasp.html")
			contentType = "text/html"
		case "compliance-pci":
			filePath = filepath.Join(reportsDir, "compliance-pci.json")
			contentType = "application/json"
		case "compliance-nist":
			// Generate on demand since it's less common
			findings, _ := GetFindingsForScan(scanID)
			filePath = filepath.Join(reportsDir, "compliance-nist.json")
			reporter.GenerateComplianceReport(filePath, scanID, findings, reporter.FrameworkNIST800)
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
				webGenerateReportFiles(scanID, findings, targetName, WebScanConfig{})
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
	if !validScanIDRe.MatchString(scanID) {
		http.Error(w, "invalid scan ID format", http.StatusBadRequest)
		return
	}
	wsHub.HandleWS(w, r, scanID)
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

// handleScanCompliance handles GET /api/scan/compliance?id=<scanID>&framework=owasp|pci|nist
func handleScanCompliance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scanID := r.URL.Query().Get("id")
	if scanID == "" {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "id parameter required"})
		return
	}
	// Validate format to prevent path traversal via crafted scan IDs in filepath.Join.
	if !validScanIDRe.MatchString(scanID) {
		http.Error(w, "invalid scan ID format", http.StatusBadRequest)
		return
	}
	fw := r.URL.Query().Get("framework")

	findings, err := GetFindingsForScan(scanID)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var framework reporter.ComplianceFramework
	switch strings.ToLower(fw) {
	case "pci":
		framework = reporter.FrameworkPCIDSS
	case "nist":
		framework = reporter.FrameworkNIST800
	default:
		framework = reporter.FrameworkOWASP10
	}

	// Generate in-memory (no file write needed for API response)
	tmpFile := filepath.Join(os.TempDir(), "sentryQ", scanID, "compliance-api-"+fw+".json")
	_ = os.MkdirAll(filepath.Dir(tmpFile), 0700)
	report, err := reporter.GenerateComplianceReport(tmpFile, scanID, findings, framework)
	if err != nil && report == nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpJSON(w, http.StatusOK, report)
}

// handleScansDiff handles GET /api/scans/diff?a=<scanID>&b=<scanID>
func handleScansDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idA := r.URL.Query().Get("a")
	idB := r.URL.Query().Get("b")
	if idA == "" || idB == "" {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "a and b parameters required"})
		return
	}
	if !validScanIDRe.MatchString(idA) || !validScanIDRe.MatchString(idB) {
		http.Error(w, "invalid scan ID format", http.StatusBadRequest)
		return
	}

	findingsA, err := GetFindingsForScan(idA)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load scan A: " + err.Error()})
		return
	}
	findingsB, err := GetFindingsForScan(idB)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load scan B: " + err.Error()})
		return
	}

	fingerprint := func(f reporter.Finding) string {
		return strings.ToLower(f.FilePath) + "|" + strings.ToLower(f.IssueName)
	}

	setA := make(map[string]bool, len(findingsA))
	for _, f := range findingsA {
		setA[fingerprint(f)] = true
	}
	setB := make(map[string]bool, len(findingsB))
	for _, f := range findingsB {
		setB[fingerprint(f)] = true
	}

	var newFindings, fixedFindings, persistingFindings []reporter.Finding

	for _, f := range findingsB {
		fp := fingerprint(f)
		if setA[fp] {
			persistingFindings = append(persistingFindings, f)
		} else {
			newFindings = append(newFindings, f)
		}
	}
	for _, f := range findingsA {
		if !setB[fingerprint(f)] {
			fixedFindings = append(fixedFindings, f)
		}
	}

	countSev := func(findings []reporter.Finding, sev string) int {
		n := 0
		for _, f := range findings {
			if strings.ToLower(f.Severity) == sev {
				n++
			}
		}
		return n
	}
	deltaCritical := countSev(newFindings, "critical") - countSev(fixedFindings, "critical")
	deltaHigh := countSev(newFindings, "high") - countSev(fixedFindings, "high")

	httpJSON(w, http.StatusOK, map[string]interface{}{
		"total_a":             len(findingsA),
		"total_b":             len(findingsB),
		"new_findings":        newFindings,
		"fixed_findings":      fixedFindings,
		"persisting_findings": persistingFindings,
		"delta_critical":      deltaCritical,
		"delta_high":          deltaHigh,
	})
}
