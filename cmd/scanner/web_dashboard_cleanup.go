package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"SentryQ/utils"
)

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
