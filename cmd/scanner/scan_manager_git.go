package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"SentryQ/utils"

	"github.com/google/uuid"
)


// maxFileContentSize is the maximum file size sent to AI for context (10 MB).
const maxFileContentSize = 10 * 1024 * 1024

// maxTotalFileContentsSize is the cumulative cap on file content loaded into the AI
// context map to prevent OOM on large repositories (512 MB).
const maxTotalFileContentsSize = 512 * 1024 * 1024

// getGitBin returns the correct git executable name for the current OS,
// consistent with the pattern used by getTrivyBin, getSemgrepBin, and getOSVBin.
func getGitBin() string {
	if runtime.GOOS == "windows" {
		return "git.exe"
	}
	return "git"
}

// getDefaultRulesDir returns the absolute path to the built-in rules directory.
// It resolves the path relative to the running executable so the binary works
// correctly regardless of the working directory (e.g. installed to /usr/local/bin
// or run from a different directory on Windows). Falls back to the relative "rules"
// path if os.Executable() is unavailable.
func getDefaultRulesDir() string {
	if exePath, err := os.Executable(); err == nil {
		// filepath.EvalSymlinks resolves any symlinks created by package managers.
		if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
			exePath = resolved
		}
		candidate := filepath.Join(filepath.Dir(exePath), "rules")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "rules"
}

// registerScan registers a cancellation function for a scan
func registerScan(scanID string, cancel context.CancelFunc) {
	activeScansMu.Lock()
	defer activeScansMu.Unlock()
	activeScans[scanID] = cancel
}

// unregisterScan removes a scan's cancellation function
func unregisterScan(scanID string) {
	activeScansMu.Lock()
	defer activeScansMu.Unlock()
	delete(activeScans, scanID)
}

// StopScan terminates an active scan
func StopScan(scanID string) error {
	// Cancel and unregister inside a single lock to avoid calling cancel()
	// after it has already been cleaned up by another goroutine.
	activeScansMu.Lock()
	cancel, exists := activeScans[scanID]
	if exists {
		cancel()
		delete(activeScans, scanID)
	}
	activeScansMu.Unlock()

	if !exists {
		return fmt.Errorf("scan %s not found or already completed", scanID)
	}

	utils.LogInfo(fmt.Sprintf("Scan %s terminated by user request", scanID))

	if err := UpdateScanStatus(scanID, "stopped"); err != nil {
		utils.LogError(fmt.Sprintf("Failed to update scan %s status to stopped", scanID), err)
	}
	wsHub.BroadcastLog(scanID, "🛑 Scan terminated by user", "warning")
	wsHub.BroadcastError(scanID, "Scan aborted by user")

	return nil
}

// validateScanConfigHosts checks all user-supplied Ollama host fields for SSRF risk.
// Uses validateOllamaHost (allows LAN, blocks cloud IMDS / link-local).
func validateScanConfigHosts(cfg WebScanConfig) error {
	for _, h := range []string{cfg.OllamaHost, cfg.ConsolidationOllamaHost, cfg.JudgeOllamaHost} {
		if err := validateOllamaHost(h); err != nil {
			return err
		}
	}
	return nil
}

// StartScanFromUpload handles uploaded files
func StartScanFromUpload(targetDir string, configJSON string) (string, error) {
	scanID := uuid.New().String()
	var webCfg WebScanConfig
	if err := json.Unmarshal([]byte(configJSON), &webCfg); err != nil {
		return "", fmt.Errorf("failed to parse config JSON: %v", err)
	}
	if err := validateScanConfigHosts(webCfg); err != nil {
		return "", fmt.Errorf("invalid Ollama host in scan config: %v", err)
	}

	displayName := filepath.Base(targetDir)

	// Strip secrets (e.g. PRToken) before persisting the config JSON to the DB.
	safeConfig, err := json.Marshal(sanitizeConfigForStorage(webCfg))
	if err != nil {
		return "", fmt.Errorf("failed to serialize sanitized config: %v", err)
	}
	if err := CreateScan(scanID, displayName, "upload", string(safeConfig)); err != nil {
		return "", fmt.Errorf("failed to create scan record: %v", err)
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				wsHub.BroadcastError(scanID, fmt.Sprintf("Scan crashed with panic: %v", r))
				if err := UpdateScanStatus(scanID, "failed"); err != nil {
					utils.LogError(fmt.Sprintf("Failed to mark scan %s as failed after panic", scanID), err)
				}
			}
		}()
		timeout := getScanTimeout()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		registerScan(scanID, cancel)
		defer unregisterScan(scanID)
		defer cancel()

		defer os.RemoveAll(targetDir) // Clean up upload temp directory
		runScan(ctx, scanID, targetDir, webCfg)

		// Handle timeout separately from user cancellation (StopScan already
		// updates status to "stopped" before the goroutine reaches this point).
		if ctx.Err() == context.DeadlineExceeded {
			wsHub.BroadcastLog(scanID, fmt.Sprintf("⏰ Scan timed out after %s. Set SENTRYQ_SCAN_TIMEOUT_MINUTES to allow longer scans.", timeout), "error")
			_ = UpdateScanStatus(scanID, "failed")
		}
	}()
	return scanID, nil
}

// forceRemoveAll removes a directory tree. On Windows, git objects are created
// with read-only attributes; os.RemoveAll returns "access denied" for those
// files and leaves the temp dir behind.
//
// Strategy:
//  1. os.Chmod(p, 0700) — Go's Windows implementation sets FILE_ATTRIBUTE_READONLY
//     via SetFileAttributes, which is enough for most cases.
//  2. If os.RemoveAll still fails (e.g. locked junction points), fall back to
//     "attrib -R /S /D" which recursively clears the read-only attribute flag
//     using the built-in Windows CLI tool, then retry RemoveAll.
func forceRemoveAll(path string) {
	if runtime.GOOS == "windows" {
		_ = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			_ = os.Chmod(p, 0700)
			return nil
		})
	}
	if err := os.RemoveAll(path); err != nil && runtime.GOOS == "windows" {
		// Best-effort: strip read-only attributes with the built-in attrib command,
		// then retry. Errors from attrib are intentionally ignored — RemoveAll
		// already failed once, so we log the final outcome only.
		_ = exec.Command("attrib", "-R", "/S", "/D", path).Run()
		if retryErr := os.RemoveAll(path); retryErr != nil {
			utils.LogWarn(fmt.Sprintf("forceRemoveAll: failed to remove %s after attrib retry: %v", path, retryErr))
		}
	}
}

// sanitizeConfigForStorage returns a copy of cfg with secrets zeroed out so
// they are never written to the SQLite database.
// WebhookURLs is zeroed because webhook URLs routinely embed auth tokens in the
// path (Slack /services/T/B/SECRET, Discord /webhooks/ID/SECRET, etc.).
func sanitizeConfigForStorage(cfg WebScanConfig) WebScanConfig {
	cfg.PRToken = ""
	cfg.WebhookURLs = ""
	return cfg
}

// credentialPattern matches embedded credentials in any scheme URL:
// https://user:pass@host, ssh://user:pass@host, etc.
var credentialPattern = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@\s]+:[^@\s]+@`)

// isValidGitURL validates a repository URL with strict structural checks to prevent
// flag injection and embedded-credential leakage.
func isValidGitURL(rawURL string) bool {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return false
	}
	// Prevent flag injection: URL must not start with a hyphen.
	if strings.HasPrefix(trimmed, "-") {
		return false
	}
	// Handle SCP-style SSH URLs (git@github.com:user/repo.git).
	// These are not parseable as standard URLs; do minimal structural validation.
	if strings.HasPrefix(trimmed, "git@") {
		// Must contain exactly one colon separating host from path.
		return strings.Count(trimmed, ":") == 1 && !strings.Contains(trimmed, " ")
	}
	// For http/https/ssh URLs use url.Parse for strict structural validation.
	u, err := url.Parse(trimmed)
	if err != nil {
		return false
	}
	if u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "ssh" {
		return false
	}
	if u.Host == "" {
		return false
	}
	// Reject embedded passwords (https://user:pass@host or ssh://user:pass@host) —
	// they risk leaking into logs and git error output.
	// A bare username without a password is fine for SSH (ssh://git@github.com/...).
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return false
		}
	}
	// Block private/reserved IPs to prevent git-clone-based SSRF.
	// Resolve the hostname and reject any result that falls in RFC1918,
	// loopback, or link-local ranges.
	host := u.Hostname()
	if addrs, err := net.LookupHost(host); err == nil {
		privateRanges := []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"127.0.0.0/8", "::1/128",
			"169.254.0.0/16", "fe80::/10",
			"fc00::/7",
		}
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip == nil {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				return false
			}
			for _, cidr := range privateRanges {
				_, block, parseErr := net.ParseCIDR(cidr)
				if parseErr == nil && block.Contains(ip) {
					return false
				}
			}
		}
	}
	return true
}

// sanitizeGitOutput strips embedded credentials from git command output before
// it is sent to the browser, preventing accidental token/password disclosure.
// Handles https://, ssh://, and other scheme URLs.
func sanitizeGitOutput(output string) string {
	return credentialPattern.ReplaceAllStringFunc(output, func(match string) string {
		// Find the scheme end ("://") to reconstruct the sanitized URL.
		schemeEnd := strings.Index(match, "://")
		if schemeEnd < 0 {
			return "***:***@"
		}
		return match[:schemeEnd+3] + "***:***@"
	})
}

// StartScanFromGit clones a repo and scans it
func StartScanFromGit(repoURL string, configJSON string) (string, error) {
	if !isValidGitURL(repoURL) {
		return "", fmt.Errorf("invalid or unsafe Git URL provided")
	}

	scanID := uuid.New().String()
	var webCfg WebScanConfig
	if err := json.Unmarshal([]byte(configJSON), &webCfg); err != nil {
		return "", fmt.Errorf("failed to parse config JSON: %v", err)
	}
	if err := validateScanConfigHosts(webCfg); err != nil {
		return "", fmt.Errorf("invalid Ollama host in scan config: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "sentryq-scan-"+scanID[:8]+"-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %v", err)
	}

	parts := strings.Split(strings.TrimSuffix(repoURL, ".git"), "/")
	displayName := parts[len(parts)-1]
	if displayName == "" {
		displayName = repoURL
	}

	// Strip secrets before persisting config to the DB.
	safeConfig, err := json.Marshal(sanitizeConfigForStorage(webCfg))
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to serialize sanitized config: %v", err)
	}
	if err := CreateScan(scanID, displayName, "git", string(safeConfig)); err != nil {
		os.RemoveAll(tmpDir) // don't leak the temp dir if we never start the goroutine
		return "", fmt.Errorf("failed to create scan record: %v", err)
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				wsHub.BroadcastError(scanID, fmt.Sprintf("Scan crashed with panic: %v", r))
				if err := UpdateScanStatus(scanID, "failed"); err != nil {
					utils.LogError(fmt.Sprintf("Failed to mark scan %s as failed after panic", scanID), err)
				}
			}
		}()
		defer forceRemoveAll(tmpDir)

		// Register a timeout-bounded context so StopScan (cancel) AND the
		// global scan timeout both terminate the scan + clone gracefully.
		timeout := getScanTimeout()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		registerScan(scanID, cancel)
		defer unregisterScan(scanID)
		defer cancel()

		wsHub.BroadcastLog(scanID, fmt.Sprintf("Cloning repository: %s", repoURL), "phase")
		wsHub.BroadcastProgress(scanID, "Cloning Repository", 5)

		// Derive clone timeout from the scan context so StopScan also
		// terminates the git clone (not just the scan pipeline).
		cloneCtx, cloneCancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cloneCancel()
		cmd := exec.CommandContext(cloneCtx, getGitBin(), "clone", "--depth", "1", "--", repoURL, tmpDir)
		output, err := cmd.CombinedOutput()
		if err != nil {
			if ctx.Err() != nil {
				return // scan was stopped by user or timed out, no need to broadcast error
			}
			wsHub.BroadcastError(scanID, fmt.Sprintf("Git clone failed: %s", sanitizeGitOutput(string(output))))
			if err := UpdateScanStatus(scanID, "failed"); err != nil {
				utils.LogError(fmt.Sprintf("Failed to mark scan %s as failed", scanID), err)
			}
			return
		}

		wsHub.BroadcastLog(scanID, "Repository cloned successfully", "success")

		// Incremental scan: the repo was cloned with --depth 1 (single commit).
		// git diff HEAD~1 and git diff base...HEAD both require additional history,
		// so we deepen the clone before attempting the diff.
		if webCfg.IncrementalScan && len(webCfg.ChangedFiles) == 0 {
			base := webCfg.BaseBranch
			if base == "" {
				base = "main"
			}
			wsHub.BroadcastLog(scanID, "Incremental scan: deepening shallow clone to fetch diff history...", "info")
			// Fetch extra commits so HEAD~1 and remote base branch are available.
			if _, ferr := runGit(tmpDir, "fetch", "--deepen=10", "origin"); ferr != nil {
				wsHub.BroadcastLog(scanID, fmt.Sprintf("Incremental scan: fetch --deepen failed (%v) — running full scan", ferr), "warning")
			} else {
				changed, err := getChangedFiles(tmpDir, base)
				if err != nil {
					wsHub.BroadcastLog(scanID, fmt.Sprintf("Incremental scan: git diff failed (%v) — running full scan", err), "warning")
				} else if len(changed) == 0 {
					wsHub.BroadcastLog(scanID, "Incremental scan: no changed files vs "+base+" — running full scan", "info")
				} else {
					webCfg.ChangedFiles = changed
					wsHub.BroadcastLog(scanID, fmt.Sprintf("Incremental scan: %d changed file(s) vs %s", len(changed), base), "info")
				}
			}
		}

		runScan(ctx, scanID, tmpDir, webCfg)

		// Handle timeout separately from user cancellation.
		if ctx.Err() == context.DeadlineExceeded {
			wsHub.BroadcastLog(scanID, fmt.Sprintf("⏰ Scan timed out after %s. Set SENTRYQ_SCAN_TIMEOUT_MINUTES to allow longer scans.", timeout), "error")
			_ = UpdateScanStatus(scanID, "failed")
		}
	}()

	return scanID, nil
}
