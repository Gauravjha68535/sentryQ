package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"SentryQ/reporter"
)

const githubReleasesURL = "https://api.github.com/repos/Gauravjha68535/sentryQ/releases/latest"

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
	Body string `json:"body"`
}

// RunUpdate checks for a newer SentryQ release on GitHub and replaces the current
// binary if one is available. The old binary is backed up as <binary>.bak before replacement.
func RunUpdate() {
	currentVersion := reporter.Version
	fmt.Printf("SentryQ v%s — checking for updates...\n", currentVersion)

	release, err := fetchLatestRelease()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update check failed: %v\n", err)
		os.Exit(1)
	}

	latestTag := strings.TrimPrefix(release.TagName, "v")
	if latestTag == currentVersion {
		fmt.Printf("You are already on the latest version (v%s). No update needed.\n", currentVersion)
		return
	}

	fmt.Printf("New version available: v%s (you have v%s)\n", latestTag, currentVersion)
	if release.Body != "" {
		lines := strings.Split(strings.TrimSpace(release.Body), "\n")
		fmt.Println("\nRelease notes:")
		for i, l := range lines {
			if i >= 10 {
				fmt.Println("  ...")
				break
			}
			fmt.Println(" ", l)
		}
		fmt.Println()
	}

	assetName := buildAssetName()
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		fmt.Fprintf(os.Stderr, "No pre-built binary found for %s in release v%s.\n", assetName, latestTag)
		fmt.Fprintf(os.Stderr, "Build from source: git pull && ./build.sh\n")
		os.Exit(1)
	}

	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot determine current binary path: %v\n", err)
		os.Exit(1)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot resolve symlinks for binary path: %v\n", err)
		os.Exit(1)
	}

	// Look for a matching SHA256 checksum asset (e.g. sentryq-linux-amd64.sha256)
	checksumAssetName := assetName + ".sha256"
	var checksumURL string
	for _, asset := range release.Assets {
		if asset.Name == checksumAssetName {
			checksumURL = asset.BrowserDownloadURL
			break
		}
	}

	fmt.Printf("Downloading %s...\n", downloadURL)
	tmpFile, err := downloadToTemp(downloadURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Download failed: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmpFile)

	// Verify SHA256 if a checksum asset was published alongside the binary.
	// Fail hard — a missing match means either corruption or tampering.
	if checksumURL != "" {
		fmt.Println("Verifying SHA256 checksum...")
		expectedHash, err := fetchChecksumFile(checksumURL)
		if err != nil {
			os.Remove(tmpFile)
			fmt.Fprintf(os.Stderr, "Failed to fetch checksum file: %v\n", err)
			os.Exit(1)
		}
		if err := verifyChecksum(tmpFile, expectedHash); err != nil {
			os.Remove(tmpFile)
			fmt.Fprintf(os.Stderr, "Checksum verification FAILED: %v\n", err)
			fmt.Fprintf(os.Stderr, "The downloaded binary has been removed. Do not retry automatically.\n")
			os.Exit(1)
		}
		fmt.Println("Checksum OK.")
	} else {
		// A self-updating security scanner that silently executes unverified binaries is a
		// supply chain attack surface. Refuse to proceed without a checksum.
		os.Remove(tmpFile)
		fmt.Fprintf(os.Stderr, "Update aborted: no %s checksum asset published in release v%s.\n", checksumAssetName, latestTag)
		fmt.Fprintf(os.Stderr, "Build from source instead: git pull && ./build.sh\n")
		os.Exit(1)
	}

	// Back up existing binary
	backupPath := execPath + ".bak"
	if err := os.Rename(execPath, backupPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to back up current binary to %s: %v\n", backupPath, err)
		os.Exit(1)
	}

	// Move new binary into place
	if err := os.Rename(tmpFile, execPath); err != nil {
		// Try to restore backup
		_ = os.Rename(backupPath, execPath)
		fmt.Fprintf(os.Stderr, "Failed to install new binary: %v\n", err)
		os.Exit(1)
	}

	if err := os.Chmod(execPath, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not chmod new binary: %v\n", err)
	}

	fmt.Printf("Updated to v%s. Previous binary saved as %s\n", latestTag, backupPath)
	fmt.Println("Run 'sentryq' to start the new version.")
}

func fetchLatestRelease() (*githubRelease, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", githubReleasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SentryQ/"+reporter.Version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request to GitHub API failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no releases found at %s", githubReleasesURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub release JSON: %w", err)
	}
	return &release, nil
}

func buildAssetName() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	name := fmt.Sprintf("sentryq-%s-%s", goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// fetchChecksumFile downloads a .sha256 file and returns the hex digest.
// The file is expected to be either just a 64-char hex string, or in the
// standard `sha256sum` format: "<hex>  <filename>".
func fetchChecksumFile(url string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	// Handle both "<hex>" and "<hex>  <filename>" formats
	line := strings.TrimSpace(string(raw))
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty checksum file")
	}
	hash := parts[0]
	if len(hash) != 64 {
		return "", fmt.Errorf("unexpected checksum format (got %d chars, want 64)", len(hash))
	}
	return strings.ToLower(hash), nil
}

// verifyChecksum computes the SHA256 of filePath and compares it to expectedHex.
func verifyChecksum(filePath, expectedHex string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !hmac.Equal([]byte(actual), []byte(expectedHex)) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHex, actual)
	}
	return nil
}

func downloadToTemp(url string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "sentryq-update-*")
	if err != nil {
		return "", fmt.Errorf("cannot create temp file: %w", err)
	}
	defer tmp.Close()

	// Cap at 200 MB — no legitimate SentryQ binary will ever be larger.
	// Without a limit, a compromised release URL can exhaust disk space.
	const maxBinarySize = 200 << 20
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, maxBinarySize)); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("download incomplete: %w", err)
	}

	return tmp.Name(), nil
}
