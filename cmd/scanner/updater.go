package main

import (
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

	fmt.Printf("Downloading %s...\n", downloadURL)
	tmpFile, err := downloadToTemp(downloadURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Download failed: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmpFile)

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

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("download incomplete: %w", err)
	}

	return tmp.Name(), nil
}
