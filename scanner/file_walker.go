package scanner

import (
	"SentryQ/utils"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// skipDirs contains directories that should never be scanned
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	"__pycache__": true, ".venv": true, "venv": true,
	".idea": true, ".vscode": true, ".svn": true,
	"dist": true, "build": true, ".next": true,
}

// skipFiles contains filenames that should never be scanned (scanner metadata)
var skipFiles = map[string]bool{
	".scanner-ai-stats.json":   true,
	".threat-intel-cache.json": true,
}

// knownFilenames maps extensionless filenames to their language
var knownFilenames = map[string]string{
	"dockerfile":  "dockerfile",
	"makefile":    "makefile",
	"vagrantfile": "ruby",
	"gemfile":     "ruby",
	"rakefile":    "ruby",
	"jenkinsfile": "groovy",
	"procfile":    "yaml",
}

// ScanResult holds file counts and findings
type ScanResult struct {
	TotalFiles   int
	TotalFolders int
	ByLanguage   map[string]int
	FilePaths    map[string][]string
	SkippedExts  map[string]int
	mu           sync.RWMutex
}

// WalkDirectory scans the target directory with parallel processing
func WalkDirectory(root string) (*ScanResult, error) {
	result := &ScanResult{
		ByLanguage:  make(map[string]int),
		FilePaths:   make(map[string][]string),
		SkippedExts: make(map[string]int),
	}

	var wg sync.WaitGroup
	fileChan := make(chan string, 100)

	// Worker pool
	numWorkers := 4
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				processFile(path, result)
			}
		}()
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			utils.LogWarn(fmt.Sprintf("Skipping unreadable path %s: %v", path, err))
			return nil
		}

		if info.IsDir() {
			// Skip known non-source directories.
			// Normalise to lowercase so "Node_Modules" or "BUILD" are caught on
			// case-sensitive Linux filesystems the same as on Windows.
			if skipDirs[strings.ToLower(info.Name())] {
				return filepath.SkipDir
			}
			result.mu.Lock()
			result.TotalFolders++
			result.mu.Unlock()
			return nil
		}

		result.mu.Lock()
		result.TotalFiles++
		result.mu.Unlock()

		fileChan <- path
		return nil
	})

	close(fileChan)
	wg.Wait()

	if err != nil {
		utils.LogWarn(fmt.Sprintf("Directory walk encountered errors — scan results may be partial: %v", err))
	}

	return result, err
}

func processFile(path string, result *ScanResult) {
	// Skip scanner metadata files
	baseName := strings.ToLower(filepath.Base(path))
	if skipFiles[baseName] {
		return
	}

	ext := filepath.Ext(path)
	lang := utils.GetLanguage(ext)

	// If extension not recognized, try matching by filename (Dockerfile, Makefile, etc.)
	if lang == "unknown" {
		if fileLang, ok := knownFilenames[baseName]; ok {
			lang = fileLang
		}
	}

	result.mu.Lock()
	if lang != "unknown" {
		result.ByLanguage[lang]++
		result.FilePaths[lang] = append(result.FilePaths[lang], path)
	} else {
		result.ByLanguage["other"]++
		skipExt := ext
		if skipExt == "" {
			skipExt = filepath.Base(path)
		}
		result.SkippedExts[skipExt]++
	}
	result.mu.Unlock()
}

