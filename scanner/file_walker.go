package scanner

import (
	"SentryQ/utils"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
			return err
		}

		if info.IsDir() {
			// Skip known non-source directories
			if skipDirs[info.Name()] {
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

// DisplayStats prints the file breakdown to console
func (r *ScanResult) DisplayStats() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Count only recognized source files (exclude "other")
	sourceFiles := 0
	otherFiles := 0
	for lang, count := range r.ByLanguage {
		if lang == "other" {
			otherFiles = count
		} else {
			sourceFiles += count
		}
	}

	if otherFiles > 0 {
		utils.LogInfo(fmt.Sprintf("Found %d source files (%d skipped) across %d folders", sourceFiles, otherFiles, r.TotalFolders))
	} else {
		utils.LogInfo(fmt.Sprintf("Found %d source files across %d folders", sourceFiles, r.TotalFolders))
	}
	utils.LogInfo("Language breakdown:")
	for lang, count := range r.ByLanguage {
		if lang == "other" {
			continue
		}
		utils.LogProgress(lang, fmt.Sprintf("%d files", count))
	}

	// Show skipped extensions summary
	if len(r.SkippedExts) > 0 {
		// Sort by count descending
		type extCount struct {
			ext   string
			count int
		}
		var sorted []extCount
		for ext, count := range r.SkippedExts {
			sorted = append(sorted, extCount{ext, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})

		var parts []string
		for _, ec := range sorted {
			parts = append(parts, fmt.Sprintf("%s(%d)", ec.ext, ec.count))
		}
		utils.LogInfo(fmt.Sprintf("Skipped extensions: %s", strings.Join(parts, ", ")))
	}
}
