package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// SentryQIgnore holds compiled patterns from a .sentryqignore file.
// Syntax matches .gitignore:
//   - Blank lines and lines starting with # are ignored
//   - Trailing / means directory-only match
//   - Leading ! negates the pattern (un-ignore)
//   - * matches anything except /
//   - ** matches anything including /
//   - Pattern without / matches any path segment (like filename glob)
//   - Pattern with / is anchored to the root of the scanned directory
type SentryQIgnore struct {
	patterns []ignorePattern
}

type ignorePattern struct {
	raw     string // cleaned pattern (no leading !, no trailing /)
	negate  bool   // true if pattern started with !
	dirOnly bool   // true if pattern ended with /
	rooted  bool   // true if pattern contains / (anchored to scan root)
}

// LoadIgnoreFile reads .sentryqignore from the target directory.
// Returns nil if no file exists (not an error — ignore file is optional).
func LoadIgnoreFile(targetDir string) *SentryQIgnore {
	candidates := []string{
		filepath.Join(targetDir, ".sentryqignore"),
		filepath.Join(targetDir, "sentryqignore"),
	}
	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		ig := &SentryQIgnore{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			pat := ignorePattern{}
			if strings.HasPrefix(line, "!") {
				pat.negate = true
				line = line[1:]
			}
			if strings.HasSuffix(line, "/") {
				pat.dirOnly = true
				line = strings.TrimSuffix(line, "/")
			}
			// A pattern is rooted if it contains a slash (excluding trailing)
			if strings.Contains(line, "/") {
				pat.rooted = true
			}
			pat.raw = line
			ig.patterns = append(ig.patterns, pat)
		}
		f.Close()
		return ig
	}
	return nil
}

// Matches reports whether relPath (relative to scan root, using OS separators)
// should be excluded from scanning based on the ignore patterns.
// isDir should be true when relPath refers to a directory.
func (ig *SentryQIgnore) Matches(relPath string, isDir bool) bool {
	if ig == nil || len(ig.patterns) == 0 {
		return false
	}
	// Normalise to forward slashes for consistent matching
	rel := filepath.ToSlash(relPath)
	base := filepath.Base(rel)

	matched := false
	for _, pat := range ig.patterns {
		if pat.dirOnly && !isDir {
			continue
		}
		p := pat.raw
		var hit bool

		if strings.Contains(p, "**") {
			hit = matchDoublestar(p, rel)
		} else if pat.rooted {
			// Anchored to root — match rel directly
			hit, _ = filepath.Match(p, rel)
			// Also match as prefix so "src/vendor" matches "src/vendor/deep/file"
			if !hit {
				hit = strings.HasPrefix(rel, p+"/") || rel == p
			}
		} else {
			// Unanchored — match base name or any path segment
			hit, _ = filepath.Match(p, base)
			if !hit {
				// Try matching each path component
				for _, seg := range strings.Split(rel, "/") {
					if m, _ := filepath.Match(p, seg); m {
						hit = true
						break
					}
				}
			}
		}

		if hit {
			matched = !pat.negate
		}
	}
	return matched
}

// matchDoublestar handles patterns containing ** (recursive glob).
// Examples: **/*.min.js, src/**/test, **/vendor
func matchDoublestar(pattern, path string) bool {
	// Split pattern into parts around **
	parts := strings.SplitN(pattern, "**", 2)
	prefix := strings.TrimSuffix(parts[0], "/")
	suffix := strings.TrimPrefix(parts[1], "/")

	switch {
	case prefix == "" && suffix == "":
		return true // ** matches everything
	case prefix == "":
		// **/<suffix> — suffix must match the basename or end of path
		if m, _ := filepath.Match(suffix, filepath.Base(path)); m {
			return true
		}
		// Check if any trailing portion matches
		for i := range path {
			if path[i] == '/' {
				if m, _ := filepath.Match(suffix, path[i+1:]); m {
					return true
				}
			}
		}
		return false
	case suffix == "":
		// <prefix>/** — path must start with prefix
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	default:
		// <prefix>/**/<suffix>
		if !strings.HasPrefix(path, prefix+"/") {
			return false
		}
		rest := path[len(prefix)+1:]
		if m, _ := filepath.Match(suffix, rest); m {
			return true
		}
		// Check if suffix matches any trailing segment
		for i := range rest {
			if rest[i] == '/' {
				if m, _ := filepath.Match(suffix, rest[i+1:]); m {
					return true
				}
			}
		}
		return false
	}
}
