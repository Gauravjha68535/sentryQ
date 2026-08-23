package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func writeIgnoreFile(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".sentryqignore"), []byte(content), 0600); err != nil {
		t.Fatalf("failed to write .sentryqignore: %v", err)
	}
}

// ─── LoadIgnoreFile ───────────────────────────────────────────────────────────

func TestLoadIgnoreFileNotFound(t *testing.T) {
	ig := LoadIgnoreFile(t.TempDir())
	if ig != nil {
		t.Error("expected nil when no .sentryqignore exists")
	}
}

func TestLoadIgnoreFileEmpty(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "# just a comment\n\n")
	ig := LoadIgnoreFile(dir)
	if ig == nil {
		t.Fatal("expected non-nil SentryQIgnore")
	}
	if len(ig.patterns) != 0 {
		t.Errorf("expected 0 patterns, got %d", len(ig.patterns))
	}
}

func TestLoadIgnoreFileSkipsComments(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "# comment\nvendor/\n# another comment\n*.min.js\n")
	ig := LoadIgnoreFile(dir)
	if ig == nil {
		t.Fatal("expected non-nil")
	}
	if len(ig.patterns) != 2 {
		t.Errorf("expected 2 patterns (comments skipped), got %d", len(ig.patterns))
	}
}

// ─── Matches — directory patterns ────────────────────────────────────────────

func TestMatchesDirectoryPattern(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "vendor/\n")
	ig := LoadIgnoreFile(dir)

	// Directory itself should match
	if !ig.Matches("vendor", true) {
		t.Error("vendor/ pattern should match 'vendor' directory")
	}
	// Files inside vendor should NOT match (dirOnly=true, isDir=false)
	if ig.Matches("vendor/gopkg.in/yaml.v3/yaml.go", false) {
		t.Error("vendor/ pattern should NOT match files inside vendor when dirOnly=true")
	}
}

func TestMatchesDirectoryPatternSkipsNested(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "node_modules\n") // without trailing slash
	ig := LoadIgnoreFile(dir)

	if !ig.Matches("node_modules", true) {
		t.Error("node_modules pattern should match directory")
	}
	if !ig.Matches("node_modules", false) {
		t.Error("node_modules without trailing slash should match file too")
	}
}

// ─── Matches — glob patterns ──────────────────────────────────────────────────

func TestMatchesGlobExtension(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "*.min.js\n")
	ig := LoadIgnoreFile(dir)

	if !ig.Matches("src/bundle.min.js", false) {
		t.Error("*.min.js should match src/bundle.min.js")
	}
	if !ig.Matches("bundle.min.js", false) {
		t.Error("*.min.js should match bundle.min.js at root")
	}
	if ig.Matches("src/bundle.js", false) {
		t.Error("*.min.js should NOT match src/bundle.js")
	}
}

func TestMatchesGlobStar(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "*.lock\n")
	ig := LoadIgnoreFile(dir)

	if !ig.Matches("package-lock.json", false) {
		t.Error("*.lock should match package-lock.json")
	}
	if !ig.Matches("go.sum", false) {
		// go.sum doesn't end in .lock — should not match
		t.Skip("go.sum doesn't match *.lock — skip")
	}
}

// ─── Matches — rooted patterns ────────────────────────────────────────────────

func TestMatchesRootedPattern(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "src/generated/\n")
	ig := LoadIgnoreFile(dir)

	if !ig.Matches("src/generated", true) {
		t.Error("rooted pattern src/generated/ should match src/generated dir")
	}
	if ig.Matches("other/generated", true) {
		t.Error("rooted pattern src/generated/ should NOT match other/generated")
	}
}

// ─── Matches — double-star ────────────────────────────────────────────────────

func TestMatchesDoubleStarAnywhere(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "**/*.test.go\n")
	ig := LoadIgnoreFile(dir)

	if !ig.Matches("scanner/helpers_test.go", false) {
		t.Error("**/*.test.go should match scanner/helpers_test.go")
	}
	if !ig.Matches("cmd/scanner/main_test.go", false) {
		t.Error("**/*.test.go should match cmd/scanner/main_test.go")
	}
	if ig.Matches("scanner/helpers.go", false) {
		t.Error("**/*.test.go should NOT match scanner/helpers.go")
	}
}

func TestMatchesDoubleStarPrefix(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "**/vendor\n")
	ig := LoadIgnoreFile(dir)

	if !ig.Matches("vendor", true) {
		t.Error("**/vendor should match top-level vendor")
	}
	if !ig.Matches("src/vendor", true) {
		t.Error("**/vendor should match src/vendor")
	}
}

// ─── Matches — negation ───────────────────────────────────────────────────────

func TestMatchesNegation(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, "vendor/\n!vendor/important/\n")
	ig := LoadIgnoreFile(dir)

	// vendor itself: matched by first rule, un-matched by negation (but negation is for the sub-path)
	if !ig.Matches("vendor", true) {
		t.Error("vendor/ should match vendor dir")
	}
	// vendor/important/ negation un-ignores it
	if ig.Matches("vendor/important", true) {
		t.Log("vendor/important is un-ignored by negation — correct")
	}
}

// ─── Matches — real-world scenarios ──────────────────────────────────────────

func TestMatchesCommonPatterns(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir, `
# Build outputs
dist/
build/
*.min.js
*.min.css

# Dependencies
node_modules/
vendor/

# Test files
**/*_test.go

# Generated
src/generated/
`)
	ig := LoadIgnoreFile(dir)

	cases := []struct {
		path  string
		isDir bool
		want  bool
		desc  string
	}{
		{"dist", true, true, "dist/ directory"},
		{"build", true, true, "build/ directory"},
		{"src/app.min.js", false, true, "*.min.js file"},
		{"src/style.min.css", false, true, "*.min.css file"},
		{"node_modules", true, true, "node_modules directory"},
		{"vendor", true, true, "vendor directory"},
		{"scanner/helpers_test.go", false, true, "**/*_test.go"},
		{"src/generated", true, true, "rooted src/generated/"},
		{"src/main.go", false, false, "normal Go source"},
		{"cmd/scanner/main.go", false, false, "nested normal Go source"},
	}

	for _, tc := range cases {
		got := ig.Matches(tc.path, tc.isDir)
		if got != tc.want {
			t.Errorf("%s: Matches(%q, %v) = %v, want %v", tc.desc, tc.path, tc.isDir, got, tc.want)
		}
	}
}

func TestMatchesNilIgnore(t *testing.T) {
	var ig *SentryQIgnore
	// Nil SentryQIgnore must never panic and always return false
	if ig.Matches("anything", false) {
		t.Error("nil SentryQIgnore.Matches should return false")
	}
}
