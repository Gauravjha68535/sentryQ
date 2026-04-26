package scanner

import (
	"SentryQ/utils"
	"testing"
)

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Unix-style paths (Linux / macOS)
		{"Go test file (unix)", "/home/user/project/main_test.go", true},
		{"JS test file (unix)", "/home/user/project/app.test.js", true},
		{"TS spec file (unix)", "/home/user/project/app.spec.ts", true},
		{"Test directory (unix)", "/home/user/project/test/utils.go", true},
		{"Tests directory (unix)", "/home/user/project/tests/utils.go", true},
		{"Mock directory (unix)", "/home/user/project/mock/service.go", true},
		{"Fixture directory (unix)", "/home/user/project/fixture/data.json", true},
		{"__test__ directory (unix)", "/home/user/project/__test__/foo.py", true},
		{"Normal source file (unix)", "/home/user/project/src/main.go", false},
		{"Normal JS file (unix)", "/home/user/project/src/app.js", false},

		// Windows-style paths (backslashes)
		{"Go test file (windows)", `C:\Users\dev\project\main_test.go`, true},
		{"Test directory (windows)", `C:\Users\dev\project\test\utils.go`, true},
		{"Tests directory (windows)", `C:\Users\dev\project\tests\utils.go`, true},
		{"Mock directory (windows)", `C:\Users\dev\project\mock\service.go`, true},
		{"Fixture directory (windows)", `C:\Users\dev\project\fixture\data.json`, true},
		{"Normal source file (windows)", `C:\Users\dev\project\src\main.go`, false},
		{"Normal JS file (windows)", `C:\Users\dev\project\src\app.js`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.IsTestFile(tt.path)
			if result != tt.expected {
				t.Errorf("IsTestFile(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}
