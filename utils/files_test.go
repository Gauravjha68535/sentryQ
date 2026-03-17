package utils

import "testing"

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
		{"__tests__ directory (unix)", "/home/user/project/__tests__/bar.js", true},
		{"__mocks__ directory (unix)", "/home/user/project/__mocks__/api.js", true},
		{"Testdata directory (unix)", "/home/user/project/testdata/input.txt", true},
		{"Spec directory (unix)", "/home/user/project/spec/feature.rb", true},
		{"Specs directory (unix)", "/home/user/project/specs/feature.rb", true},
		{"Fixtures directory (unix)", "/home/user/project/fixtures/data.yaml", true},
		{"node_modules (unix)", "/home/user/project/node_modules/pkg/index.js", true},
		{"Normal source file (unix)", "/home/user/project/src/main.go", false},
		{"Normal JS file (unix)", "/home/user/project/src/app.js", false},
		{"Python file (unix)", "/home/user/project/app.py", false},
		{"Configuration file (unix)", "/home/user/project/config/settings.json", false},

		// Windows-style paths (backslashes)
		{"Go test file (windows)", `C:\Users\dev\project\main_test.go`, true},
		{"Test directory (windows)", `C:\Users\dev\project\test\utils.go`, true},
		{"Tests directory (windows)", `C:\Users\dev\project\tests\utils.go`, true},
		{"Mock directory (windows)", `C:\Users\dev\project\mock\service.go`, true},
		{"Fixture directory (windows)", `C:\Users\dev\project\fixture\data.json`, true},
		{"Normal source file (windows)", `C:\Users\dev\project\src\main.go`, false},
		{"Normal JS file (windows)", `C:\Users\dev\project\src\app.js`, false},

		// Edge cases
		{"File with test in name but not test file", "/home/user/project/newtest.go", false},
		{"File with spec in name but not spec file", "/home/user/project/specsheet.csv", false},
		{"controller (unix)", "/home/user/project/controllers/user.go", false},
		{"handler (unix)", "/home/user/project/handlers/auth.go", false},
		{"model (unix)", "/home/user/project/models/user.py", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTestFile(tt.path)
			if result != tt.expected {
				t.Errorf("IsTestFile(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}
