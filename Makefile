.PHONY: all build build-windows clean test test-cover

# Default build target
all: build

# Standard Linux build
# Note: CGO is required because go-tree-sitter embeds C sources.
# CGO_ENABLED=1 is the default on native builds but we set it explicitly
# so that Docker/CI builders with non-standard defaults don't break silently.
build:
	@mkdir -p bin
	CGO_ENABLED=1 go build -trimpath -o bin/sentryq ./cmd/scanner

# Windows cross-compilation target
# Requires mingw-w64 for CGO cross-compilation (go-tree-sitter C sources).
# Install on Ubuntu/Debian: sudo apt-get install mingw-w64
build-windows:
	@mkdir -p bin
	@command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || { \
		echo "ERROR: x86_64-w64-mingw32-gcc not found."; \
		echo "Install it with: sudo apt-get install mingw-w64"; \
		exit 1; \
	}
	@echo "Building for Windows (mingw-w64 found)..."
	CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -trimpath -o bin/sentryq.exe ./cmd/scanner

# Clean built binaries
clean:
	@rm -rf bin/

# Run tests
test:
	go test ./...

# Run tests with coverage report
test-cover:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out
