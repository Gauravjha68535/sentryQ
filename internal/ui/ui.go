package ui

import (
	"embed"
	"errors"
	"io/fs"
	"sync"
)

// webUIEmbed is the embedded React build output.
// This embeds all files from the dist directory at compile time.
//
//go:embed all:dist
var webUIEmbed embed.FS

// Cached filesystem for static assets to avoid recomputing fs.Sub on every call.
// staticFSErr is package-level so the original error survives beyond the first call.
var (
	staticFS     fs.FS
	staticFSErr  error
	staticFSOnce sync.Once
)

var errStaticFSNotInitialized = errors.New("static filesystem not initialized")

// StaticFS returns the embedded static filesystem for the web UI.
// The returned fs.FS is rooted at the "dist" directory.
// This function is safe for concurrent use and caches the result.
//
// Returns an error if the embedded filesystem was not properly initialized.
func StaticFS() (fs.FS, error) {
	staticFSOnce.Do(func() {
		staticFS, staticFSErr = fs.Sub(webUIEmbed, "dist")
		if staticFSErr != nil {
			staticFS = nil
		}
	})

	if staticFS == nil {
		return nil, errors.Join(errStaticFSNotInitialized, staticFSErr)
	}

	return staticFS, nil
}

