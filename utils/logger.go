package utils

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/fatih/color"
)

var InfoColor = color.New(color.FgGreen, color.Bold)
var ErrorColor = color.New(color.FgRed, color.Bold)
var WarnColor = color.New(color.FgYellow, color.Bold)

// logMu protects terminal output from concurrent goroutines
// (pattern engine workers, AI workers) interleaving lines.
var logMu sync.Mutex

// isWindowsConsole returns true when running on Windows, where classic cmd.exe
// may not support Unicode/emoji characters without chcp 65001.
func isWindowsConsole() bool {
	return runtime.GOOS == "windows"
}

func LogInfo(msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	if isWindowsConsole() {
		InfoColor.Print("[OK] ")
	} else {
		InfoColor.Print("[✓] ")
	}
	fmt.Println(msg)
}

func LogError(msg string, err error) {
	logMu.Lock()
	defer logMu.Unlock()
	if isWindowsConsole() {
		ErrorColor.Print("[ERR] ")
	} else {
		ErrorColor.Print("[✗] ")
	}
	fmt.Printf("%s: %v\n", msg, err)
}

func LogWarn(msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	if isWindowsConsole() {
		WarnColor.Print("[WARN] ")
	} else {
		WarnColor.Print("[⚠] ")
	}
	fmt.Println(msg)
}

func PrintBanner() {
	fmt.Println()
	color.Set(color.FgMagenta)
	if isWindowsConsole() {
		fmt.Print(`
+----------------------------------------------+
|                                              |
|   [SENTRYQ] AI-POWERED SECURITY SCANNER      |
|                                              |
+----------------------------------------------+
`)
	} else {
		fmt.Print(`
╔══════════════════════════════════════════════╗
║                                              ║
║   🔒 SENTRYQ: AI-POWERED SECURITY SCANNER    ║
║                                              ║
╚══════════════════════════════════════════════╝
`)
	}
	color.Unset()
}
