package utils

import (
	"fmt"
	"runtime"

	"github.com/fatih/color"
)

var InfoColor = color.New(color.FgGreen, color.Bold)
var ErrorColor = color.New(color.FgRed, color.Bold)
var WarnColor = color.New(color.FgYellow, color.Bold)

// isWindowsConsole returns true when running on Windows, where classic cmd.exe
// may not support Unicode/emoji characters without chcp 65001.
func isWindowsConsole() bool {
	return runtime.GOOS == "windows"
}

func LogInfo(msg string) {
	if isWindowsConsole() {
		InfoColor.Print("[OK] ")
	} else {
		InfoColor.Print("[✓] ")
	}
	fmt.Println(msg)
}

func LogError(msg string, err error) {
	if isWindowsConsole() {
		ErrorColor.Print("[ERR] ")
	} else {
		ErrorColor.Print("[✗] ")
	}
	fmt.Printf("%s: %v\n", msg, err)
}

func LogWarn(msg string) {
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
