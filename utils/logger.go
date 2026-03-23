package utils

import (
	"fmt"
	"log"
	"os"

	"github.com/fatih/color"
)

var Logger *log.Logger
var InfoColor = color.New(color.FgGreen, color.Bold)
var ErrorColor = color.New(color.FgRed, color.Bold)
var WarnColor = color.New(color.FgYellow, color.Bold)
var ProgressColor = color.New(color.FgCyan, color.Bold)
var HeaderColor = color.New(color.FgMagenta, color.Bold)

func InitLogger() {
	Logger = log.New(os.Stdout, "", 0)
	color.Unset()
}

func LogInfo(msg string) {
	InfoColor.Print("[✓] ")
	fmt.Println(msg)
}

func LogError(msg string, err error) {
	ErrorColor.Print("[✗] ")
	fmt.Printf("%s: %v\n", msg, err)
}

func LogWarn(msg string) {
	WarnColor.Print("[⚠] ")
	fmt.Println(msg)
}

func LogProgress(step, detail string) {
	ProgressColor.Print("[→] ")
	fmt.Printf("%s: %s\n", step, detail)
}

func LogHeader(msg string) {
	fmt.Println()
	HeaderColor.Println("═══════════════════════════════════════════════════════")
	HeaderColor.Printf("  %s\n", msg)
	HeaderColor.Println("═══════════════════════════════════════════════════════")
	fmt.Println()
}

func LogSubHeader(msg string) {
	ProgressColor.Println(fmt.Sprintf("\n┌─ %s", msg))
	ProgressColor.Println("└────────────────────────────────────────")
}



func PrintBanner() {
	fmt.Println()
	color.Set(color.FgMagenta)
	fmt.Print(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔒  AI-POWERED SOURCE CODE SECURITY SCANNER  			║
║                                                           ║
║   Version 2.0 | Built with Go + Ollama AI  				║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
`)
	color.Unset()
}


