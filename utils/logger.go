package utils

import (
	"fmt"
	"log"
	"os"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
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

func CreateProgressBar(total int, description string) *progressbar.ProgressBar {
	return progressbar.NewOptions(total,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWidth(40),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerHead:    "█",
			SaucerPadding: "░",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
}

func PrintBanner() {
	fmt.Println()
	color.Set(color.FgMagenta)
	fmt.Print(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔒  AI-POWERED SOURCE CODE SECURITY SCANNER  		║
║                                                           ║
║   Version 2.0 | Built with Go + Ollama AI            	║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
`)
	color.Unset()
}

func PrintSummary(total, critical, high, medium, low, aiValidated int) {
	fmt.Println()
	HeaderColor.Println("📊 SCAN SUMMARY")
	fmt.Println("┌─────────────────────────────────────────────────────┐")

	fmt.Printf("│  %-20s: %-25s │\n", "Total Findings", color.HiWhiteString("%d", total))

	if critical > 0 {
		fmt.Printf("│  %-20s: %-25s │\n", "Critical", color.HiRedString("%d", critical))
	}
	if high > 0 {
		fmt.Printf("│  %-20s: %-25s │\n", "High", color.HiYellowString("%d", high))
	}
	if medium > 0 {
		fmt.Printf("│  %-20s: %-25s │\n", "Medium", color.HiBlueString("%d", medium))
	}
	if low > 0 {
		fmt.Printf("│  %-20s: %-25s │\n", "Low", color.HiCyanString("%d", low))
	}

	if total > 0 {
		fmt.Printf("│  %-20s: %-25s │\n", "AI Validated", color.HiGreenString("%d (%.1f%%)", aiValidated, float64(aiValidated)/float64(total)*100))
	} else {
		fmt.Printf("│  %-20s: %-25s │\n", "AI Validated", color.HiGreenString("%d (0.0%%)", aiValidated))
	}

	fmt.Println("└─────────────────────────────────────────────────────┘")
	fmt.Println()
}
