package main

import (
	"context"
	"flag"
	"fmt"

	"QWEN_SCR_24_FEB_2026/ai"
	"QWEN_SCR_24_FEB_2026/utils"

	"github.com/google/uuid"
)

func main() {
	utils.InitLogger()
	utils.PrintBanner()

	portPtr := flag.Int("port", 5336, "Web server port")
	ollamaPtr := flag.String("ollama-host", "", "Remote Ollama host:port")
	flag.Parse()

	port := *portPtr
	ollamaHost := *ollamaPtr

	if port <= 0 || port > 65535 {
		port = 5336
		fmt.Printf("📡 Web UI: http://localhost:%d\n", port)
	}

	if ollamaHost != "" {
		fmt.Printf("🔗 Ollama: %s\n", ollamaHost)
		ai.SetOllamaHost(ollamaHost)
	} else {
		fmt.Println("🔗 Ollama: localhost:11434")
	}

	// If a positional argument is provided, treat it as a directory to scan immediately
	if flag.NArg() > 0 {
		targetDir := flag.Arg(0)
		fmt.Printf("🚀 Starting CLI scan of: %s\n", targetDir)

		// Initialize database
		if err := InitDB(); err != nil {
			fmt.Printf("❌ Failed to initialize database: %v\n", err)
			return
		}
		
		// Configure a basic scan (no AI by default for speed in CLI, but can be enabled)
		cfg := WebScanConfig{
			EnableDeepScan: true,
			EnableAI:       false, // CLI defaults to static scan
			OllamaHost:     ollamaHost,
		}
		
		// Generate a unique scan ID
		scanID := "cli-" + uuid.New().String()[:8]
		if err := CreateScan(scanID, targetDir, "cli", "{}"); err != nil {
			fmt.Printf("❌ Failed to create scan record: %v\n", err)
			return
		}
		
		// Run the scan synchronously
		ctx := context.Background()
		runScan(ctx, scanID, targetDir, cfg)
		
		// Print summary
		findings, _ := GetFindingsForScan(scanID)
		fmt.Printf("\n✅ CLI Scan Complete. Total Findings: %d\n", len(findings))
		return
	}

	// Start the web server from web_dashboard
	StartWebServer(port)
}
