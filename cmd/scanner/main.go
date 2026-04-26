package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"

	"SentryQ/ai"
	"SentryQ/utils"

	"github.com/google/uuid"
)

func main() {
	utils.PrintBanner()

	portPtr := flag.Int("port", 5336, "Web server port")
	ollamaPtr := flag.String("ollama-host", "", "Remote Ollama host:port (overrides OLLAMA_HOST env var)")
	flag.Parse()

	// PORT env var support for container deployments
	port := *portPtr
	if envPort := os.Getenv("PORT"); envPort != "" && *portPtr == 5336 {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}
	if port <= 0 || port > 65535 {
		port = 5336
	}

	// OLLAMA_HOST env var support; --ollama-host flag takes precedence
	ollamaHost := *ollamaPtr
	if ollamaHost == "" {
		ollamaHost = os.Getenv("OLLAMA_HOST")
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
		// Apply stored AI provider/model/API key settings (same settings the web UI uses).
		loadSettings()

		// Configure a basic scan (no AI by default for speed in CLI, but can be enabled)
		cfg := WebScanConfig{
			EnableDeepScan: true,
			EnableAI:       false, // CLI defaults to static scan
			OllamaHost:     ollamaHost,
		}
		
		// Generate a unique scan ID
		scanID := "cli-" + uuid.New().String()
		if err := CreateScan(scanID, targetDir, "cli", "{}"); err != nil {
			fmt.Printf("❌ Failed to create scan record: %v\n", err)
			return
		}
		
		// Run the scan synchronously
		ctx := context.Background()
		runScan(ctx, scanID, targetDir, cfg)
		
		// Print summary
		findings, err := GetFindingsForScan(scanID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to retrieve findings from DB: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n✅ CLI Scan Complete. Total Findings: %d\n", len(findings))
		return
	}

	// Start the web server from web_dashboard
	StartWebServer(port)
}
