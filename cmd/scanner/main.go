package main

import (
	"fmt"
	"os"

	"QWEN_SCR_24_FEB_2026/utils"
)

func main() {
	utils.InitLogger()
	utils.PrintBanner()

	port := 5336

	// Check for --port flag
	for i, arg := range os.Args[1:] {
		if arg == "--port" || arg == "-port" {
			if i+1 < len(os.Args[1:])-1+1 {
				fmt.Sscanf(os.Args[i+2], "%d", &port)
			}
		}
	}

	if port <= 0 {
		port = 5336
	}

	StartWebServer(port)
}
