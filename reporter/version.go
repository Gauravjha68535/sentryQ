package reporter

// Version is the SentryQ scanner version, used across all generated reports
// (CSV, HTML, PDF, SARIF). Override at build time with:
//
//	go build -ldflags "-X SentryQ/reporter.Version=3.0.0" ./...
var Version = "2.0.0"
