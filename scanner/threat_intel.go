package scanner

import (
	"fmt"
	"strings"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// MITRETechnique represents a MITRE ATT&CK technique
type MITRETechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tactics     []string `json:"tactics"`
	Platforms   []string `json:"platforms"`
}

// ThreatIntelScanner annotates findings with MITRE ATT&CK technique mappings.
// All enrichment is done locally (no network calls).
type ThreatIntelScanner struct {
	mitreATTACK map[string]MITRETechnique
}

// NewThreatIntelScanner creates a new threat intelligence scanner
func NewThreatIntelScanner() *ThreatIntelScanner {
	return &ThreatIntelScanner{
		mitreATTACK: loadMITREATTACK(),
	}
}

// ScanWithThreatIntel annotates each finding with its MITRE ATT&CK technique.
// This is a pure local operation — no external API calls are made.
func (tis *ThreatIntelScanner) ScanWithThreatIntel(findings []reporter.Finding) ([]reporter.Finding, error) {
	utils.LogInfo("Annotating findings with MITRE ATT&CK mappings...")

	enhanced := make([]reporter.Finding, len(findings))
	for i, f := range findings {
		enhanced[i] = f
		if technique := tis.mapToMITRE(f); technique.ID != "" {
			enhanced[i].Description = fmt.Sprintf("%s\n\nMITRE ATT&CK: %s - %s",
				f.Description, technique.ID, technique.Name)
		}
	}

	return enhanced, nil
}

func (tis *ThreatIntelScanner) mapToMITRE(finding reporter.Finding) MITRETechnique {
	name := strings.ToLower(finding.IssueName)

	// Keyword → technique mappings
	switch {
	case strings.Contains(name, "sql injection"):
		return tis.mitreATTACK["T1190"]
	case strings.Contains(name, "command injection"), strings.Contains(name, "os command"),
		strings.Contains(name, "exec("), strings.Contains(name, "shell"):
		return tis.mitreATTACK["T1059"]
	case strings.Contains(name, "xss"), strings.Contains(name, "cross-site scripting"):
		return tis.mitreATTACK["T1189"]
	case strings.Contains(name, "hardcoded"), strings.Contains(name, "secret"),
		strings.Contains(name, "credential"), strings.Contains(name, "password"),
		strings.Contains(name, "api key"), strings.Contains(name, "token"):
		return tis.mitreATTACK["T1078"]
	case strings.Contains(name, "path traversal"), strings.Contains(name, "directory traversal"),
		strings.Contains(name, "lfi"), strings.Contains(name, "rfi"):
		return tis.mitreATTACK["T1083"]
	case strings.Contains(name, "ssrf"):
		return tis.mitreATTACK["T1190"]
	case strings.Contains(name, "deserialization"), strings.Contains(name, "unserialize"):
		return tis.mitreATTACK["T1190"]
	case strings.Contains(name, "xxe"), strings.Contains(name, "xml external"):
		return tis.mitreATTACK["T1190"]
	case strings.Contains(name, "ldap injection"):
		return tis.mitreATTACK["T1190"]
	case strings.Contains(name, "open redirect"):
		return tis.mitreATTACK["T1189"]
	case strings.Contains(name, "insecure random"), strings.Contains(name, "weak random"):
		return tis.mitreATTACK["T1552"] // Unsecured Credentials — insufficient entropy in secrets
	}

	return MITRETechnique{}
}

func loadMITREATTACK() map[string]MITRETechnique {
	return map[string]MITRETechnique{
		"T1190": {
			ID:          "T1190",
			Name:        "Exploit Public-Facing Application",
			Description: "Adversaries may attempt to exploit a weakness in an Internet-facing host or system",
			Tactics:     []string{"Initial Access"},
			Platforms:   []string{"Containers", "IaaS", "Linux", "Windows", "macOS"},
		},
		"T1059": {
			ID:          "T1059",
			Name:        "Command and Scripting Interpreter",
			Description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries",
			Tactics:     []string{"Execution"},
			Platforms:   []string{"Linux", "Windows", "macOS"},
		},
		"T1189": {
			ID:          "T1189",
			Name:        "Drive-by Compromise",
			Description: "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing",
			Tactics:     []string{"Initial Access"},
			Platforms:   []string{"Linux", "Windows", "macOS"},
		},
		"T1078": {
			ID:          "T1078",
			Name:        "Valid Accounts",
			Description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access",
			Tactics:     []string{"Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"},
			Platforms:   []string{"Containers", "IaaS", "Linux", "Windows", "macOS"},
		},
		"T1040": {
			ID:          "T1040",
			Name:        "Network Sniffing",
			Description: "Adversaries may sniff network traffic to capture information about an environment",
			Tactics:     []string{"Credential Access", "Discovery"},
			Platforms:   []string{"Linux", "Windows", "macOS"},
		},
		"T1552": {
			ID:          "T1552",
			Name:        "Unsecured Credentials",
			Description: "Adversaries may search for insecure credentials (e.g. hardcoded secrets or weak entropy) that can be leveraged for initial access or privilege escalation",
			Tactics:     []string{"Credential Access"},
			Platforms:   []string{"Linux", "Windows", "macOS", "Containers"},
		},
		"T1083": {
			ID:          "T1083",
			Name:        "File and Directory Discovery",
			Description: "Adversaries may enumerate files and directories or may search in specific locations for configuration files or credentials",
			Tactics:     []string{"Discovery"},
			Platforms:   []string{"Linux", "Windows", "macOS"},
		},
	}
}
