package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SARIF 2.1.0 types
type sarifLog struct {
	Version string      `json:"version"`
	Schema  string      `json:"$schema"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
	Rules   []sarifRule   `json:"tool.driver.rules,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	FullDescription  sarifMessage      `json:"fullDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       sarifRuleProps    `json:"properties"`
}

type sarifRuleProps struct {
	Severity string   `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
	Properties sarifResultProps `json:"properties,omitempty"`
}

type sarifResultProps struct {
	AIValidated string  `json:"aiValidated,omitempty"`
	TrustScore  float64 `json:"trustScore,omitempty"`
	Source      string  `json:"source,omitempty"`
	OWASP       string  `json:"owasp,omitempty"`
	ExploitPoC  string  `json:"exploitPoc,omitempty"`
	FixedCode   string  `json:"fixedCode,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// severityToSARIFLevel maps SentryQ severity to SARIF level
func severityToSARIFLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// GenerateSARIF writes a SARIF 2.1.0 report to filename
func GenerateSARIF(filename string, findings []Finding) error {
	// Collect unique rules
	ruleMap := map[string]sarifRule{}
	for _, f := range findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = strings.ReplaceAll(strings.ToLower(f.IssueName), " ", "-")
		}
		if _, exists := ruleMap[ruleID]; !exists {
			helpURI := ""
			if f.CWE != "" {
				cweNum := strings.TrimPrefix(f.CWE, "CWE-")
				helpURI = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cweNum)
			}
			tags := []string{}
			if f.CWE != "" {
				tags = append(tags, f.CWE)
			}
			if f.OWASP != "" {
				tags = append(tags, f.OWASP)
			}
			ruleMap[ruleID] = sarifRule{
				ID:               ruleID,
				Name:             f.IssueName,
				ShortDescription: sarifMessage{Text: f.IssueName},
				FullDescription:  sarifMessage{Text: f.Description},
				HelpURI:          helpURI,
				Properties:       sarifRuleProps{Severity: strings.ToLower(f.Severity), Tags: tags},
			}
		}
	}

	rules := make([]sarifRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	// Build results
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = strings.ReplaceAll(strings.ToLower(f.IssueName), " ", "-")
		}

		lineNum := 1
		if f.LineNumber != "" {
			fmt.Sscanf(f.LineNumber, "%d", &lineNum)
		}
		if lineNum < 1 {
			lineNum = 1
		}

		uri := f.FilePath
		if strings.HasPrefix(uri, "/") {
			uri = uri[1:]
		}

		msg := f.Description
		if f.Remediation != "" {
			msg += " Remediation: " + f.Remediation
		}

		results = append(results, sarifResult{
			RuleID: ruleID,
			Level:  severityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
					Region:           sarifRegion{StartLine: lineNum},
				},
			}},
			Properties: sarifResultProps{
				AIValidated: f.AiValidated,
				TrustScore:  f.TrustScore,
				Source:      f.Source,
				OWASP:       f.OWASP,
				ExploitPoC:  f.ExploitPoC,
				FixedCode:   f.FixedCode,
			},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "SentryQ",
					Version:        "1.0.0",
					InformationURI: "https://github.com/SentryQ/SentryQ",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
