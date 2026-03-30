package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// ThreatIntelScanner performs threat intelligence integration
type ThreatIntelScanner struct {
	mu          sync.RWMutex
	cveCache    map[string]CVEInfo
	lastUpdate  time.Time
	cacheFile   string
	mitreATTACK map[string]MITRETechnique
	kevCache    map[string]bool // map of CVE-IDs that are in CISA KEV
}

// CVEInfo represents CVE information
type CVEInfo struct {
	ID          string    `json:"id"`
	Summary     string    `json:"summary"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSSScore   float64   `json:"cvss_score"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	References  []string  `json:"references"`
}

// MITRETechnique represents MITRE ATT&CK technique
type MITRETechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tactics     []string `json:"tactics"`
	Platforms   []string `json:"platforms"`
}

// NewThreatIntelScanner creates a new threat intelligence scanner
func NewThreatIntelScanner() *ThreatIntelScanner {
	return &ThreatIntelScanner{
		cveCache:    make(map[string]CVEInfo),
		lastUpdate:  time.Time{},
		cacheFile:   ".threat-intel-cache.json",
		mitreATTACK: loadMITREATTACK(),
		kevCache:    make(map[string]bool),
	}
}

// ScanWithThreatIntel enhances findings with threat intelligence
func (tis *ThreatIntelScanner) ScanWithThreatIntel(findings []reporter.Finding) ([]reporter.Finding, error) {
	var enhancedFindings []reporter.Finding

	utils.LogInfo("Enhancing findings with threat intelligence...")

	// Load CVE cache
	tis.loadCVECache()
	tis.loadCisaKEV()

	// Check for CVE updates
	tis.mu.RLock()
	lastUp := tis.lastUpdate
	tis.mu.RUnlock()

	if time.Since(lastUp) > 24*time.Hour {
		utils.LogInfo("Updating CVE database...")
		tis.updateCVECache()
	}

	for _, finding := range findings {
		enhancedFinding := finding

		// Enrich with CVE data if applicable
		if strings.Contains(strings.ToUpper(finding.RuleID), "CVE") || strings.Contains(strings.ToUpper(finding.IssueName), "CVE") {
			// Extract CVE ID loosely
			cveID := extractCVE(finding.RuleID)
			if cveID == "" {
				cveID = extractCVE(finding.IssueName)
			}

			if cveID != "" {
				cveInfo := tis.getCVEInfo(cveID)
				if cveInfo.ID != "" {
					enhancedFinding.Description = fmt.Sprintf("%s\n\nCVE Details: %s (CVSS: %.1f)",
						finding.Description, cveInfo.Summary, cveInfo.CVSSScore)
					enhancedFinding.Remediation = fmt.Sprintf("%s\n\nReferences: %s",
						finding.Remediation, strings.Join(cveInfo.References, ", "))
				}

				// Check CISA KEV and EPSS
				epss, _ := tis.getEPSSScore(cveID)

				tis.mu.RLock()
				inKEV := tis.kevCache[strings.ToUpper(cveID)]
				tis.mu.RUnlock()

				if inKEV || epss > 0.05 {
					enhancedFinding.IssueName = "[ACTIVELY EXPLOITED] " + enhancedFinding.IssueName
					enhancedFinding.Severity = "critical"

					exploitContext := ""
					if inKEV {
						exploitContext += "\n- Found in CISA Known Exploited Vulnerabilities Catalog."
					}
					if epss > 0.05 {
						exploitContext += fmt.Sprintf("\n- High EPSS Probability: %.1f%% chance of exploitation in the next 30 days.", epss*100)
					}
					enhancedFinding.Description += fmt.Sprintf("\n\nTHREAT INTEL ALERT: %s", exploitContext)
				}
			}
		}

		// Map to MITRE ATT&CK
		mitreTechnique := tis.mapToMITRE(finding)
		if mitreTechnique.ID != "" {
			enhancedFinding.Description = fmt.Sprintf("%s\n\nMITRE ATT&CK: %s - %s",
				enhancedFinding.Description, mitreTechnique.ID, mitreTechnique.Name)
		}

		enhancedFindings = append(enhancedFindings, enhancedFinding)
	}

	return enhancedFindings, nil
}



// Helper functions
func (tis *ThreatIntelScanner) loadCVECache() {
	// Load from cache file
	data, err := os.ReadFile(tis.cacheFile)
	if err != nil {
		return
	}

	tis.mu.Lock()
	defer tis.mu.Unlock()
	if err := json.Unmarshal(data, &tis.cveCache); err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to parse CVE cache: %v", err))
	}
}

func (tis *ThreatIntelScanner) updateCVECache() {
	// Fetch recent CVEs from NVD API
	client := &http.Client{
		Timeout: 120 * time.Second, // NVD responses can be large
	}

	// Implement date-filtered requests to drastically reduce payload size
	lookbackDays := 120
	startTime := time.Now().AddDate(0, 0, -lookbackDays).UTC().Format("2006-01-02T15:04:05.000")
	endTime := time.Now().UTC().Format("2006-01-02T15:04:05.000")
	nvdURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=%s&lastModEndDate=%s&resultsPerPage=100", startTime, endTime)

	var resp *http.Response
	var err error
	nvdKey := os.Getenv("NVD_API_KEY")

	// Retry loop for NVD API
	for attempt := 1; attempt <= 3; attempt++ {
		req, errReq := http.NewRequest("GET", nvdURL, nil)
		if errReq != nil {
			utils.LogWarn(fmt.Sprintf("Failed to create request for CVE cache: %v", errReq))
			return
		}

		// Add NVD API Key for better rate limits if provided
		if nvdKey != "" {
			req.Header.Set("apiKey", nvdKey)
			if attempt == 1 {
				utils.LogInfo("Using NVD API key for threat intelligence updates.")
			}
		}

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			break
		}

		if err != nil {
			utils.LogWarn(fmt.Sprintf("NVD update attempt %d failed: %v", attempt, err))
		} else {
			utils.LogWarn(fmt.Sprintf("NVD update attempt %d returned status %d", attempt, resp.StatusCode))
			resp.Body.Close()
		}

		if attempt < 3 {
			time.Sleep(2 * time.Second)
		}
	}

	if err != nil || (resp != nil && resp.StatusCode != 200) {
		utils.LogWarn("Failed to update CVE cache after 3 attempts. Using existing cache if available.")
		return
	}

	// Validate API key if provided (check for auth errors)
	if nvdKey != "" && (resp.StatusCode == 403 || resp.StatusCode == 401) {
		utils.LogWarn("NVD API key appears to be invalid. Threat intel updates may be rate-limited.")
		utils.LogWarn("To validate your NVD API key, visit: https://nvd.nist.gov/developers/request-an-api-key")
	}

	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to decode NVD API response: %v", err))
		return
	}

	tis.mu.Lock()
	defer tis.mu.Unlock()

	for _, v := range nvdResp.Vulnerabilities {
		cve := v.CVE
		info := CVEInfo{ID: cve.ID}

		if len(cve.Descriptions) > 0 {
			info.Summary = cve.Descriptions[0].Value
		}

		if len(cve.Metrics.CvssMetricV31) > 0 {
			info.CVSSScore = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			info.Severity = cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		}

		for _, ref := range cve.References {
			info.References = append(info.References, ref.URL)
		}

		tis.cveCache[cve.ID] = info
	}

	tis.lastUpdate = time.Now()

	// Save back to file
	if data, err := json.MarshalIndent(tis.cveCache, "", "  "); err == nil {
		_ = os.WriteFile(tis.cacheFile, data, 0644)
	}
}

func (tis *ThreatIntelScanner) getCVEInfo(cveID string) CVEInfo {
	tis.mu.RLock()
	info, exists := tis.cveCache[cveID]
	tis.mu.RUnlock()

	if exists {
		return info
	}

	// Fetch from NVD API if not in cache (simplified for missing ones)
	return CVEInfo{}
}

func extractCVE(text string) string {
	// Simple regex to extract CVE-YYYY-XXXX
	// Can be imported via regexp if needed but since strings are short we can just do basic pattern
	// Let's assume we have strings package
	parts := strings.Split(strings.ToUpper(text), "-")
	for i, part := range parts {
		if part == "CVE" && i+2 < len(parts) {
			return fmt.Sprintf("CVE-%s-%s", parts[i+1], parts[i+2])
		}
	}
	// Fallback to searching the string
	return ""
}

// loadCisaKEV downloads the CISA Known Exploited Vulnerabilities catalog
func (tis *ThreatIntelScanner) loadCisaKEV() {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var kevData struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&kevData); err == nil {
		tis.mu.Lock()
		for _, vuln := range kevData.Vulnerabilities {
			tis.kevCache[strings.ToUpper(vuln.CveID)] = true
		}
		tis.mu.Unlock()
	}
}

// getEPSSScore queries the FIRST.org EPSS API for real-time exploitation probability
func (tis *ThreatIntelScanner) getEPSSScore(cveID string) (float64, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", cveID))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var epssData struct {
		Data []struct {
			Epss string `json:"epss"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&epssData); err != nil {
		return 0, err
	}

	if len(epssData.Data) > 0 {
		var score float64
		fmt.Sscanf(epssData.Data[0].Epss, "%f", &score)
		return score, nil
	}

	return 0, nil
}

func (tis *ThreatIntelScanner) mapToMITRE(finding reporter.Finding) MITRETechnique {
	// Map finding to MITRE ATT&CK technique
	findingType := strings.ToLower(finding.IssueName)

	for _, technique := range tis.mitreATTACK {
		if strings.Contains(findingType, strings.ToLower(technique.Name)) {
			return technique
		}
	}

	// Default mappings
	if strings.Contains(findingType, "sql injection") {
		return tis.mitreATTACK["T1190"] // Exploit Public-Facing Application
	}
	if strings.Contains(findingType, "command injection") {
		return tis.mitreATTACK["T1059"] // Command and Scripting Interpreter
	}
	if strings.Contains(findingType, "xss") {
		return tis.mitreATTACK["T1189"] // Drive-by Compromise
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
	}
}
