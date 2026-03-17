package scanner

import (
	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
)

// getTrivyBin returns the correct executable name based on OS
func getTrivyBin() string {
	if runtime.GOOS == "windows" {
		return "trivy.exe"
	}
	return "trivy"
}

// ContainerScanner handles Dockerfile and container image scanning
type ContainerScanner struct {
	srCounter int64
}

// NewContainerScanner creates a new container scanner
func NewContainerScanner(counter int64) *ContainerScanner {
	return &ContainerScanner{
		srCounter: counter,
	}
}

// ScanContainers scans Dockerfiles in the target directory
func (cs *ContainerScanner) ScanContainers(targetDir string) ([]reporter.Finding, error) {
	var findings []reporter.Finding
	var dockerfiles []string
	var k8sManifests []string

	// Find all Dockerfiles and K8s YAML files
	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			base := strings.ToLower(filepath.Base(path))
			if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
				dockerfiles = append(dockerfiles, path)
			} else if strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml") {
				// We'll optimistically inspect yaml files for K8s kinds
				k8sManifests = append(k8sManifests, path)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	var parsedImages []string

	// Scan Dockerfiles
	for _, df := range dockerfiles {
		fileFindings, baseImage := cs.scanDockerfile(df)
		findings = append(findings, fileFindings...)
		if baseImage != "" {
			parsedImages = append(parsedImages, baseImage)
		}
	}

	// Scan Kubernetes Manifests
	for _, k8s := range k8sManifests {
		findings = append(findings, cs.scanKubernetesManifest(k8s)...)
	}

	// Try running external container scanners natively (Trivy)
	if hasTrivy() && len(parsedImages) > 0 {
		utils.LogInfo(fmt.Sprintf("Trivy detected, running container image vulnerability scan on %d unique images...", len(parsedImages)))
		trivyFindings := cs.runTrivyScan(parsedImages)
		findings = append(findings, trivyFindings...)
	}

	return findings, nil
}

func (cs *ContainerScanner) scanDockerfile(filePath string) ([]reporter.Finding, string) {
	var findings []reporter.Finding
	var baseImage string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 1

	var currentBaseImage string
	var hasAnyUser bool        // Track if ANY stage has USER directive
	var hasAnyHealthCheck bool // Track if ANY stage has HEALTHCHECK

	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			lineNum++
			continue
		}

		// Check for FROM (Start of a new stage)
		if strings.HasPrefix(strings.ToUpper(trimmedLine), "FROM ") {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 2 {
				currentBaseImage = parts[1]
				baseImage = currentBaseImage // Update global base image (last one wins)
			}

			if strings.Contains(strings.ToLower(trimmedLine), ":latest") || !strings.Contains(trimmedLine, ":") {
				findings = append(findings, cs.createFinding(filePath, lineNum,
					"CONTAINER-LATEST-TAG",
					"Base Image using 'latest' tag",
					"Using the 'latest' tag can lead to unpredictable builds and security vulnerabilities.",
					"medium",
					"CWE-1104",
					"A06:2021-Vulnerable and Outdated Components"))
			}
		}

		// Check for USER
		if strings.HasPrefix(strings.ToUpper(trimmedLine), "USER ") {
			hasAnyUser = true // Global: at least one stage has it
			if strings.Contains(strings.ToLower(trimmedLine), "root") || strings.TrimSpace(trimmedLine[5:]) == "0" {
				findings = append(findings, cs.createFinding(filePath, lineNum,
					"CONTAINER-ROOT-USER",
					"Container explicitly running as root",
					"Running containers as root violates the principle of least privilege.",
					"high",
					"CWE-250",
					"A01:2021-Broken Access Control"))
			}
		}

		// Check for HEALTHCHECK
		if strings.HasPrefix(strings.ToUpper(trimmedLine), "HEALTHCHECK") {
			hasAnyHealthCheck = true // Global: at least one stage has it
		}

		// Check for secrets in ENV
		if strings.HasPrefix(strings.ToUpper(trimmedLine), "ENV ") || strings.HasPrefix(strings.ToUpper(trimmedLine), "ARG ") {
			secretRegex := regexp.MustCompile(`(?i)(password|secret|key|token|credentials)`)
			if secretRegex.MatchString(trimmedLine) {
				findings = append(findings, cs.createFinding(filePath, lineNum,
					"CONTAINER-ENV-SECRET",
					"Potential secret baked into container image",
					"Defining secrets using ENV or ARG bakes them into the image layers.",
					"critical",
					"CWE-312",
					"A07:2021-Identification and Authentication Failures"))
			}
		}

		// Check for EXPOSE
		if strings.HasPrefix(strings.ToUpper(trimmedLine), "EXPOSE ") {
			portRegex := regexp.MustCompile(`\b(22|3389|23)\b`)
			if portRegex.MatchString(trimmedLine) {
				findings = append(findings, cs.createFinding(filePath, lineNum,
					"CONTAINER-EXPOSE-SENSITIVE-PORT",
					"Suspicious or sensitive port exposed",
					"Exposing SSH, RDP, or Telnet directly in a container is generally a bad practice.",
					"high",
					"CWE-200",
					"A05:2021-Security Misconfiguration"))
			}
		}

		lineNum++
	}

	// Warn if ANY stage is missing USER directive (security best practice)
	if !hasAnyUser {
		findings = append(findings, cs.createFinding(filePath, 0,
			"CONTAINER-MISSING-USER",
			"No USER directive found in any stage",
			"The container will run as root by default. Add a 'USER <non-root-user>' directive to any stage.",
			"high",
			"CWE-250",
			"A01:2021-Broken Access Control"))
	}

	if !hasAnyHealthCheck {
		findings = append(findings, cs.createFinding(filePath, 0,
			"CONTAINER-MISSING-HEALTHCHECK",
			"No HEALTHCHECK instruction in any stage",
			"Adding a HEALTHCHECK instruction ensures that the container orchestrator knows if the application is healthy.",
			"low",
			"CWE-754",
			"A05:2021-Security Misconfiguration"))
	}

	return findings, baseImage
}

func hasTrivy() bool {
	_, err := exec.LookPath(getTrivyBin())
	return err == nil
}

func (cs *ContainerScanner) runTrivyScan(images []string) []reporter.Finding {
	var findings []reporter.Finding

	// Deduplicate images
	uniqueImages := make(map[string]bool)
	for _, img := range images {
		// Ignore scratch/build stages
		if strings.ToLower(img) != "scratch" && !strings.HasPrefix(img, "builder") {
			uniqueImages[img] = true
		}
	}

	type trivyResult struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
			Severity         string `json:"Severity"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
		} `json:"Vulnerabilities"`
	}

	type trivyReport struct {
		Results []trivyResult `json:"Results"`
	}

	for image := range uniqueImages {
		utils.LogInfo(fmt.Sprintf("    Scanning base image: %s...", image))

		cmd := exec.Command(getTrivyBin(), "image", "-q", "--format", "json", image)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			utils.LogWarn(fmt.Sprintf("Failed to run Trivy on %s (it might need to be downloaded first or not exist). Skipping.", image))
			continue
		}

		var report trivyReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			continue
		}

		for _, result := range report.Results {
			for _, vuln := range result.Vulnerabilities {
				severity := strings.ToLower(vuln.Severity)
				if severity == "critical" || severity == "high" {
					desc := fmt.Sprintf("%s\n\nPackage: %s\nInstalled Version: %s\nFixed Version: %s\nImage: %s",
						vuln.Description, vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion, image)

					findings = append(findings, cs.createFinding(
						"FROM "+image,
						0,
						vuln.VulnerabilityID,
						fmt.Sprintf("[TRIVY] %s in %s", vuln.VulnerabilityID, vuln.PkgName),
						desc,
						severity,
						"CWE-1104",
						"A06:2021-Vulnerable and Outdated Components",
					))
				}
			}
		}
	}

	return findings
}

// scanKubernetesManifest does rudimentary security linting of Kubernetes YAMLs
func (cs *ContainerScanner) scanKubernetesManifest(filePath string) []reporter.Finding {
	var findings []reporter.Finding
	content, err := os.ReadFile(filePath)
	if err != nil {
		return findings
	}

	yamlStr := string(content)

	// If it doesn't look like K8s, skip
	if !strings.Contains(yamlStr, "apiVersion:") || !strings.Contains(yamlStr, "kind:") {
		return findings
	}

	lines := strings.Split(yamlStr, "\n")
	for i, line := range lines {
		trimmed := strings.ToLower(strings.TrimSpace(line))

		if strings.Contains(trimmed, "privileged: ") && strings.Contains(trimmed, "true") {
			findings = append(findings, cs.createFinding(
				filePath,
				i+1,
				"K8S-PRIVILEGED-CONTAINER",
				"Kubernetes Pod running as privileged",
				"Running privileged containers provides all capabilities to the container, and it nearly lifts all the limitations enforced by the cgroup controller.",
				"critical",
				"CWE-250",
				"A01:2021-Broken Access Control",
			))
		}

		if strings.Contains(trimmed, "allowprivilegeescalation: ") && strings.Contains(trimmed, "true") {
			findings = append(findings, cs.createFinding(
				filePath,
				i+1,
				"K8S-PRIVILEGE-ESCALATION",
				"Container allows privilege escalation",
				"A container should not generally be allowed to gain more privileges than its parent process.",
				"high",
				"CWE-250",
				"A01:2021-Broken Access Control",
			))
		}
	}

	return findings
}

func (cs *ContainerScanner) createFinding(filePath string, lineNum int, ruleID, issueName, description, severity, cwe, owasp string) reporter.Finding {
	srNo := int(atomic.AddInt64(&cs.srCounter, 1))
	lineRef := "0"
	if lineNum > 0 {
		lineRef = fmt.Sprintf("%d", lineNum)
	}

	conf := 0.8
	if severity == "critical" {
		conf = 0.95
	} else if severity == "high" {
		conf = 0.85
	}

	return reporter.Finding{
		SrNo:        srNo,
		IssueName:   issueName,
		Description: description,
		Severity:    severity,
		FilePath:    filePath,
		LineNumber:  lineRef,
		AiValidated: "No",
		RuleID:      ruleID,
		Source:      "dockerfile",
		CWE:         cwe,
		OWASP:       owasp,
		Confidence:  conf,
	}
}
