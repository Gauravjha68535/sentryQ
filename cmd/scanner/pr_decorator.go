package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// PRConfig holds the config needed to post findings as PR comments.
type PRConfig struct {
	Provider    string // "github" or "gitlab"
	Token       string // personal access token / CI token
	Repo        string // "owner/repo" for GitHub; "namespace/project" for GitLab
	PRNumber    int    // GitHub PR number
	MRID        int    // GitLab merge request IID
	GitLabURL   string // GitLab base URL (default: https://gitlab.com)
	MaxComments int    // max inline file comments to post (0 = unlimited)
}

// DecoratePR posts a summary comment + per-file inline comments on the PR/MR.
// Errors are logged but non-fatal — scan results are always saved to DB first.
func DecoratePR(cfg PRConfig, scanID string, findings []reporter.Finding) {
	if cfg.Token == "" {
		utils.LogWarn("pr-decorator: no token supplied — skipping PR decoration")
		return
	}
	if cfg.Repo == "" {
		utils.LogWarn("pr-decorator: no repo supplied — skipping PR decoration")
		return
	}

	summary := buildPRSummaryComment(scanID, findings)

	switch strings.ToLower(cfg.Provider) {
	case "github":
		if cfg.PRNumber <= 0 {
			utils.LogWarn("pr-decorator: github requires --pr-number")
			return
		}
		postGitHubPRComment(cfg, summary)
		postGitHubReviewComments(cfg, findings)
	case "gitlab":
		if cfg.MRID <= 0 {
			utils.LogWarn("pr-decorator: gitlab requires --mr-iid")
			return
		}
		if cfg.GitLabURL == "" {
			cfg.GitLabURL = "https://gitlab.com"
		}
		postGitLabMRNote(cfg, summary)
	default:
		utils.LogWarn(fmt.Sprintf("pr-decorator: unknown provider %q (use 'github' or 'gitlab')", cfg.Provider))
	}
}

// buildPRSummaryComment creates the markdown summary comment body.
func buildPRSummaryComment(scanID string, findings []reporter.Finding) string {
	counts := map[string]int{}
	for _, f := range findings {
		if f.Status == "false_positive" || f.Status == "ignored" {
			continue
		}
		counts[strings.ToLower(f.Severity)]++
	}
	total := counts["critical"] + counts["high"] + counts["medium"] + counts["low"] + counts["info"]

	riskIcon := "✅"
	if counts["critical"] > 0 {
		riskIcon = "🚨"
	} else if counts["high"] > 0 {
		riskIcon = "⚠️"
	} else if total > 0 {
		riskIcon = "ℹ️"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## %s SentryQ Security Scan — %d finding(s)\n\n", riskIcon, total))
	sb.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := counts[sev]; n > 0 {
			icon := map[string]string{"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[sev]
			sevLabel := strings.ToUpper(sev[:1]) + sev[1:]
			sb.WriteString(fmt.Sprintf("| %s %s | **%d** |\n", icon, sevLabel, n))
		}
	}

	if total > 0 {
		sb.WriteString("\n### Top Findings\n\n")
		shown := 0
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			for _, f := range findings {
				if strings.ToLower(f.Severity) != sev || f.Status == "false_positive" {
					continue
				}
				if shown >= 10 {
					break
				}
				sb.WriteString(fmt.Sprintf("- **%s** `%s` — %s (line %s)\n",
					strings.ToUpper(f.Severity),
					f.FilePath,
					f.IssueName,
					f.LineNumber,
				))
				shown++
			}
			if shown >= 10 {
				break
			}
		}
		if total > 10 {
			sb.WriteString(fmt.Sprintf("\n_…and %d more. View full report in SentryQ._\n", total-10))
		}
	}

	sb.WriteString(fmt.Sprintf("\n---\n_SentryQ scan ID: `%s` • %s_\n", scanID, time.Now().UTC().Format("2006-01-02 15:04 UTC")))
	return sb.String()
}

// ── GitHub ────────────────────────────────────────────────────────────────────

func postGitHubPRComment(cfg PRConfig, body string) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d/comments", cfg.Repo, cfg.PRNumber)
	payload, _ := json.Marshal(map[string]string{"body": body})

	req, _ := http.NewRequest("POST", url, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SentryQ/"+reporter.Version)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		utils.LogWarn(fmt.Sprintf("pr-decorator: GitHub comment POST failed: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		utils.LogWarn(fmt.Sprintf("pr-decorator: GitHub returned HTTP %d: %s", resp.StatusCode, string(b)))
		return
	}
	utils.LogInfo(fmt.Sprintf("pr-decorator: posted summary comment to GitHub PR #%d", cfg.PRNumber))
}

// postGitHubReviewComments posts inline code comments on the PR diff for
// critical/high findings. Limited to cfg.MaxComments (default 20) to avoid spam.
func postGitHubReviewComments(cfg PRConfig, findings []reporter.Finding) {
	maxC := cfg.MaxComments
	if maxC <= 0 {
		maxC = 20
	}

	// Get the latest commit SHA for the PR so we can anchor comments
	sha := getGitHubPRHeadSHA(cfg)
	if sha == "" {
		return
	}

	type reviewComment struct {
		Path     string `json:"path"`
		Line     int    `json:"line"`
		Side     string `json:"side"`
		Body     string `json:"body"`
		CommitID string `json:"commit_id"`
	}

	var comments []reviewComment
	seen := map[string]bool{}
	for _, f := range findings {
		if len(comments) >= maxC {
			break
		}
		if strings.ToLower(f.Severity) != "critical" && strings.ToLower(f.Severity) != "high" {
			continue
		}
		if f.Status == "false_positive" || f.Status == "ignored" {
			continue
		}
		line := parseFirstLine(f.LineNumber)
		if line <= 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d", f.FilePath, line)
		if seen[key] {
			continue
		}
		seen[key] = true

		body := fmt.Sprintf("**SentryQ %s: %s**\n\n%s\n\n**Remediation:** %s\n\n_Rule: `%s` | %s_",
			strings.ToUpper(f.Severity), f.IssueName,
			f.Description,
			f.Remediation,
			f.RuleID, f.CWE,
		)
		comments = append(comments, reviewComment{
			Path:     f.FilePath,
			Line:     line,
			Side:     "RIGHT",
			Body:     body,
			CommitID: sha,
		})
	}

	if len(comments) == 0 {
		return
	}

	// Create a review with all inline comments in one API call
	type reviewPayload struct {
		CommitID string          `json:"commit_id"`
		Body     string          `json:"body"`
		Event    string          `json:"event"`
		Comments []reviewComment `json:"comments"`
	}
	payload, _ := json.Marshal(reviewPayload{
		CommitID: sha,
		Body:     "",
		Event:    "COMMENT",
		Comments: comments,
	})

	url := fmt.Sprintf("https://api.github.com/repos/%s/pulls/%d/reviews", cfg.Repo, cfg.PRNumber)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SentryQ/"+reporter.Version)

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		utils.LogWarn(fmt.Sprintf("pr-decorator: GitHub review POST failed: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		utils.LogWarn(fmt.Sprintf("pr-decorator: GitHub review returned HTTP %d: %s", resp.StatusCode, string(b)))
		return
	}
	utils.LogInfo(fmt.Sprintf("pr-decorator: posted %d inline review comment(s) on GitHub PR #%d", len(comments), cfg.PRNumber))
}

func getGitHubPRHeadSHA(cfg PRConfig) string {
	url := fmt.Sprintf("https://api.github.com/repos/%s/pulls/%d", cfg.Repo, cfg.PRNumber)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SentryQ/"+reporter.Version)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var pr struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return ""
	}
	return pr.Head.SHA
}

// ── GitLab ────────────────────────────────────────────────────────────────────

func postGitLabMRNote(cfg PRConfig, body string) {
	url := fmt.Sprintf("%s/api/v4/projects/%s/merge_requests/%d/notes",
		strings.TrimRight(cfg.GitLabURL, "/"),
		urlEncodeRepo(cfg.Repo),
		cfg.MRID,
	)
	payload, _ := json.Marshal(map[string]string{"body": body})

	req, _ := http.NewRequest("POST", url, bytes.NewReader(payload))
	req.Header.Set("Private-Token", cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SentryQ/"+reporter.Version)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		utils.LogWarn(fmt.Sprintf("pr-decorator: GitLab note POST failed: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		utils.LogWarn(fmt.Sprintf("pr-decorator: GitLab returned HTTP %d: %s", resp.StatusCode, string(b)))
		return
	}
	utils.LogInfo(fmt.Sprintf("pr-decorator: posted summary note to GitLab MR !%d", cfg.MRID))
}

// ── helpers ───────────────────────────────────────────────────────────────────

func parseFirstLine(lineRef string) int {
	var n int
	fmt.Sscanf(strings.Split(lineRef, "-")[0], "%d", &n)
	return n
}

func urlEncodeRepo(repo string) string {
	return strings.ReplaceAll(repo, "/", "%2F")
}
