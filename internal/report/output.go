package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ohader/gh-security/internal/checks"
)

// RepoResult holds all findings for a single repository.
type RepoResult struct {
	Name     string
	Private  bool
	Findings []checks.Finding
}

// ansi colour helpers
const (
	colRed    = "\033[31m"
	colYellow = "\033[33m"
	colCyan   = "\033[36m"
	colGreen  = "\033[32m"
	colReset  = "\033[0m"
)

func severityLabel(s checks.Severity) string {
	label := fmt.Sprintf("%-8s", "["+string(s)+"]")
	switch s {
	case checks.SeverityAlert:
		return colRed + label + colReset
	case checks.SeverityWarn:
		return colYellow + label + colReset
	case checks.SeverityInfo:
		return colCyan + label + colReset
	case checks.SeverityOK:
		return colGreen + label + colReset
	}
	return label
}

func printFinding(f checks.Finding) {
	fmt.Printf("%s %s\n", severityLabel(f.Severity), f.Message)
}

// Print writes human-readable, ANSI-coloured output to stdout.
// title is the first header line, e.g. "Organization: myorg" or "User: someuser".
func Print(title string, orgFindings []checks.Finding, repoResults []RepoResult) {
	fmt.Printf("%s\n\n", title)

	if len(orgFindings) > 0 {
		fmt.Println("=== Organization-Level Checks ===")
		for _, f := range orgFindings {
			printFinding(f)
		}
	}

	counts := map[checks.Severity]int{}

	for _, rr := range repoResults {
		visibility := "public"
		if rr.Private {
			visibility = "private"
		}
		fmt.Printf("\n=== Repository: %s (https://github.com/%s) [%s] ===\n", rr.Name, rr.Name, visibility)
		for _, f := range rr.Findings {
			printFinding(f)
			counts[f.Severity]++
		}
	}

	for _, f := range orgFindings {
		counts[f.Severity]++
	}

	total := len(repoResults)
	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Repositories scanned: %d  |  ALERT: %d  |  WARN: %d  |  INFO: %d\n",
		total,
		counts[checks.SeverityAlert],
		counts[checks.SeverityWarn],
		counts[checks.SeverityInfo],
	)
}

// jsonFinding is the wire format for JSON output.
type jsonFinding struct {
	Scope      string `json:"scope"`
	Repository string `json:"repository"`
	Severity   string `json:"severity"`
	Check      string `json:"check"`
	Message    string `json:"message"`
}

// PrintJSON writes a flat JSON array of all findings to stdout.
func PrintJSON(_ string, orgFindings []checks.Finding, repoResults []RepoResult) error {
	var out []jsonFinding

	for _, f := range orgFindings {
		out = append(out, jsonFinding{
			Scope:      "org",
			Repository: "",
			Severity:   string(f.Severity),
			Check:      f.Check,
			Message:    f.Message,
		})
	}

	for _, rr := range repoResults {
		for _, f := range rr.Findings {
			out = append(out, jsonFinding{
				Scope:      "repo",
				Repository: rr.Name,
				Severity:   string(f.Severity),
				Check:      f.Check,
				Message:    f.Message,
			})
		}
	}

	if out == nil {
		out = []jsonFinding{}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
