package checks

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityAlert Severity = "ALERT"
	SeverityWarn  Severity = "WARN"
	SeverityInfo  Severity = "INFO"
	SeverityOK    Severity = "OK"
)

// Finding represents a single security finding.
type Finding struct {
	Severity Severity
	Check    string // short key used in JSON output
	Message  string // full human-readable text (printed after [SEVERITY])
}

// InsufficientPermissions returns a WARN finding for checks that require admin access.
func InsufficientPermissions(check string) Finding {
	return Finding{
		Severity: SeverityWarn,
		Check:    check,
		Message:  fmt.Sprintf("%s: insufficient permissions to verify (check requires admin access)", check),
	}
}

// CheckOrgForkPRApproval checks the fork PR contributor approval policy.
//
// Severity mapping:
//   - "all_external_contributors"  → OK   (most restrictive)
//   - "first_time_contributor"     → WARN (medium)
//   - "new_to_github"              → ALERT (too permissive)
//   - "not_required" / unknown     → ALERT (least restrictive)
func CheckOrgForkPRApproval(policy string) Finding {
	switch policy {
	case "all_external_contributors":
		return Finding{
			Severity: SeverityOK,
			Check:    "Fork PR Approval",
			Message:  `Fork PR Approval: "all_external_contributors" (compliant)`,
		}
	case "first_time_contributor":
		return Finding{
			Severity: SeverityWarn,
			Check:    "Fork PR Approval",
			Message:  `Fork PR Approval: "first_time_contributor" — consider requiring approval for all external contributors`,
		}
	default:
		return Finding{
			Severity: SeverityAlert,
			Check:    "Fork PR Approval",
			Message:  fmt.Sprintf(`Fork PR Approval: %q — expected "all_external_contributors"`, policy),
		}
	}
}

// CheckOrgWorkflowPermissions checks whether org default workflow permissions are write.
func CheckOrgWorkflowPermissions(perm string) Finding {
	if perm == "write" {
		return Finding{
			Severity: SeverityAlert,
			Check:    "Default Workflow Permissions",
			Message:  `Default Workflow Permissions: "write" — expected "read"`,
		}
	}
	return Finding{
		Severity: SeverityOK,
		Check:    "Default Workflow Permissions",
		Message:  fmt.Sprintf("Default Workflow Permissions: %q (compliant)", perm),
	}
}

// CheckRepoActionsEnabled checks whether GitHub Actions is enabled on a repository.
func CheckRepoActionsEnabled(enabled bool) Finding {
	if enabled {
		return Finding{
			Severity: SeverityWarn,
			Check:    "GitHub Actions",
			Message:  "GitHub Actions is enabled",
		}
	}
	return Finding{
		Severity: SeverityOK,
		Check:    "GitHub Actions",
		Message:  "GitHub Actions is disabled",
	}
}

// CheckActionsEnabledNoWorkflows returns an INFO finding when Actions is enabled but no
// workflow files exist, suggesting that Actions could safely be disabled.
func CheckActionsEnabledNoWorkflows() Finding {
	return Finding{
		Severity: SeverityInfo,
		Check:    "GitHub Actions",
		Message:  "GitHub Actions is enabled but no workflow files found in .github/workflows — consider disabling Actions",
	}
}

// CheckRepoWorkflowPermissions checks whether repo default workflow permissions are write.
func CheckRepoWorkflowPermissions(perm string) Finding {
	if perm == "write" {
		return Finding{
			Severity: SeverityAlert,
			Check:    "Repo Workflow Permissions",
			Message:  `Repo Workflow Permissions: "write" — expected "read"`,
		}
	}
	return Finding{
		Severity: SeverityOK,
		Check:    "Repo Workflow Permissions",
		Message:  fmt.Sprintf("Default workflow permissions: %s (compliant)", perm),
	}
}

// workflowYAML is used to unmarshal a GitHub Actions workflow file.
type workflowYAML struct {
	On          interface{}            `yaml:"on"`
	Permissions interface{}            `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Permissions interface{} `yaml:"permissions"`
}

// CheckWorkflowFilePermissions parses a workflow YAML and returns findings for
// overly permissive permission scopes (write-all or any scope set to write).
func CheckWorkflowFilePermissions(filename string, content []byte) []Finding {
	var workflow workflowYAML
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		// Can't parse — skip silently.
		return nil
	}

	var findings []Finding

	// Top-level permissions
	findings = append(findings, permissionFindings(filename, "workflow level", workflow.Permissions)...)

	// Per-job permissions
	for jobName, job := range workflow.Jobs {
		findings = append(findings, permissionFindings(filename, fmt.Sprintf("job %q", jobName), job.Permissions)...)
	}

	return findings
}

// CheckWorkflowTriggers checks for dangerous trigger configurations in a workflow file.
// It reports pull_request_target, which runs with the target repo's write permissions
// while checking out code from the contributor's fork.
func CheckWorkflowTriggers(filename string, content []byte) []Finding {
	var workflow workflowYAML
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return nil
	}

	if hasPullRequestTarget(workflow.On) {
		return []Finding{{
			Severity: SeverityAlert,
			Check:    filename,
			Message:  fmt.Sprintf("%s: uses pull_request_target — runs with target repo permissions but may execute code from a contributor's fork", filename),
		}}
	}
	return nil
}

// hasPullRequestTarget reports whether the workflow's on: field includes pull_request_target.
// The field can be a string, a sequence, or a map.
func hasPullRequestTarget(on interface{}) bool {
	switch v := on.(type) {
	case string:
		return v == "pull_request_target"
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == "pull_request_target" {
				return true
			}
		}
	case map[string]interface{}:
		_, ok := v["pull_request_target"]
		return ok
	}
	return false
}

// permissionFindings evaluates a permissions value (string or map) and returns findings.
func permissionFindings(filename, context string, perms interface{}) []Finding {
	if perms == nil {
		return nil
	}

	switch p := perms.(type) {
	case string:
		if p == "write-all" {
			return []Finding{{
				Severity: SeverityAlert,
				Check:    filename,
				Message:  fmt.Sprintf("%s: permissions \"write-all\" at %s", filename, context),
			}}
		}
	case map[string]interface{}:
		var findings []Finding
		for scope, val := range p {
			if valStr, ok := val.(string); ok && valStr == "write" {
				findings = append(findings, Finding{
					Severity: SeverityAlert,
					Check:    filename,
					Message:  fmt.Sprintf("%s: %s has %s: write", filename, context, scope),
				})
			}
		}
		return findings
	}
	return nil
}
