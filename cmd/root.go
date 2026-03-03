package cmd

import (
	"fmt"
	"os"
	"sort"

	"github.com/ohader/gh-security/internal/checks"
	"github.com/ohader/gh-security/internal/github"
	"github.com/ohader/gh-security/internal/report"
	"github.com/spf13/cobra"
)

var (
	org         string
	user        string
	repoName    string
	jsonOutput  bool
	verbose     bool
	alertOnly   bool
	publicOnly  bool
	privateOnly bool
)

var rootCmd = &cobra.Command{
	Use:   "gh-security",
	Short: "Audit GitHub organisation repositories for security misconfigurations",
	Long: `Scans all repositories in a GitHub organisation and reports security findings:

  - Whether GitHub Actions is enabled on each repo
  - Whether any workflow YAML uses overly permissive permissions
  - Whether the org fork PR approval policy requires approval for all external contributors
  - Whether the org/repo default workflow token permissions is set to write
  - Whether the wiki is enabled on each repo

Examples:
  gh security --org myorg
  gh security --user someuser
  gh security --org myorg --json
  gh security --org myorg --verbose`,
	RunE: run,
}

func init() {
	rootCmd.Flags().StringVar(&org, "org", "", "GitHub organisation name to audit")
	rootCmd.Flags().StringVar(&user, "user", "", "GitHub username whose repositories to audit")
	rootCmd.Flags().StringVar(&repoName, "repo", "", "Restrict scan to a single repository name within --org or --user")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output findings as JSON")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print progress to stderr")
	rootCmd.Flags().BoolVar(&alertOnly, "alert", false, "Show only ALERT findings")
	rootCmd.Flags().BoolVar(&publicOnly, "public", false, "Show only public repositories")
	rootCmd.Flags().BoolVar(&privateOnly, "private", false, "Show only private repositories")
}

// Execute is the entry point called from main.
func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	if org == "" && user == "" {
		return fmt.Errorf("--org or --user is required")
	}
	if org != "" && user != "" {
		return fmt.Errorf("--org and --user are mutually exclusive")
	}
	if publicOnly && privateOnly {
		return fmt.Errorf("--public and --private are mutually exclusive")
	}

	client, err := github.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w\nHint: Run 'gh auth login' to authenticate", err)
	}

	var orgFindings []checks.Finding
	var repos []github.Repo
	var title string

	if org != "" {
		title = "Organization: " + org
		logf("Checking org-level settings for %s…", org)

		forkPolicy, ok, err := client.GetOrgForkPRApproval(org)
		if err != nil {
			return fmt.Errorf("failed to check fork PR approval: %w", err)
		}
		if !ok {
			orgFindings = append(orgFindings, checks.InsufficientPermissions("Fork PR Approval"))
		} else {
			orgFindings = append(orgFindings, checks.CheckOrgForkPRApproval(forkPolicy))
		}

		orgWorkflowPerm, ok, err := client.GetOrgWorkflowPermissions(org)
		if err != nil {
			return fmt.Errorf("failed to check org workflow permissions: %w", err)
		}
		if !ok {
			orgFindings = append(orgFindings, checks.InsufficientPermissions("Default Workflow Permissions"))
		} else {
			orgFindings = append(orgFindings, checks.CheckOrgWorkflowPermissions(orgWorkflowPerm))
		}

		repos, err = listOrFetch(client, repoName, org, client.ListOrgRepos)
		if err != nil {
			return err
		}
	} else {
		title = "User: " + user
		repos, err = listOrFetch(client, repoName, user, client.ListUserRepos)
		if err != nil {
			return err
		}
	}

	logf("Found %d repositories", len(repos))

	// Filter out archived repositories
	var active []github.Repo
	for _, r := range repos {
		if r.Archived {
			logf("Skipping archived repository: %s", r.FullName)
		} else {
			active = append(active, r)
		}
	}
	repos = active

	if len(repos) == 0 {
		return printResults(title, orgFindings, nil)
	}

	// --- Concurrent repo scanning ---
	const maxWorkers = 10
	numWorkers := maxWorkers
	if len(repos) < numWorkers {
		numWorkers = len(repos)
	}

	type repoJob struct {
		repo github.Repo
	}
	type repoResult struct {
		result report.RepoResult
		err    error
	}

	jobs := make(chan github.Repo, len(repos))
	results := make(chan repoResult, len(repos))

	for w := 0; w < numWorkers; w++ {
		go func() {
			for repo := range jobs {
				r, err := scanRepo(client, repo)
				results <- repoResult{result: r, err: err}
			}
		}()
	}

	for _, repo := range repos {
		jobs <- repo
	}
	close(jobs)

	var repoResults []report.RepoResult
	for range repos {
		res := <-results
		if res.err != nil {
			logf("Warning: error scanning %s: %v", res.result.Name, res.err)
			continue
		}
		repoResults = append(repoResults, res.result)
	}

	// Sort by repo name for deterministic output
	sort.Slice(repoResults, func(i, j int) bool {
		return repoResults[i].Name < repoResults[j].Name
	})

	return printResults(title, orgFindings, repoResults)
}

// scanRepo performs all per-repository checks and returns a RepoResult.
func scanRepo(client *github.Client, repo github.Repo) (report.RepoResult, error) {
	rr := report.RepoResult{Name: repo.FullName, Private: repo.Private}

	logf("Scanning %s…", repo.FullName)

	// Actions enabled
	enabled, actionsOk, err := client.GetRepoActionsPermissions(repo.FullName)
	if err != nil {
		return rr, fmt.Errorf("GetRepoActionsPermissions: %w", err)
	}
	if !actionsOk {
		rr.Findings = append(rr.Findings, checks.InsufficientPermissions("GitHub Actions"))
	} else {
		rr.Findings = append(rr.Findings, checks.CheckRepoActionsEnabled(enabled))
	}

	// Fork PR contributor approval (repo-level)
	forkPolicy, ok, err := client.GetRepoForkPRApproval(repo.FullName)
	if err != nil {
		return rr, fmt.Errorf("GetRepoForkPRApproval: %w", err)
	}
	if !ok {
		rr.Findings = append(rr.Findings, checks.InsufficientPermissions("Fork PR Approval"))
	} else {
		rr.Findings = append(rr.Findings, checks.CheckOrgForkPRApproval(forkPolicy))
	}

	// Repo workflow permissions
	repoWorkflowPerm, ok, err := client.GetRepoWorkflowPermissions(repo.FullName)
	if err != nil {
		return rr, fmt.Errorf("GetRepoWorkflowPermissions: %w", err)
	}
	if !ok {
		rr.Findings = append(rr.Findings, checks.InsufficientPermissions("Repo Workflow Permissions"))
	} else {
		rr.Findings = append(rr.Findings, checks.CheckRepoWorkflowPermissions(repoWorkflowPerm))
	}

	// Workflow file permissions
	workflowFiles, err := client.ListWorkflowFiles(repo.FullName)
	workflowListOk := err == nil
	if err != nil {
		logf("Warning: could not list workflow files for %s: %v", repo.FullName, err)
	} else {
		for _, wf := range workflowFiles {
			content, err := client.GetFileContent(repo.FullName, wf.Path)
			if err != nil {
				logf("Warning: could not fetch %s/%s: %v", repo.FullName, wf.Path, err)
				continue
			}
			rr.Findings = append(rr.Findings, checks.CheckWorkflowFilePermissions(wf.Name, content)...)
			rr.Findings = append(rr.Findings, checks.CheckWorkflowTriggers(wf.Name, content)...)
		}
	}

	// Actions enabled with no workflow files → suggest disabling
	if actionsOk && enabled && workflowListOk && len(workflowFiles) == 0 {
		rr.Findings = append(rr.Findings, checks.CheckActionsEnabledNoWorkflows())
	}

	// Wiki — only relevant for public repositories
	if !repo.Private {
		rr.Findings = append(rr.Findings, checks.CheckWikiEnabled(repo.HasWiki))
		if repo.HasWiki {
			rr.Findings = append(rr.Findings, checks.WikiRestrictionNote())
		}
	}

	return rr, nil
}

func printResults(title string, orgFindings []checks.Finding, repoResults []report.RepoResult) error {
	if publicOnly {
		repoResults = filterByVisibility(repoResults, false)
	} else if privateOnly {
		repoResults = filterByVisibility(repoResults, true)
	}
	if alertOnly {
		orgFindings = filterAlerts(orgFindings)
		var filtered []report.RepoResult
		for _, rr := range repoResults {
			rr.Findings = filterAlerts(rr.Findings)
			if len(rr.Findings) > 0 {
				filtered = append(filtered, rr)
			}
		}
		repoResults = filtered
	}
	if jsonOutput {
		return report.PrintJSON(title, orgFindings, repoResults)
	}
	report.Print(title, orgFindings, repoResults)
	return nil
}

// listOrFetch returns either a single repo (when repoName is set) or the full list for owner.
func listOrFetch(client *github.Client, repoName, owner string, listFn func(string) ([]github.Repo, error)) ([]github.Repo, error) {
	if repoName != "" {
		logf("Fetching repository %s/%s…", owner, repoName)
		r, err := client.GetRepo(owner + "/" + repoName)
		if err != nil {
			return nil, fmt.Errorf("failed to get repository: %w", err)
		}
		return []github.Repo{r}, nil
	}
	logf("Fetching repositories for %s…", owner)
	repos, err := listFn(owner)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}
	return repos, nil
}

// filterByVisibility keeps only repos matching the given private flag.
func filterByVisibility(repoResults []report.RepoResult, private bool) []report.RepoResult {
	var out []report.RepoResult
	for _, rr := range repoResults {
		if rr.Private == private {
			out = append(out, rr)
		}
	}
	return out
}

// filterAlerts returns only findings with severity ALERT.
func filterAlerts(findings []checks.Finding) []checks.Finding {
	var out []checks.Finding
	for _, f := range findings {
		if f.Severity == checks.SeverityAlert {
			out = append(out, f)
		}
	}
	return out
}

func logf(format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}
