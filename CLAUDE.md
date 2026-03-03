# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`gh-security` is a GitHub CLI extension (`gh extension`) that audits all repositories in a GitHub organisation for security misconfigurations. It is installed via `gh extension install .` and invoked as `gh security`.

## Build & Install

```bash
# Build
go build -o gh-security

# Install as gh extension (for local testing)
gh extension install .

# Run
gh security --org <orgname>
gh security --org <orgname> --json
gh security --org <orgname> --verbose
```

There are no automated tests in this codebase.

## Architecture

### Entry Point & CLI

- `main.go` → `cmd.Execute()` → Cobra root command in `cmd/root.go`
- All flags are registered in `cmd/root.go:init()` and bound to package-level vars
- The `run()` function in `cmd/root.go` orchestrates the entire pipeline

### Processing Pipeline (in order)

1. Validate `--org` is set
2. Create `github.Client`
3. Fetch org-level checks: fork PR approval policy, default workflow permissions
4. `ListOrgRepos()` — paginated, returns `[]github.Repo` with `HasWiki` already included
5. 10-worker goroutine pool over repos:
   a. `GetRepoActionsPermissions` → `CheckRepoActionsEnabled`
   b. `GetRepoWorkflowPermissions` → `CheckRepoWorkflowPermissions`
   c. `ListWorkflowFiles` → for each .yml/.yaml → `GetFileContent` → `CheckWorkflowFilePermissions`
   d. `repo.HasWiki` from list response → `CheckWikiEnabled`
   e. If `has_wiki`: append `WikiRestrictionNote()`
6. Collect and sort results by repo name
7. Print via `report.Print()` or `report.PrintJSON()`

### Permission Degradation

Admin-gated API calls (`GetRepoActionsPermissions`, `GetRepoWorkflowPermissions`, `GetOrgForkPRApproval`, `GetOrgWorkflowPermissions`) return `(value, bool ok, error)`. When `ok=false` (HTTP 403/404), the caller emits a `WARN: insufficient permissions` finding and continues.

Publicly accessible calls (`ListWorkflowFiles`, `GetFileContent`) treat 404 as "nothing to check" and non-403/404 errors are surfaced as warnings.

### GitHub API Client

`internal/github/client.go` wraps `github.com/cli/go-gh/v2/pkg/api.DefaultRESTClient()`, which automatically picks up the user's `gh` CLI authentication token.

### Key Internal Packages

| Package | Responsibility |
|---|---|
| `internal/github` | REST client, `Repo`/`WorkflowFile` types, org/repo API calls |
| `internal/checks` | `Finding`/`Severity` types, all check functions |
| `internal/report` | `Print` (text with ANSI colour), `PrintJSON` |

### Checks Implemented

| Check | Severity | Notes |
|---|---|---|
| Fork PR approval policy | WARN | Expected: `all_external_contributors` |
| Org default workflow permissions | ALERT | Expected: `read` |
| Repo Actions enabled | WARN | — |
| Repo default workflow permissions | ALERT | Expected: `read` |
| Workflow YAML `permissions: write-all` | ALERT | Checked at workflow and job level |
| Workflow YAML scope with `write` | ALERT | Checked at workflow and job level |
| Wiki enabled | WARN | — |
| Wiki restriction | INFO | Cannot be checked via API — manual action note |

### Known Limitation

The "Restrict editing to collaborators only" wiki setting is not exposed by the GitHub REST API or GraphQL API. The tool surfaces an INFO-level note on repos with wikis enabled.
