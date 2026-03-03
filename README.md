# gh-security — GitHub Organisation Security Scanner

A GitHub CLI extension that audits all repositories in a GitHub organisation for common security misconfigurations.

## Checks

| Severity | Check | Details |
|----------|-------|---------|
| `WARN`  | Fork PR approval policy | Organisation should require approval from all external contributors |
| `ALERT` | Org default workflow permissions | Token should be `read`, not `write` |
| `WARN`  | GitHub Actions enabled | Flags every repo where Actions is turned on |
| `ALERT` | Repo default workflow permissions | Token should be `read`, not `write` |
| `ALERT` | Workflow `permissions: write-all` | Detected at workflow level and per-job |
| `ALERT` | Workflow scope set to `write` | Any individual permission scope (e.g. `contents: write`) |
| `WARN`  | Wiki enabled | Wiki surfaces an unnecessary attack surface |
| `INFO`  | Wiki restriction | Cannot be verified via the API — manual check required |

## Installation

### From GitHub (end users)

```bash
gh extension install ohader/gh-security
```

### From source (developers)

```bash
git clone https://github.com/ohader/gh-security.git
cd gh-security
go build -o gh-security
gh extension install .
```

### Prerequisites

- [GitHub CLI](https://cli.github.com/) installed and authenticated
- Go 1.21 or later (only needed when building from source)

```bash
gh auth login
```

## Usage

```
gh security --org <orgname> [--json] [--verbose]
```

### Flags

| Flag | Required | Description |
|------|----------|-------------|
| `--org` | Yes | GitHub organisation name to audit |
| `--json` | No | Output all findings as a JSON array |
| `--verbose` / `-v` | No | Print progress to stderr while scanning |

### Examples

```bash
# Audit an organisation
gh security --org myorg

# Machine-readable output
gh security --org myorg --json

# Show progress while scanning a large org
gh security --org myorg --verbose
```

## Sample output

```
Organization: myorg

=== Organization-Level Checks ===
[ALERT]  Fork PR Approval: policy is "first_time_contributors" — expected "all_external_contributors"
[OK]     Default Workflow Permissions: "read" (compliant)

=== Repository: myorg/api ===
[ALERT]  GitHub Actions is enabled
[ALERT]  ci.yml: permissions "write-all" at workflow level
[ALERT]  ci.yml: job "deploy" has contents: write
[WARN]   Wiki is enabled
[INFO]   Wiki restriction ('Restrict editing to collaborators only') cannot be verified via the GitHub API — check manually in repo Settings → General → Wiki

=== Repository: myorg/website ===
[WARN]   GitHub Actions: insufficient permissions to verify (check requires admin access)
[OK]     Wiki is disabled

=== Repository: myorg/docs ===
[OK]     GitHub Actions is disabled
[OK]     Default workflow permissions: read (compliant)
[OK]     Wiki is disabled

=== Summary ===
Repositories scanned: 3  |  ALERT: 3  |  WARN: 2  |  INFO: 1
```

## JSON output

`--json` produces a flat array. Each finding has five fields:

```json
[
  {
    "scope": "org",
    "repository": "",
    "severity": "ALERT",
    "check": "Fork PR Approval",
    "message": "Fork PR Approval: policy is \"first_time_contributors\" — expected \"all_external_contributors\""
  },
  {
    "scope": "repo",
    "repository": "myorg/api",
    "severity": "ALERT",
    "check": "ci.yml",
    "message": "ci.yml: permissions \"write-all\" at workflow level"
  }
]
```

| Field | Values |
|-------|--------|
| `scope` | `"org"` or `"repo"` |
| `repository` | full name (`owner/repo`), empty for org-level findings |
| `severity` | `"ALERT"`, `"WARN"`, `"INFO"`, or `"OK"` |
| `check` | short category key |
| `message` | full human-readable description |

## Required permissions

Some checks require elevated access. When the authenticated token lacks the necessary permissions the tool emits a `WARN: insufficient permissions` finding and continues — it never crashes on a 403 or 404.

| Check | Minimum required scope |
|-------|------------------------|
| Fork PR approval policy | Org owner / `admin:org` |
| Org default workflow permissions | Org owner / `admin:org` |
| Repo Actions enabled | Repo admin |
| Repo default workflow permissions | Repo admin |
| Workflow YAML content | Public repos: none; private repos: `repo` or `read:repo` |
| Wiki status (`has_wiki`) | None (included in the org repos list) |

## Known limitation

The **"Restrict editing to collaborators only"** wiki setting is not exposed by the GitHub REST API or GraphQL API. The tool surfaces an `INFO` note on every repo where the wiki is enabled, prompting a manual check in **Settings → General → Wiki**.

## License

MIT License
