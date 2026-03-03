package github

import (
	"encoding/json"
	"fmt"
	"io"
)

// Repo represents a GitHub repository as returned by the org repos list endpoint.
type Repo struct {
	FullName string `json:"full_name"`
	Name     string `json:"name"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
	HasWiki  bool `json:"has_wiki"`
	Private  bool `json:"private"`
	Archived bool `json:"archived"`
}

type orgForkPRApproval struct {
	ApprovalPolicy string `json:"approval_policy"`
}

type orgWorkflowPermissions struct {
	DefaultWorkflowPermissions string `json:"default_workflow_permissions"`
}

// GetOrgForkPRApproval retrieves the fork PR contributor approval policy for an org.
// Returns (policy, ok, error). ok=false when the caller lacks admin access (HTTP 403/404).
func (c *Client) GetOrgForkPRApproval(org string) (string, bool, error) {
	path := fmt.Sprintf("orgs/%s/actions/permissions/fork-pr-contributor-approval", org)
	response, err := c.rest.Request("GET", path, nil)
	if err != nil {
		if isPermissionError(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to get fork PR approval policy: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", false, err
	}

	var result orgForkPRApproval
	if err := json.Unmarshal(body, &result); err != nil {
		return "", false, err
	}
	return result.ApprovalPolicy, true, nil
}

// GetOrgWorkflowPermissions retrieves the default workflow token permissions for an org.
// Returns (permissions, ok, error). ok=false when the caller lacks admin access (HTTP 403/404).
func (c *Client) GetOrgWorkflowPermissions(org string) (string, bool, error) {
	path := fmt.Sprintf("orgs/%s/actions/permissions/workflow", org)
	response, err := c.rest.Request("GET", path, nil)
	if err != nil {
		if isPermissionError(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to get org workflow permissions: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", false, err
	}

	var result orgWorkflowPermissions
	if err := json.Unmarshal(body, &result); err != nil {
		return "", false, err
	}
	return result.DefaultWorkflowPermissions, true, nil
}

// ListOrgRepos retrieves all repositories for an organization (paginated).
func (c *Client) ListOrgRepos(org string) ([]Repo, error) {
	return c.listReposPaginated(fmt.Sprintf("orgs/%s/repos", org))
}

// ListUserRepos retrieves all repositories for a GitHub user (paginated).
func (c *Client) ListUserRepos(username string) ([]Repo, error) {
	return c.listReposPaginated(fmt.Sprintf("users/%s/repos", username))
}

// listReposPaginated fetches all pages from a repos list endpoint.
func (c *Client) listReposPaginated(base string) ([]Repo, error) {
	var repos []Repo
	page := 1
	const perPage = 100

	for {
		path := fmt.Sprintf("%s?per_page=%d&page=%d", base, perPage, page)
		response, err := c.rest.Request("GET", path, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}

		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return nil, err
		}

		var pageRepos []Repo
		if err := json.Unmarshal(body, &pageRepos); err != nil {
			return nil, fmt.Errorf("failed to parse repositories response: %w", err)
		}

		if len(pageRepos) == 0 {
			break
		}
		repos = append(repos, pageRepos...)
		if len(pageRepos) < perPage {
			break
		}
		page++
	}

	return repos, nil
}
