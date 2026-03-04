package github

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GetRepo fetches metadata for a single repository.
// fullName is "owner/repo".
func (c *Client) GetRepo(fullName string) (Repo, error) {
	response, err := c.rest.Request("GET", fmt.Sprintf("repos/%s", fullName), nil)
	if err != nil {
		return Repo{}, fmt.Errorf("failed to get repository %s: %w", fullName, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return Repo{}, err
	}

	var repo Repo
	if err := json.Unmarshal(body, &repo); err != nil {
		return Repo{}, err
	}
	return repo, nil
}

// WorkflowFile represents an entry in the .github/workflows directory listing.
type WorkflowFile struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

type repoForkPRApproval struct {
	ApprovalPolicy string `json:"approval_policy"`
}

// GetRepoForkPRApproval retrieves the fork PR contributor approval policy for a repository.
// Returns (policy, ok, error). ok=false when the caller lacks admin access (HTTP 403/404).
func (c *Client) GetRepoForkPRApproval(fullName string) (string, bool, error) {
	path := fmt.Sprintf("repos/%s/actions/permissions/fork-pr-contributor-approval", fullName)
	response, err := c.rest.Request("GET", path, nil)
	if err != nil {
		if isPermissionError(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to get repo fork PR approval policy: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", false, err
	}

	var result repoForkPRApproval
	if err := json.Unmarshal(body, &result); err != nil {
		return "", false, err
	}
	return result.ApprovalPolicy, true, nil
}

type repoActionsPermissions struct {
	Enabled bool `json:"enabled"`
}

type repoWorkflowPermissions struct {
	DefaultWorkflowPermissions string `json:"default_workflow_permissions"`
}

type fileContent struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// GetRepoActionsPermissions returns whether Actions is enabled on a repository.
// fullName is "owner/repo". Returns (enabled, ok, error). ok=false on HTTP 403/404.
func (c *Client) GetRepoActionsPermissions(fullName string) (bool, bool, error) {
	path := fmt.Sprintf("repos/%s/actions/permissions", fullName)
	response, err := c.rest.Request("GET", path, nil)
	if err != nil {
		if isPermissionError(err) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("failed to get repo actions permissions: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false, false, err
	}

	var result repoActionsPermissions
	if err := json.Unmarshal(body, &result); err != nil {
		return false, false, err
	}
	return result.Enabled, true, nil
}

// GetRepoWorkflowPermissions returns the default workflow token permissions for a repository.
// fullName is "owner/repo". Returns (perm, ok, error). ok=false on HTTP 403/404.
func (c *Client) GetRepoWorkflowPermissions(fullName string) (string, bool, error) {
	path := fmt.Sprintf("repos/%s/actions/permissions/workflow", fullName)
	response, err := c.rest.Request("GET", path, nil)
	if err != nil {
		if isPermissionError(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to get repo workflow permissions: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", false, err
	}

	var result repoWorkflowPermissions
	if err := json.Unmarshal(body, &result); err != nil {
		return "", false, err
	}
	return result.DefaultWorkflowPermissions, true, nil
}

// ListWorkflowFiles returns YAML files in .github/workflows for a repository.
// A 404 (directory absent) is treated as an empty list (ok). A 403 is returned as an error.
// fullName is "owner/repo".
func (c *Client) ListWorkflowFiles(fullName string) ([]WorkflowFile, error) {
	path := fmt.Sprintf("repos/%s/contents/.github/workflows", fullName)
	response, err := c.rest.Request("GET", path, nil)
	if err != nil {
		if httpStatusCode(err) == 404 {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list workflow files: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var files []WorkflowFile
	if err := json.Unmarshal(body, &files); err != nil {
		return nil, err
	}

	var yamlFiles []WorkflowFile
	for _, f := range files {
		if f.Type == "file" && (strings.HasSuffix(f.Name, ".yml") || strings.HasSuffix(f.Name, ".yaml")) {
			yamlFiles = append(yamlFiles, f)
		}
	}
	return yamlFiles, nil
}

// HasWikiPages reports whether the wiki for a public repository has at least one page.
// GitHub redirects /wiki to the repo root when no pages exist; a 200 means pages exist.
func (c *Client) HasWikiPages(fullName string) (bool, error) {
	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedirect.Get(fmt.Sprintf("https://github.com/%s/wiki", fullName))
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// GetFileContent fetches a file from a repository and returns its decoded contents.
// fullName is "owner/repo", filePath is the path within the repo.
func (c *Client) GetFileContent(fullName, filePath string) ([]byte, error) {
	apiPath := fmt.Sprintf("repos/%s/contents/%s", fullName, filePath)
	response, err := c.rest.Request("GET", apiPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get file content: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var fc fileContent
	if err := json.Unmarshal(body, &fc); err != nil {
		return nil, err
	}

	if fc.Encoding != "base64" {
		return []byte(fc.Content), nil
	}

	// GitHub wraps base64 content with newlines — strip before decoding.
	cleaned := strings.ReplaceAll(fc.Content, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 content: %w", err)
	}
	return decoded, nil
}
