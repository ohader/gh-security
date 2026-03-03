package github

import (
	"errors"

	"github.com/cli/go-gh/v2/pkg/api"
)

// Client wraps the GitHub API client
type Client struct {
	rest *api.RESTClient
}

// NewClient creates a new GitHub API client using gh CLI's authentication
func NewClient() (*Client, error) {
	rest, err := api.DefaultRESTClient()
	if err != nil {
		return nil, err
	}
	return &Client{rest: rest}, nil
}

// httpStatusCode extracts the HTTP status code from a go-gh API error, or 0 if not applicable.
func httpStatusCode(err error) int {
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode
	}
	return 0
}

// isPermissionError returns true for HTTP 403/404 responses that indicate insufficient access.
func isPermissionError(err error) bool {
	code := httpStatusCode(err)
	return code == 403 || code == 404
}
