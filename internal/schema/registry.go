package schema

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Registry struct {
	baseURL string
	groupID string
	client  *http.Client
	strict  bool
}

type Config struct {
	URL     string
	GroupID string
	Strict  bool
}

func NewRegistry(cfg Config) *Registry {
	return &Registry{
		baseURL: strings.TrimRight(cfg.URL, "/"),
		groupID: cfg.GroupID,
		strict:  cfg.Strict,
		client:  &http.Client{Timeout: 5 * time.Second},
	}
}

func (r *Registry) Validate(ctx context.Context, schemaID, schemaVersion string) error {
	if r == nil || r.baseURL == "" {
		return nil
	}
	if strings.TrimSpace(schemaID) == "" || strings.TrimSpace(schemaVersion) == "" {
		return fmt.Errorf("schema_id and schema_version are required")
	}
	endpoint := fmt.Sprintf("%s/apis/registry/v2/groups/%s/artifacts/%s/versions/%s",
		r.baseURL,
		url.PathEscape(r.groupID),
		url.PathEscape(schemaID),
		url.PathEscape(schemaVersion),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		if r.strict {
			return fmt.Errorf("schema registry unavailable: %w", err)
		}
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("schema is not registered: %s version %s", schemaID, schemaVersion)
	}
	if r.strict {
		return fmt.Errorf("schema registry validation failed: status %d", resp.StatusCode)
	}
	return nil
}
