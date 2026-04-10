package ociregistry

import (
	"context"
	"fmt"

	"oras.land/oras-go/v2/registry/remote"
)

// BaseClient provides common functionality for registry interactions.
type BaseClient struct {
	RepoTarget string
	PlainHTTP  bool
}

func (c *BaseClient) GetRepository(ctx context.Context) (*remote.Repository, error) {
	repo, err := remote.NewRepository(c.RepoTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}
	repo.PlainHTTP = c.PlainHTTP
	return repo, nil
}
