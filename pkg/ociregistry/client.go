package ociregistry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"filippo.io/age"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

// BaseClient provides common functionality for registry interactions.
type BaseClient struct {
	RepoTarget       string
	PlainHTTP        bool
	DockerConfigPath string
}

func (c *BaseClient) GetRepository(ctx context.Context) (*remote.Repository, error) {
	repo, err := remote.NewRepository(c.RepoTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}
	repo.PlainHTTP = c.PlainHTTP

	var store credentials.Store
	if c.DockerConfigPath != "" {
		store, err = credentials.NewStore(c.DockerConfigPath, credentials.StoreOptions{})
	} else {
		store, err = credentials.NewStoreFromDocker(credentials.StoreOptions{})
	}

	if err == nil {
		repo.Client = &auth.Client{
			Client:     &http.Client{Transport: http.DefaultTransport},
			Cache:      auth.NewCache(),
			Credential: credentials.Credential(store),
		}
	}

	return repo, nil
}

// UnlockVault reconstructs the Vault Identity from the OCI config.
func (c *BaseClient) UnlockVault(ctx context.Context, repo *remote.Repository, identities []age.Identity) (age.Identity, *Config, *ocispec.Manifest, error) {
	manifestDesc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to resolve manifest: %w", err)
	}

	rc, err := repo.Fetch(ctx, manifestDesc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer rc.Close()

	var manifest ocispec.Manifest
	if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	rc, err = repo.Fetch(ctx, manifest.Config)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to fetch config: %w", err)
	}
	defer rc.Close()

	var config Config
	if err := json.NewDecoder(rc).Decode(&config); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode config: %w", err)
	}

	sheafBytes, err := base64.StdEncoding.DecodeString(config.Vault.VaultKeySheaf)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode vault keysheaf: %w", err)
	}

	ageReader, err := age.Decrypt(bytes.NewReader(sheafBytes), identities...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt vault key: %w", err)
	}

	vaultKeyBytes, err := io.ReadAll(ageReader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read decrypted vault key: %w", err)
	}

	vaultIdentity, err := age.ParseHybridIdentity(string(vaultKeyBytes))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse vault identity: %w", err)
	}

	return vaultIdentity, &config, &manifest, nil
}

// FetchIndex resolves everything and returns the decrypted index and the vault identity.
func (c *BaseClient) FetchIndex(ctx context.Context, identities []age.Identity) (*Index, age.Identity, *Config, *ocispec.Manifest, error) {
	repo, err := c.GetRepository(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	vaultIdentity, config, manifest, err := c.UnlockVault(ctx, repo, identities)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var indexLayerDesc *ocispec.Descriptor
	for _, l := range manifest.Layers {
		if l.MediaType == MediaTypeIndex {
			indexLayerDesc = &l
			break
		}
	}
	if indexLayerDesc == nil {
		return nil, nil, nil, nil, fmt.Errorf("index layer not found")
	}

	rc, err := repo.Fetch(ctx, *indexLayerDesc)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to fetch index: %w", err)
	}
	defer rc.Close()

	// Decrypt Index
	ageReader, err := age.Decrypt(rc, vaultIdentity)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to decrypt index: %w", err)
	}

	var index Index
	if err := json.NewDecoder(ageReader).Decode(&index); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse index JSON: %w", err)
	}

	return &index, vaultIdentity, config, manifest, nil
}
