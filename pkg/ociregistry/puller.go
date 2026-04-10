package ociregistry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
)

type Puller struct {
	RepoTarget string
	PlainHTTP  bool
}

func NewPuller(target string) *Puller {
	return &Puller{
		RepoTarget: target,
		PlainHTTP:  false,
	}
}

// unlockVault reconstructs the Vault Identity from the OCI config.
func (p *Puller) unlockVault(ctx context.Context, repo *remote.Repository, identities []age.Identity) (age.Identity, *Config, *ocispec.Manifest, error) {
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
func (p *Puller) FetchIndex(ctx context.Context, identities []age.Identity) (*Index, age.Identity, error) {
	repo, err := remote.NewRepository(p.RepoTarget)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create repository: %w", err)
	}
	repo.PlainHTTP = p.PlainHTTP

	vaultIdentity, _, manifest, err := p.unlockVault(ctx, repo, identities)
	if err != nil {
		return nil, nil, err
	}

	var indexLayerDesc *ocispec.Descriptor
	for _, l := range manifest.Layers {
		if l.MediaType == MediaTypeIndex {
			indexLayerDesc = &l
			break
		}
	}
	if indexLayerDesc == nil {
		return nil, nil, fmt.Errorf("index layer not found")
	}

	rc, err := repo.Fetch(ctx, *indexLayerDesc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch index: %w", err)
	}
	defer rc.Close()

	// 5. Decrypt Index
	ageReader, err := age.Decrypt(rc, vaultIdentity)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt index: %w", err)
	}

	var index Index
	if err := json.NewDecoder(ageReader).Decode(&index); err != nil {
		return nil, nil, fmt.Errorf("failed to parse index JSON: %w", err)
	}

	return &index, vaultIdentity, nil
}

// PullFile streams a specific file using the vault identity.
func (p *Puller) PullFile(ctx context.Context, entry FileEntry, vaultIdentity age.Identity) (io.ReadCloser, error) {
	repo, err := remote.NewRepository(p.RepoTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}
	repo.PlainHTTP = p.PlainHTTP

	headerBytes, err := base64.StdEncoding.DecodeString(entry.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file header: %w", err)
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for _, chunk := range entry.Chunks {
			desc := ocispec.Descriptor{
				MediaType: MediaTypeLayer,
				Digest:    digest.Digest(chunk.Digest),
				Size:      chunk.SizeEncrypted,
			}
			rc, err := repo.Fetch(ctx, desc)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			io.Copy(pw, rc)
			rc.Close()
		}
	}()

	fullStream := io.MultiReader(bytes.NewReader(headerBytes), pr)
	ageReader, err := age.Decrypt(fullStream, vaultIdentity)
	if err != nil {
		return nil, err
	}

	return &readCloserWrapper{
		Reader: ageReader,
		closer: func() error { return pr.Close() },
	}, nil
}

type readCloserWrapper struct {
	io.Reader
	closer func() error
}

func (r *readCloserWrapper) Close() error { return r.closer() }

