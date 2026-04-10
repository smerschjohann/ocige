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

// FetchIndex resolves the manifest, identifies the index layer, and decrypts it.
func (p *Puller) FetchIndex(ctx context.Context, identities []age.Identity) (*Index, error) {
	repo, err := remote.NewRepository(p.RepoTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}
	repo.PlainHTTP = p.PlainHTTP

	// 1. Resolve manifest
	manifestDesc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve manifest: %w", err)
	}

	// 2. Fetch Manifest
	rc, err := repo.Fetch(ctx, manifestDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer rc.Close()

	var manifest ocispec.Manifest
	if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	// 3. Fetch Config
	rc, err = repo.Fetch(ctx, manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch config: %w", err)
	}
	defer rc.Close()

	var config Config
	if err := json.NewDecoder(rc).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	// 4. Identify and Fetch Index Layer
	var indexLayerDesc *ocispec.Descriptor
	for _, l := range manifest.Layers {
		if l.MediaType == MediaTypeIndex {
			indexLayerDesc = &l
			break
		}
	}
	if indexLayerDesc == nil {
		return nil, fmt.Errorf("index layer not found in manifest")
	}

	rc, err = repo.Fetch(ctx, *indexLayerDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch index layer: %w", err)
	}
	defer rc.Close()

	// 5. Decrypt Index
	headerBytes, err := base64.StdEncoding.DecodeString(config.Index.KeySheaf)
	if err != nil {
		return nil, fmt.Errorf("failed to decode index header: %w", err)
	}

	fullStream := io.MultiReader(bytes.NewReader(headerBytes), rc)
	ageReader, err := age.Decrypt(fullStream, identities...)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt index: %w", err)
	}

	var index Index
	if err := json.NewDecoder(ageReader).Decode(&index); err != nil {
		return nil, fmt.Errorf("failed to parse index JSON: %w", err)
	}

	return &index, nil
}

type readCloserWrapper struct {
	io.Reader
	closer func() error
}

func (r *readCloserWrapper) Close() error {
	return r.closer()
}

// PullFile streams a specific file from the registry using its index entry.
func (p *Puller) PullFile(ctx context.Context, entry FileEntry, identities []age.Identity) (io.ReadCloser, error) {
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
				pw.CloseWithError(fmt.Errorf("failed to fetch chunk: %w", err))
				return
			}
			if _, err := io.Copy(pw, rc); err != nil {
				rc.Close()
				pw.CloseWithError(fmt.Errorf("failed to stream chunk: %w", err))
				return
			}
			rc.Close()
		}
	}()

	fullStream := io.MultiReader(bytes.NewReader(headerBytes), pr)
	ageReader, err := age.Decrypt(fullStream, identities...)
	if err != nil {
		return nil, err
	}

	return &readCloserWrapper{
		Reader: ageReader,
		closer: func() error {
			return pr.Close()
		},
	}, nil
}
