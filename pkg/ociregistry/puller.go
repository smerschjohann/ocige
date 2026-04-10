package ociregistry

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Puller struct {
	BaseClient
}

func NewPuller(target string) *Puller {
	return &Puller{
		BaseClient: BaseClient{
			RepoTarget: target,
			PlainHTTP:  false,
		},
	}
}

// FetchIndex resolves everything and returns the decrypted index and the vault identity.
func (p *Puller) FetchIndex(ctx context.Context, identities []age.Identity) (*Index, age.Identity, error) {
	idx, vaultId, _, _, err := p.BaseClient.FetchIndex(ctx, identities)
	return idx, vaultId, err
}

// PullFile streams a specific file using the vault identity.
func (p *Puller) PullFile(ctx context.Context, entry FileEntry, vaultIdentity age.Identity) (io.ReadCloser, error) {
	repo, err := p.GetRepository(ctx)
	if err != nil {
		return nil, err
	}

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

