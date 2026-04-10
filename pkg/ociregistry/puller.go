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
	"golang.org/x/sync/errgroup"
	"os"
	"sync"
)

type Puller struct {
	BaseClient
	Concurrency int
	Silent      bool
}

func NewPuller(target string) *Puller {
	return &Puller{
		BaseClient: BaseClient{
			RepoTarget: target,
			PlainHTTP:  false,
		},
		Concurrency: 5,
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
	pm := NewProgressManager(p.Silent)

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(p.Concurrency)

	go func() {
		defer pw.Close()
		defer pm.Wait()

		type chunkResult struct {
			tempPath string
			err      error
		}
		
		results := make(map[int]string)
		var mu sync.Mutex
		nextOrder := 0
		
		// To avoid overwhelming the results map, we use a channel to communicate finished chunks
		finishedChunks := make(chan int, len(entry.Chunks))

		for i, chunk := range entry.Chunks {
			desc := ocispec.Descriptor{
				MediaType: MediaTypeLayer,
				Digest:    digest.Digest(chunk.Digest),
				Size:      chunk.SizeEncrypted,
			}
			
			chunkOrder := i
			g.Go(func() error {
				rc, err := repo.Fetch(gCtx, desc)
				if err != nil {
					return err
				}
				defer rc.Close()

				label := fmt.Sprintf("%s [%d]", entry.Path, chunkOrder)
				tr := pm.TrackReader(fmt.Sprintf("%s-%d", entry.Path, chunkOrder), label, chunk.SizeEncrypted, rc)
				defer tr.Close()
				
				tempFile, err := os.CreateTemp("", "ocige-pull-chunk-*")
				if err != nil {
					return err
				}
				tempPath := tempFile.Name()
				
				if _, err := io.Copy(tempFile, tr); err != nil {
					tempFile.Close()
					os.Remove(tempPath)
					return err
				}
				tempFile.Close()

				mu.Lock()
				results[chunkOrder] = tempPath
				mu.Unlock()
				finishedChunks <- chunkOrder
				return nil
			})
		}

		// Wait for chunks and stream them in order
		for nextOrder < len(entry.Chunks) {
			mu.Lock()
			tempPath, ok := results[nextOrder]
			mu.Unlock()

			if ok {
				f, err := os.Open(tempPath)
				if err != nil {
					pw.CloseWithError(err)
					return
				}
				io.Copy(pw, f)
				f.Close()
				os.Remove(tempPath)
				nextOrder++
			} else {
				// Wait for a chunk to be finished
				select {
				case <-finishedChunks:
					continue
				case <-gCtx.Done():
					pw.CloseWithError(gCtx.Err())
					return
				}
			}
		}

		if err := g.Wait(); err != nil {
			pw.CloseWithError(err)
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

