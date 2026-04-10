package ociregistry

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"

	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"

	"filippo.io/age"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
)

type Puller struct {
	BaseClient
	Concurrency int
	Silent      bool
	Retries     int
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

// PullMultiple streams multiple files concurrently using the vault identity.
func (p *Puller) PullMultiple(ctx context.Context, files []FileEntry, vaultIdentity age.Identity, destDir string) error {
	pm := NewProgressManager(p.Silent)
	defer pm.Wait()

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(p.Concurrency)

	sem := make(chan struct{}, p.Concurrency)

	for _, entry := range files {
		entry := entry // capture
		g.Go(func() error {
			pm.Message(fmt.Sprintf("  -> Pulling %s...", entry.Path))

			fileReader, err := p.PullFileInternal(gCtx, entry, vaultIdentity, pm, sem)
			if err != nil {
				return fmt.Errorf("failed to decrypt %s: %w", entry.Path, err)
			}
			defer fileReader.Close()

			outPath := filepath.Join(destDir, entry.Path)
			if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
				return err
			}

			out, err := os.Create(outPath)
			if err != nil {
				return err
			}
			defer out.Close()

			if _, err := io.Copy(out, fileReader); err != nil {
				os.Remove(outPath)
				return fmt.Errorf("failed to stream %s: %w", entry.Path, err)
			}
			return nil
		})
	}

	err := g.Wait()
	if err != nil {
		pm.AbortAll()
	}
	return err
}

// PullFileInternal streams a specific file using the given global semaphore and progress manager.
func (p *Puller) PullFileInternal(ctx context.Context, entry FileEntry, vaultIdentity age.Identity, pm *ProgressManager, sem chan struct{}) (io.ReadCloser, error) {
	repo, err := p.GetRepository(ctx)
	if err != nil {
		return nil, err
	}

	headerBytes, err := base64.StdEncoding.DecodeString(entry.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file header: %w", err)
	}

	pr, pw := io.Pipe()

	g, gCtx := errgroup.WithContext(ctx)
	// We do not set limit on chunk errgroup, because we use the global semaphore to limit concurrently active downloads across all files.

	go func() {
		defer pw.Close()

		var mu sync.Mutex
		cond := sync.NewCond(&mu)
		nextOrder := 0
		results := make(map[int]string)

		go func() {
			<-gCtx.Done()
			cond.Broadcast()
		}()

		for i, chunk := range entry.Chunks {
			desc := ocispec.Descriptor{
				MediaType: MediaTypeLayer,
				Digest:    digest.Digest(chunk.Digest),
				Size:      chunk.SizeEncrypted,
			}

			chunkOrder := i
			chunkExpectedDigest := chunk.Digest
			g.Go(func() error {
				sem <- struct{}{}
				defer func() { <-sem }()

				var lastErr error
				maxAttempts := p.Retries + 1
				if maxAttempts < 1 {
					maxAttempts = 1
				}
				for attempt := 0; attempt < maxAttempts; attempt++ {
					if err := gCtx.Err(); err != nil {
						return err
					}

					rc, err := repo.Fetch(gCtx, desc)
					if err != nil {
						lastErr = err
						continue
					}

					label := fmt.Sprintf("%s [%d]", entry.Path, chunkOrder)
					if attempt > 0 {
						label += fmt.Sprintf(" (retry %d)", attempt)
					}
					tr := pm.TrackReader(fmt.Sprintf("%s-%d-%d", entry.Path, chunkOrder, attempt), label, chunk.SizeEncrypted, rc)

					hasher := sha256.New()

					mu.Lock()
					isNext := (chunkOrder == nextOrder)
					mu.Unlock()

					if isNext {
						htr := io.TeeReader(tr, hasher)
						if _, err := io.Copy(pw, htr); err != nil {
							tr.Close()
							rc.Close()
							return err // Direct stream failure cannot be retried at chunk level
						}

						actualDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
						if actualDigest != chunkExpectedDigest {
							tr.Close()
							rc.Close()
							return fmt.Errorf("hash mismatch for chunk %d: expected %s, got %s", chunkOrder, chunkExpectedDigest, actualDigest)
						}

						tr.Close()
						rc.Close()

						mu.Lock()
						nextOrder++
						cond.Broadcast()
						mu.Unlock()
						return nil
					}

					tempFile, err := os.CreateTemp("", "ocige-pull-chunk-*")
					if err != nil {
						tr.Close()
						rc.Close()
						lastErr = err
						continue
					}
					tempPath := tempFile.Name()

					htr := io.TeeReader(tr, hasher)
					if _, err := io.Copy(tempFile, htr); err != nil {
						tempFile.Close()
						os.Remove(tempPath)
						tr.Close()
						rc.Close()
						lastErr = err
						continue
					}
					tempFile.Close()
					tr.Close()
					rc.Close()

					actualDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
					if actualDigest != chunkExpectedDigest {
						os.Remove(tempPath)
						lastErr = fmt.Errorf("hash mismatch for chunk %d: expected %s, got %s", chunkOrder, chunkExpectedDigest, actualDigest)
						continue
					}

					mu.Lock()
					results[chunkOrder] = tempPath
					cond.Broadcast()
					mu.Unlock()
					return nil
				}
				return fmt.Errorf("failed to fetch chunk %d after %d retries: %w", chunkOrder, p.Retries, lastErr)
			})
		}

		// Background collector for buffered chunks
		g.Go(func() error {
			for i := 0; i < len(entry.Chunks); i++ {
				mu.Lock()
				for nextOrder < i || (results[i] == "" && nextOrder == i) {
					if err := gCtx.Err(); err != nil {
						mu.Unlock()
						return err
					}
					if nextOrder > i {
						break // Already processed
					}
					cond.Wait()
				}

				tempPath := results[i]
				mu.Unlock()

				if tempPath != "" {
					// Was buffered to disk, now feed into pipe
					f, err := os.Open(tempPath)
					if err != nil {
						return err
					}
					_, err = io.Copy(pw, f)
					f.Close()
					os.Remove(tempPath)
					if err != nil {
						return err
					}

					mu.Lock()
					nextOrder++
					cond.Broadcast()
					mu.Unlock()
				}
			}
			return nil
		})

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
