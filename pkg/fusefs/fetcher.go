package fusefs

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"sort"

	"filippo.io/age"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"ocige/pkg/ociregistry"
)

// ChunkFetcher downloads OCI chunks and builds seekable plaintext readers.
type ChunkFetcher struct {
	client        *ociregistry.BaseClient
	vaultIdentity age.Identity
	cache         *DiskCache
	sem           chan struct{} // Concurrency limiter for registry access
	ctx           context.Context // Long-lived context for background fetches
}

func NewChunkFetcher(
	ctx context.Context,
	client *ociregistry.BaseClient,
	vaultIdentity age.Identity,
	cache *DiskCache,
	concurrency int,
) *ChunkFetcher {
	if concurrency <= 0 {
		concurrency = 5
	}
	return &ChunkFetcher{
		ctx:           ctx,
		client:        client,
		vaultIdentity: vaultIdentity,
		cache:         cache,
		sem:           make(chan struct{}, concurrency),
	}
}

// FileReaderAt is a seekable, read-only handle on a decrypted file.
type FileReaderAt struct {
	Plaintext io.ReaderAt
	Size      int64
}

// OpenFile starts parallel fetching of all OCI chunks and returns a FileReaderAt immediately.
func (f *ChunkFetcher) OpenFile(ctx context.Context, entry ociregistry.FileEntry) (*FileReaderAt, error) {
	// Sort chunks by order
	chunks := make([]ociregistry.BlobChunk, len(entry.Chunks))
	copy(chunks, entry.Chunks)
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].Order < chunks[j].Order
	})

	chunkSizes := make([]int64, len(chunks))
	slots := make([]*chunkSlot, len(chunks))
	for i := range chunks {
		chunkSizes[i] = chunks[i].SizeEncrypted
		slots[i] = newChunkSlot()
	}

	// Determine prefetcher
	prefetcher := func(idx int) {
		if idx < 0 || idx >= len(chunks) {
			return
		}
		// Triggering GetOrFetch for the next chunk
		go func() {
			_, _ = f.cache.GetOrFetch(chunks[idx].Digest, func() ([]byte, error) {
				return f.fetchChunkFromRegistry(f.ctx, chunks[idx])
			})
		}()
	}

	// Start picking up chunks in background
	for i, chunk := range chunks {
		i, chunk := i, chunk
		go func() {
			path, err := f.cache.GetOrFetch(chunk.Digest, func() ([]byte, error) {
				f.sem <- struct{}{}
				defer func() { <-f.sem }()
				return f.fetchChunkFromRegistry(f.ctx, chunk)
			})
			slots[i].resolve(path, chunk.SizeEncrypted, err)
		}()
	}

	// Decode header
	header, err := base64.StdEncoding.DecodeString(entry.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode age header: %w", err)
	}

	// Build OCIReaderAtAsync
	ociReader := NewOCIReaderAtAsync(header, slots, chunkSizes, prefetcher)

	// Build DecryptReaderAt
	// Note: DecryptReaderAt will read the header and payload nonce immediately.
	// It might block waiting for the first chunk to be resolved if it's very small.
	plaintext, _, err := age.DecryptReaderAt(ociReader, ociReader.Size(), f.vaultIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to create age DecryptReaderAt: %w", err)
	}

	return &FileReaderAt{
		Plaintext: plaintext,
		Size:      entry.Size,
	}, nil
}

func (f *ChunkFetcher) fetchChunkFromRegistry(ctx context.Context, chunk ociregistry.BlobChunk) ([]byte, error) {
	repo, err := f.client.GetRepository(ctx)
	if err != nil {
		return nil, err
	}

	desc := ocispec.Descriptor{
		MediaType: ociregistry.MediaTypeLayer,
		Digest:    digest.Digest(chunk.Digest),
		Size:      chunk.SizeEncrypted,
	}

	rc, err := repo.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch chunk %s: %w", chunk.Digest, err)
	}
	defer rc.Close()

	return io.ReadAll(rc)
}
