package ociregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"ocige/pkg/ageutils"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
	"filippo.io/age"
)

type Pusher struct {
	RepoTarget string
	ChunkSize  int64
	PlainHTTP  bool
}

func NewPusher(target string, chunkSize int64) *Pusher {
	return &Pusher{
		RepoTarget: target,
		ChunkSize:  chunkSize,
		PlainHTTP:  false,
	}
}

// PushMultiple uploads multiple paths (files or directories) as an encrypted OCI artifact.
func (p *Pusher) PushMultiple(ctx context.Context, paths []string, recipients []age.Recipient) error {
	repo, err := remote.NewRepository(p.RepoTarget)
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}
	repo.PlainHTTP = p.PlainHTTP

	var allLayers []ocispec.Descriptor
	index := Index{Files: []FileEntry{}}

	// 1. Encrypt and Push each file
	for _, inputPath := range paths {
		// Ensure we have a clean path
		inputPath = filepath.Clean(inputPath)
		baseDir := filepath.Dir(inputPath)

		err := filepath.WalkDir(inputPath, func(fpath string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}

			// Calculate relative path for storage in index
			relPath, err := filepath.Rel(baseDir, fpath)
			if err != nil {
				return fmt.Errorf("failed to calculate rel path for %s: %w", fpath, err)
			}

			fmt.Printf("Processing %s (as %s)...\n", fpath, relPath)
			fileEntry, layers, err := p.pushSingleFile(ctx, repo, fpath, relPath, recipients)
			if err != nil {
				return err
			}

			index.Files = append(index.Files, *fileEntry)
			allLayers = append(allLayers, layers...)
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed walking %s: %w", inputPath, err)
		}
	}

	// 2. Prepare, Encrypt and Push Index
	indexBytes, err := index.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	indexEncReader, indexHeaderExt := p.encryptStream(bytes.NewReader(indexBytes), recipients)
	
	// Upload index blob as a single layer
	indexBlobBytes, err := io.ReadAll(indexEncReader)
	if err != nil {
		return fmt.Errorf("failed to encrypt index: %w", err)
	}
	
	indexDigest := digest.FromBytes(indexBlobBytes)
	indexDesc := ocispec.Descriptor{
		MediaType: MediaTypeIndex,
		Digest:    indexDigest,
		Size:      int64(len(indexBlobBytes)),
		Annotations: map[string]string{
			"org.opencontainers.image.title": "ocige.index",
		},
	}

	err = repo.Push(ctx, indexDesc, bytes.NewReader(indexBlobBytes))
	if err != nil {
		return fmt.Errorf("failed to push index: %w", err)
	}
	allLayers = append([]ocispec.Descriptor{indexDesc}, allLayers...)

	// 3. Push OCI Config
	config := Config{
		Version: "1.0",
		Index: IndexMeta{
			KeySheaf: base64.StdEncoding.EncodeToString(indexHeaderExt.Header),
			Digest:   string(indexDigest),
		},
	}

	configBytes, err := config.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configDigest := digest.FromBytes(configBytes)
	configDesc := ocispec.Descriptor{
		MediaType: MediaTypeConfig,
		Digest:    configDigest,
		Size:      int64(len(configBytes)),
	}

	err = repo.Push(ctx, configDesc, bytes.NewReader(configBytes))
	if err != nil {
		return fmt.Errorf("failed to push config: %w", err)
	}

	// 4. Create and Push Manifest
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     ocispec.MediaTypeImageManifest,
		"artifactType":  ArtifactType,
		"config":        configDesc,
		"layers":        allLayers,
		"annotations": map[string]string{
			"org.opencontainers.image.title": "ocige.artifact",
		},
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}
	
	manifestDigest := digest.FromBytes(manifestBytes)
	manifestDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    manifestDigest,
		Size:      int64(len(manifestBytes)),
	}

	targetTag := repo.Reference.Reference
	if targetTag == "" {
		targetTag = "latest"
	}

	err = repo.Push(ctx, manifestDesc, bytes.NewReader(manifestBytes))
	if err != nil {
		return fmt.Errorf("failed to push manifest: %w", err)
	}

	err = repo.Tag(ctx, manifestDesc, targetTag)
	if err != nil {
		return fmt.Errorf("failed to tag manifest: %w", err)
	}

	return nil
}

func (p *Pusher) pushSingleFile(ctx context.Context, repo *remote.Repository, absPath string, relPath string, recipients []age.Recipient) (*FileEntry, []ocispec.Descriptor, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	fileHash, fileSize, err := HashFile(absPath)
	if err != nil {
		return nil, nil, err
	}

	encReader, headerExt := p.encryptStream(f, recipients)

	var layers []ocispec.Descriptor
	var chunks []BlobChunk
	order := 0

	for {
		tempFile, err := os.CreateTemp("", "ocige-chunk-*")
		if err != nil {
			return nil, nil, err
		}
		defer os.Remove(tempFile.Name())

		n, err := io.CopyN(tempFile, encReader, p.ChunkSize)
		if n == 0 {
			tempFile.Close()
			if err == io.EOF {
				break
			}
			return nil, nil, err
		}

		if _, err := tempFile.Seek(0, 0); err != nil {
			return nil, nil, err
		}
		
		hasher := sha256.New()
		if _, err := io.Copy(hasher, tempFile); err != nil {
			return nil, nil, err
		}
		chunkDigest := digest.NewDigest("sha256", hasher)
		chunkSize := n

		if _, err := tempFile.Seek(0, 0); err != nil {
			return nil, nil, err
		}
		
		desc := ocispec.Descriptor{
			MediaType: MediaTypeLayer,
			Digest:    chunkDigest,
			Size:      chunkSize,
			Annotations: map[string]string{
				"org.opencontainers.image.title": fmt.Sprintf("ocige.chunk.%d", order),
			},
		}

		err = repo.Push(ctx, desc, tempFile)
		if err != nil {
			tempFile.Close()
			return nil, nil, err
		}
		tempFile.Close()

		layers = append(layers, desc)
		chunks = append(chunks, BlobChunk{
			Digest:         string(chunkDigest),
			Order:          order,
			SizeEncrypted:  chunkSize,
			IntegritySHA256: hex.EncodeToString(hasher.Sum(nil)),
		})

		order++
		if err == io.EOF {
			break
		}
	}

	entry := &FileEntry{
		Path:   relPath,
		Header: base64.StdEncoding.EncodeToString(headerExt.Header),
		Chunks: chunks,
		Size:   fileSize,
		SHA256: fileHash,
	}

	return entry, layers, nil
}

func (p *Pusher) encryptStream(r io.Reader, recipients []age.Recipient) (io.Reader, *ageutils.HeaderExtractor) {
	pr, pw := io.Pipe()
	headerExt := ageutils.NewHeaderExtractor(pw)

	go func() {
		defer pw.Close()
		ageWriter, err := age.Encrypt(headerExt, recipients...)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(ageWriter, r); err != nil {
			ageWriter.Close()
			pw.CloseWithError(err)
			return
		}
		ageWriter.Close()
	}()

	return pr, headerExt
}
