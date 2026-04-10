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
	BaseClient
	ChunkSize int64
}

func NewPusher(target string, chunkSize int64) *Pusher {
	return &Pusher{
		BaseClient: BaseClient{
			RepoTarget: target,
		},
		ChunkSize: chunkSize,
	}
}

// PushMultiple uploads multiple paths as an encrypted OCI artifact using the Vault Identity.
func (p *Pusher) PushMultiple(ctx context.Context, paths []string, recipients []age.Recipient) error {
	repo, err := p.GetRepository(ctx)
	if err != nil {
		return err
	}

	// 1. Generate PQ-safe Vault Identity
	vaultIdentity, err := age.GenerateHybridIdentity()
	if err != nil {
		return fmt.Errorf("failed to generate vault identity: %w", err)
	}
	vaultRecipient := vaultIdentity.Recipient()

	// 2. Encrypt the Vault Secret Key for the provided recipients
	vaultKeySheafBuf := &bytes.Buffer{}
	w, err := age.Encrypt(vaultKeySheafBuf, recipients...)
	if err != nil {
		return fmt.Errorf("failed to setup vault key encryption: %w", err)
	}
	if _, err := io.WriteString(w, vaultIdentity.String()); err != nil {
		return fmt.Errorf("failed to encrypt vault key: %w", err)
	}
	w.Close()

	var allLayers []ocispec.Descriptor
	index := Index{Files: []FileEntry{}}

	// 3. Encrypt and Push each file for the Vault Recipient
	for _, inputPath := range paths {
		inputPath = filepath.Clean(inputPath)
		baseDir := filepath.Dir(inputPath)

		err := filepath.WalkDir(inputPath, func(fpath string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}

			relPath, _ := filepath.Rel(baseDir, fpath)
			fmt.Printf("Processing %s (as %s)...\n", fpath, relPath)
			
			fileEntry, layers, err := p.pushSingleFile(ctx, repo, fpath, relPath, []age.Recipient{vaultRecipient})
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

	// 4. Prepare and Push Index (WITH header attached for easy fetch)
	indexBytes, _ := index.Marshal()
	indexEncBuf := &bytes.Buffer{}
	indexWriter, err := age.Encrypt(indexEncBuf, vaultRecipient)
	if err != nil {
		return fmt.Errorf("failed to encrypt index: %w", err)
	}
	indexWriter.Write(indexBytes)
	indexWriter.Close()
	
	indexBlobBytes := indexEncBuf.Bytes()
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

	// 5. Push OCI Config
	config := Config{
		Version: "1.0",
		Vault: VaultMeta{
			VaultKeySheaf:  base64.StdEncoding.EncodeToString(vaultKeySheafBuf.Bytes()),
			VaultPublicKey: vaultRecipient.String(),
		},
		Index: IndexMeta{
			Digest: string(indexDigest),
		},
	}

	configBytes, _ := config.Marshal()
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

	// 6. Create and Push Manifest
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

	return &FileEntry{
		Path:   relPath,
		Header: base64.StdEncoding.EncodeToString(headerExt.Header),
		Chunks: chunks,
		Size:   fileSize,
		SHA256: fileHash,
	}, layers, nil
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
