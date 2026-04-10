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
	"golang.org/x/sync/errgroup"
	"sync"
)

type Pusher struct {
	BaseClient
	ChunkSize   int64
	Concurrency int
	Silent      bool
}

func NewPusher(target string, chunkSize int64) *Pusher {
	return &Pusher{
		BaseClient: BaseClient{
			RepoTarget: target,
		},
		ChunkSize:   chunkSize,
		Concurrency: 5,
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
	var mu sync.Mutex

	pm := NewProgressManager(p.Silent)
	defer pm.Wait()

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(p.Concurrency)
	sem := make(chan struct{}, p.Concurrency)

	// 3. Collect and Push each file
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
			
			g.Go(func() error {
				pm.Message(fmt.Sprintf("Processing %s...", relPath))
				
				fileEntry, layers, err := p.pushSingleFile(gCtx, repo, fpath, relPath, []age.Recipient{vaultRecipient}, pm, sem)
				if err != nil {
					return fmt.Errorf("failed to push %s: %w", relPath, err)
				}

				mu.Lock()
				index.Files = append(index.Files, *fileEntry)
				allLayers = append(allLayers, layers...)
				mu.Unlock()
				return nil
			})
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed walking %s: %w", inputPath, err)
		}
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// 4. Push Index
	pm.Message("Finalizing Index...")
	indexDesc, err := p.pushIndex(ctx, repo, &index, vaultRecipient)
	if err != nil {
		return err
	}
	allLayers = append([]ocispec.Descriptor{indexDesc}, allLayers...)

	// 5. Push Config
	pm.Message("Pushing Config...")
	config := Config{
		Version: "1.0",
		Vault: VaultMeta{
			VaultKeySheaf:  base64.StdEncoding.EncodeToString(vaultKeySheafBuf.Bytes()),
			VaultPublicKey: vaultRecipient.String(),
		},
		Index: IndexMeta{
			Digest: string(indexDesc.Digest),
		},
	}
	configDesc, err := p.pushConfig(ctx, repo, &config)
	if err != nil {
		return err
	}

	// 6. Push Manifest
	return p.pushManifest(ctx, repo, configDesc, allLayers)
}

// Append adds files to an existing artifact.
func (p *Pusher) Append(ctx context.Context, paths []string, identities []age.Identity, force bool) error {
	pm := NewProgressManager(p.Silent)
	defer pm.Wait()

	index, vaultIdentity, config, manifest, err := p.FetchIndex(ctx, identities)
	if err != nil {
		return fmt.Errorf("failed to fetch existing index: %w", err)
	}
	vaultRecipient := vaultIdentity.(*age.HybridIdentity).Recipient()

	repo, err := p.GetRepository(ctx)
	if err != nil {
		return err
	}

	existingFiles := make(map[string]bool)
	for _, f := range index.Files {
		existingFiles[f.Path] = true
	}

	var newLayers []ocispec.Descriptor
	sem := make(chan struct{}, p.Concurrency)
	
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
			if existingFiles[relPath] && !force {
				return fmt.Errorf("file %s already exists in artifact (use force to overwrite)", relPath)
			}

			pm.Message(fmt.Sprintf("Processing %s...", relPath))
			
			fileEntry, layers, err := p.pushSingleFile(ctx, repo, fpath, relPath, []age.Recipient{vaultRecipient}, pm, sem)
			if err != nil {
				return err
			}

			// Overwrite existing entry if it exists
			found := false
			for i, f := range index.Files {
				if f.Path == relPath {
					index.Files[i] = *fileEntry
					found = true
					break
				}
			}
			if !found {
				index.Files = append(index.Files, *fileEntry)
			}
			newLayers = append(newLayers, layers...)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Re-collect all referenced layers from index (to avoid keeping old layers of overwritten files in manifest)
	referencedLayers := make(map[string]bool)
	for _, f := range index.Files {
		for _, c := range f.Chunks {
			referencedLayers[c.Digest] = true
		}
	}

	allLayers := []ocispec.Descriptor{}
	// First, keep existing layers that are still referenced (and aren't the index/config)
	for _, l := range manifest.Layers {
		if l.MediaType == MediaTypeLayer && referencedLayers[string(l.Digest)] {
			allLayers = append(allLayers, l)
		}
	}
	// Add new layers
	allLayers = append(allLayers, newLayers...)

	// Push new Index
	indexDesc, err := p.pushIndex(ctx, repo, index, vaultRecipient)
	if err != nil {
		return err
	}
	allLayers = append([]ocispec.Descriptor{indexDesc}, allLayers...)

	// Push updated Config (points to new index)
	config.Index.Digest = string(indexDesc.Digest)
	configDesc, err := p.pushConfig(ctx, repo, config)
	if err != nil {
		return err
	}

	return p.pushManifest(ctx, repo, configDesc, allLayers)
}

// Rekey changes recipients by re-encrypting the Vault Secret Key.
func (p *Pusher) Rekey(ctx context.Context, identities []age.Identity, newRecipients []age.Recipient) error {
	repo, err := p.GetRepository(ctx)
	if err != nil {
		return err
	}
	vaultIdentity, config, manifest, err := p.UnlockVault(ctx, repo, identities)
	if err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	// Re-encrypt Vault Secret Key
	vaultKeySheafBuf := &bytes.Buffer{}
	w, err := age.Encrypt(vaultKeySheafBuf, newRecipients...)
	if err != nil {
		return fmt.Errorf("failed to setup vault key encryption: %w", err)
	}
	
	vaultString := ""
	if hi, ok := vaultIdentity.(*age.HybridIdentity); ok {
		vaultString = hi.String()
	} else {
		return fmt.Errorf("vault identity is not a HybridIdentity")
	}

	if _, err := io.WriteString(w, vaultString); err != nil {
		return fmt.Errorf("failed to encrypt vault key: %w", err)
	}
	w.Close()

	config.Vault.VaultKeySheaf = base64.StdEncoding.EncodeToString(vaultKeySheafBuf.Bytes())
	
	configDesc, err := p.pushConfig(ctx, repo, config)
	if err != nil {
		return err
	}

	return p.pushManifest(ctx, repo, configDesc, manifest.Layers)
}

// Remove deletes files from the index and manifest.
func (p *Pusher) Remove(ctx context.Context, identities []age.Identity, paths []string) error {
	index, vaultIdentity, config, manifest, err := p.FetchIndex(ctx, identities)
	if err != nil {
		return fmt.Errorf("failed to fetch index: %w", err)
	}
	vaultRecipient := vaultIdentity.(*age.HybridIdentity).Recipient()

	repo, err := p.GetRepository(ctx)
	if err != nil {
		return err
	}

	toRemove := make(map[string]bool)
	for _, p := range paths {
		toRemove[p] = true
	}

	newFiles := []FileEntry{}
	for _, f := range index.Files {
		if !toRemove[f.Path] {
			newFiles = append(newFiles, f)
		}
	}
	index.Files = newFiles

	// Re-collect referenced layers
	referencedLayers := make(map[string]bool)
	for _, f := range index.Files {
		for _, c := range f.Chunks {
			referencedLayers[c.Digest] = true
		}
	}

	allLayers := []ocispec.Descriptor{}
	for _, l := range manifest.Layers {
		if l.MediaType == MediaTypeLayer && referencedLayers[string(l.Digest)] {
			allLayers = append(allLayers, l)
		}
	}

	// Push new Index
	indexDesc, err := p.pushIndex(ctx, repo, index, vaultRecipient)
	if err != nil {
		return err
	}
	allLayers = append([]ocispec.Descriptor{indexDesc}, allLayers...)

	config.Index.Digest = string(indexDesc.Digest)
	configDesc, err := p.pushConfig(ctx, repo, config)
	if err != nil {
		return err
	}

	return p.pushManifest(ctx, repo, configDesc, allLayers)
}

func (p *Pusher) pushIndex(ctx context.Context, repo *remote.Repository, index *Index, recipient age.Recipient) (ocispec.Descriptor, error) {
	indexBytes, _ := index.Marshal()
	indexEncBuf := &bytes.Buffer{}
	indexWriter, err := age.Encrypt(indexEncBuf, recipient)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to encrypt index: %w", err)
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
		return ocispec.Descriptor{}, fmt.Errorf("failed to push index: %w", err)
	}
	return indexDesc, nil
}

func (p *Pusher) pushConfig(ctx context.Context, repo *remote.Repository, config *Config) (ocispec.Descriptor, error) {
	configBytes, _ := config.Marshal()
	configDigest := digest.FromBytes(configBytes)
	configDesc := ocispec.Descriptor{
		MediaType: MediaTypeConfig,
		Digest:    configDigest,
		Size:      int64(len(configBytes)),
	}

	err := repo.Push(ctx, configDesc, bytes.NewReader(configBytes))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to push config: %w", err)
	}
	return configDesc, nil
}

func (p *Pusher) pushManifest(ctx context.Context, repo *remote.Repository, configDesc ocispec.Descriptor, layers []ocispec.Descriptor) error {
	manifest := map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     ocispec.MediaTypeImageManifest,
		"artifactType":  ArtifactType,
		"config":        configDesc,
		"layers":        layers,
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

func (p *Pusher) pushSingleFile(ctx context.Context, repo *remote.Repository, absPath string, relPath string, recipients []age.Recipient, pm *ProgressManager, sem chan struct{}) (*FileEntry, []ocispec.Descriptor, error) {
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
	var mu sync.Mutex
	order := 0

	g, gCtx := errgroup.WithContext(ctx)

	for {
		tempFile, err := os.CreateTemp("", "ocige-chunk-*")
		if err != nil {
			return nil, nil, err
		}
		// We don't defer os.Remove here because we want to remove it after upload in the goroutine
		
		n, err := io.CopyN(tempFile, encReader, p.ChunkSize)
		if n == 0 {
			tempFile.Close()
			os.Remove(tempFile.Name())
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
			tempFile.Close()
			return nil, nil, err
		}
		chunkDigest := digest.NewDigest("sha256", hasher)
		chunkSize := n

		desc := ocispec.Descriptor{
			MediaType: MediaTypeLayer,
			Digest:    chunkDigest,
			Size:      chunkSize,
			Annotations: map[string]string{
				"org.opencontainers.image.title": fmt.Sprintf("ocige.chunk.%d", order),
			},
		}

		currentOrder := order
		tempPath := tempFile.Name()
		tempFile.Close() // Close it before uploading (repo.Push will open it or take it as reader)

		g.Go(func() error {
			sem <- struct{}{}
			defer func() { <-sem }()

			f, err := os.Open(tempPath)
			if err != nil {
				return err
			}
			defer f.Close()
			defer os.Remove(tempPath)

			label := fmt.Sprintf("%s [%d]", relPath, currentOrder)
			tr := pm.TrackReader(fmt.Sprintf("%s-%d", relPath, currentOrder), label, chunkSize, f)
			defer tr.Close()

			err = repo.Push(gCtx, desc, tr)
			if err != nil {
				return fmt.Errorf("failed to push chunk %d: %w", currentOrder, err)
			}
			return nil
		})

		mu.Lock()
		layers = append(layers, desc)
		chunks = append(chunks, BlobChunk{
			Digest:         string(chunkDigest),
			Order:          currentOrder,
			SizeEncrypted:  chunkSize,
			IntegritySHA256: hex.EncodeToString(hasher.Sum(nil)),
		})
		mu.Unlock()

		order++
		if err == io.EOF {
			break
		}
	}

	if err := g.Wait(); err != nil {
		return nil, nil, err
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
