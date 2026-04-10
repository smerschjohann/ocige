package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"ocige/pkg/fusefs"
	"ocige/pkg/ociregistry"

	"filippo.io/age"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/urfave/cli/v3"
)

func handlePush(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) < 1 {
		return fmt.Errorf("target is required")
	}
	if len(args) < 2 {
		return fmt.Errorf("at least one file or '-' is required")
	}
	target := args[0]
	files := args[1:]
	recipientsFile := cmd.String("recipients")
	chunkSizeMB := cmd.Int("chunk-size")
	name := cmd.String("name")
	insecure := cmd.Bool("insecure")
	dockerConfig := cmd.String("docker-config")
	concurrency := int(cmd.Int("concurrency"))
	silent := cmd.Bool("silent")
	retries := int(cmd.Int("retries"))

	if recipientsFile == "" {
		return fmt.Errorf("recipients file is required (use -R or OCIGE_RECIPIENTS)")
	}

	recipients, err := parseRecipients(recipientsFile)
	if err != nil {
		return fmt.Errorf("error parsing recipients: %w", err)
	}

	pusher := ociregistry.NewPusher(target, int64(chunkSizeMB)*1024*1024)
	pusher.PlainHTTP = insecure
	pusher.DockerConfigPath = dockerConfig
	pusher.Concurrency = concurrency
	pusher.Silent = silent
	pusher.Retries = retries

	hasStdin := false
	for _, f := range files {
		if f == "-" {
			hasStdin = true
			break
		}
	}
	if hasStdin && name == "" {
		return fmt.Errorf("--name is required when pushing from stdin (-)")
	}

	fmt.Printf("Pushing to %s...\n", target)
	err = pusher.PushMultipleWithStdin(ctx, files, name, recipients)
	if err != nil {
		return fmt.Errorf("push failed: %w", err)
	}

	fmt.Println("Push successful!")
	return nil
}

func handleCat(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) < 2 {
		return fmt.Errorf("usage: ocige cat <target> <file>")
	}
	target := args[0]
	filePath := args[1]
	identityFile := cmd.String("identity")
	force := cmd.Bool("force")

	if identityFile == "" {
		return fmt.Errorf("identity file is required (use -i or OCIGE_IDENTITY)")
	}

	identities, err := parseIdentities(identityFile)
	if err != nil {
		return fmt.Errorf("error parsing identity: %w", err)
	}

	puller := ociregistry.NewPuller(target)
	puller.PlainHTTP = cmd.Bool("insecure")
	puller.DockerConfigPath = cmd.String("docker-config")
	puller.Concurrency = 1
	puller.Silent = true // We want clean output

	index, vaultIdentity, err := puller.FetchIndex(ctx, identities)
	if err != nil {
		return err
	}

	var entry *ociregistry.FileEntry
	for _, f := range index.Files {
		if f.Path == filePath {
			entry = &f
			break
		}
	}

	if entry == nil {
		return fmt.Errorf("file %s not found in artifact", filePath)
	}

	sem := make(chan struct{}, 1)
	fileReader, err := puller.PullFileInternal(ctx, *entry, vaultIdentity, ociregistry.NewProgressManager(true), sem)
	if err != nil {
		return err
	}
	defer fileReader.Close()

	output := os.Stdout
	if IsTerminal(output) && !force {
		// Sniff content
		buf := make([]byte, 512)
		n, err := fileReader.Read(buf)
		if err != nil && err != os.ErrClosed && err.Error() != "EOF" {
			return fmt.Errorf("failed to read for content sniffing: %w", err)
		}

		if n > 0 && IsBinary(buf[:n]) {
			fmt.Fprintf(os.Stderr, "Warning: file '%s' appears to be binary. Use --force to output to terminal anyway.\n", filePath)
			return nil
		}

		// Write what we already read
		if _, err := output.Write(buf[:n]); err != nil {
			return err
		}
	}

	_, err = io.Copy(output, fileReader)
	return err
}

func handlePull(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) < 1 {
		return fmt.Errorf("target is required")
	}
	target := args[0]
	filterFiles := args[1:]
	identityFile := cmd.String("identity")
	destDir := cmd.String("output")
	insecure := cmd.Bool("insecure")
	dockerConfig := cmd.String("docker-config")
	concurrency := int(cmd.Int("concurrency"))
	silent := cmd.Bool("silent")
	retries := int(cmd.Int("retries"))

	if identityFile == "" {
		return fmt.Errorf("identity file is required (use -i or OCIGE_IDENTITY)")
	}

	identities, err := parseIdentities(identityFile)
	if err != nil {
		return fmt.Errorf("error parsing identity: %w", err)
	}

	puller := ociregistry.NewPuller(target)
	puller.PlainHTTP = insecure
	puller.DockerConfigPath = dockerConfig
	puller.Concurrency = concurrency
	puller.Silent = silent
	puller.Retries = retries

	fmt.Printf("Fetching index and unlocking vault from %s...\n", target)
	index, vaultIdentity, err := puller.FetchIndex(ctx, identities)
	if err != nil {
		return fmt.Errorf("failed to unlock vault or fetch index: %w", err)
	}

	fmt.Printf("Vault unlocked. Found %d files.\n", len(index.Files))

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	var filesToPull []ociregistry.FileEntry
	for _, entry := range index.Files {
		// If specific files were requested, only pull those
		if len(filterFiles) > 0 {
			match := false
			for _, f := range filterFiles {
				if entry.Path == f {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		filesToPull = append(filesToPull, entry)
	}

	if len(filesToPull) == 0 {
		fmt.Println("No matching files found.")
		return nil
	}

	if err := puller.PullMultiple(ctx, filesToPull, vaultIdentity, destDir); err != nil {
		return err
	}

	fmt.Println("Pull successful!")
	return nil
}

func handleLs(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) < 1 {
		return fmt.Errorf("target is required")
	}
	target := args[0]
	identityFile := cmd.String("identity")
	insecure := cmd.Bool("insecure")
	dockerConfig := cmd.String("docker-config")
	concurrency := int(cmd.Int("concurrency"))
	silent := cmd.Bool("silent")
	outputFormat := cmd.String("output")

	if identityFile == "" {
		return fmt.Errorf("identity file is required (use -i or OCIGE_IDENTITY)")
	}

	identities, err := parseIdentities(identityFile)
	if err != nil {
		return fmt.Errorf("error parsing identity: %w", err)
	}

	puller := ociregistry.NewPuller(target)
	puller.PlainHTTP = insecure
	puller.DockerConfigPath = dockerConfig
	puller.Concurrency = concurrency
	puller.Silent = silent

	if outputFormat != "json" {
		fmt.Printf("Unlocking vault and fetching index from %s...\n", target)
	}
	index, _, err := puller.FetchIndex(ctx, identities)
	if err != nil {
		return fmt.Errorf("failed to unlock vault or fetch index: %w", err)
	}

	if outputFormat == "json" {
		out, err := json.MarshalIndent(index.Files, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(out))
		return nil
	}

	fmt.Printf("\n%-40s %-10s %s\n", "PATH", "SIZE", "SHA256")
	fmt.Println(strings.Repeat("-", 80))
	for _, f := range index.Files {
		sizeStr := formatSize(f.Size)
		displayHash := strings.TrimPrefix(f.SHA256, "sha256:")
		if outputFormat != "long" && len(displayHash) > 12 {
			displayHash = displayHash[:12]
		}
		fmt.Printf("%-40s %-10s %s\n", f.Path, sizeStr, displayHash)
	}
	return nil
}

func handleAppend(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) < 1 {
		return fmt.Errorf("target is required")
	}
	if len(args) < 2 {
		return fmt.Errorf("at least one file or '-' is required")
	}
	target := args[0]
	files := args[1:]
	identityFile := cmd.String("identity")
	name := cmd.String("name")
	force := cmd.Bool("force")
	insecure := cmd.Bool("insecure")
	dockerConfig := cmd.String("docker-config")
	concurrency := int(cmd.Int("concurrency"))
	silent := cmd.Bool("silent")
	retries := int(cmd.Int("retries"))

	if identityFile == "" {
		return fmt.Errorf("identity file is required (use -i or OCIGE_IDENTITY)")
	}

	identities, err := parseIdentities(identityFile)
	if err != nil {
		return fmt.Errorf("error parsing identity: %w", err)
	}

	pusher := ociregistry.NewPusher(target, 100*1024*1024)
	pusher.PlainHTTP = insecure
	pusher.DockerConfigPath = dockerConfig
	pusher.Concurrency = concurrency
	pusher.Silent = silent
	pusher.Retries = retries

	hasStdin := false
	for _, f := range files {
		if f == "-" {
			hasStdin = true
			break
		}
	}
	if hasStdin && name == "" {
		return fmt.Errorf("--name is required when appending from stdin (-)")
	}

	fmt.Printf("Appending to %s...\n", target)
	err = pusher.AppendWithStdin(ctx, files, name, identities, force)
	if err != nil {
		return fmt.Errorf("append failed: %w", err)
	}
	fmt.Println("Append successful!")
	return nil
}

func handleRekey(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) < 1 {
		return fmt.Errorf("target is required")
	}
	if len(args) < 2 {
		return fmt.Errorf("new recipients file is required")
	}
	target := args[0]
	newRecipientsFile := args[1]
	identityFile := cmd.String("identity")
	insecure := cmd.Bool("insecure")
	dockerConfig := cmd.String("docker-config")
	retries := int(cmd.Int("retries"))

	if identityFile == "" {
		return fmt.Errorf("identity file is required (use -i or OCIGE_IDENTITY)")
	}

	identities, err := parseIdentities(identityFile)
	if err != nil {
		return fmt.Errorf("error parsing identity: %w", err)
	}

	newRecipients, err := parseRecipients(newRecipientsFile)
	if err != nil {
		return fmt.Errorf("error parsing new recipients: %w", err)
	}

	pusher := ociregistry.NewPusher(target, 0)
	pusher.PlainHTTP = insecure
	pusher.DockerConfigPath = dockerConfig
	pusher.Retries = retries

	fmt.Printf("Rekeying artifact at %s...\n", target)
	err = pusher.Rekey(ctx, identities, newRecipients)
	if err != nil {
		return fmt.Errorf("rekey failed: %w", err)
	}
	fmt.Println("Rekey successful!")
	return nil
}

func handleRemove(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) < 1 {
		return fmt.Errorf("target is required")
	}
	if len(args) < 2 {
		return fmt.Errorf("at least one file is required")
	}
	target := args[0]
	files := args[1:]
	identityFile := cmd.String("identity")
	insecure := cmd.Bool("insecure")
	dockerConfig := cmd.String("docker-config")
	retries := int(cmd.Int("retries"))

	if identityFile == "" {
		return fmt.Errorf("identity file is required (use -i or OCIGE_IDENTITY)")
	}

	identities, err := parseIdentities(identityFile)
	if err != nil {
		return fmt.Errorf("error parsing identity: %w", err)
	}

	pusher := ociregistry.NewPusher(target, 0)
	pusher.PlainHTTP = insecure
	pusher.DockerConfigPath = dockerConfig
	pusher.Retries = retries

	fmt.Printf("Removing %v from %s...\n", files, target)
	err = pusher.Remove(ctx, identities, files)
	if err != nil {
		return fmt.Errorf("remove failed: %w", err)
	}
	fmt.Println("Remove successful!")
	return nil
}

func handleKeygen(ctx context.Context, cmd *cli.Command) error {
	outFile := cmd.String("output")

	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	out := os.Stdout
	if outFile != "" {
		f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	fmt.Fprintf(out, "# Public key: %s\n", id.Recipient().String())
	fmt.Fprintf(out, "%s\n", id.String())
	return nil
}

func handleMount(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) < 2 {
		return fmt.Errorf("usage: ocige mount <target> <mountpoint>")
	}
	target := args[0]
	mountpoint := args[1]

	identityFile := cmd.String("identity")
	if identityFile == "" {
		return fmt.Errorf("identity file is required (use -i or OCIGE_IDENTITY)")
	}

	identities, err := parseIdentities(identityFile)
	if err != nil {
		return fmt.Errorf("error parsing identity: %w", err)
	}

	// Create mountpoint if it doesn't exist
	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		return fmt.Errorf("failed to create mountpoint: %w", err)
	}

	return fusefs.Mount(ctx, fusefs.MountOptions{
		Target:     target,
		Mountpoint: mountpoint,
		Identities: identities,
		BaseClient: &ociregistry.BaseClient{
			RepoTarget:       target,
			PlainHTTP:        cmd.Bool("insecure"),
			DockerConfigPath: cmd.String("docker-config"),
		},
		CacheDir:     cmd.String("cache-dir"),
		CacheMaxSize: int64(cmd.Int("cache-size")) * 1024 * 1024,
		Concurrency:  int(cmd.Int("concurrency")),
		AllowOther:   cmd.Bool("allow-other"),
		Debug:        cmd.Bool("debug"),
	})
}

func handleCacheCleanup(ctx context.Context, cmd *cli.Command) error {
	cacheDir := cmd.String("cache-dir")
	chunksDir := filepath.Join(cacheDir, "chunks")
	// Use 0 as maxSize as we are only using it for deletion/scoping, not putting.
	cache, err := fusefs.NewDiskCache(chunksDir, 0)
	if err != nil {
		return fmt.Errorf("failed to initialize cache for cleanup: %w", err)
	}

	args := cmd.Args().Slice()
	if len(args) == 0 {
		fmt.Printf("Clearing global cache at %s...\n", chunksDir)
		return cache.Clear()
	}

	target := args[0]
	fmt.Printf("Clearing cache for target %s...\n", target)

	client := &ociregistry.BaseClient{
		RepoTarget:       target,
		PlainHTTP:        cmd.Bool("insecure"),
		DockerConfigPath: cmd.String("docker-config"),
	}

	repo, err := client.GetRepository(ctx)
	if err != nil {
		return err
	}

	desc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return fmt.Errorf("failed to resolve manifest: %w", err)
	}

	rc, err := repo.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer rc.Close()

	var manifest ocispec.Manifest
	if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
		return fmt.Errorf("failed to decode manifest: %w", err)
	}

	// Delete layers
	for _, layer := range manifest.Layers {
		if err := cache.Delete(string(layer.Digest)); err != nil {
			fmt.Printf("Warning: failed to delete chunk %s: %v\n", layer.Digest, err)
		}
	}

	// Delete config
	if err := cache.Delete(string(manifest.Config.Digest)); err != nil {
		fmt.Printf("Warning: failed to delete config %s: %v\n", manifest.Config.Digest, err)
	}

	fmt.Println("Cache cleanup complete.")
	return nil
}
