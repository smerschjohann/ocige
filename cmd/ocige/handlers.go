package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"ocige/pkg/ociregistry"

	"filippo.io/age"
	"github.com/urfave/cli/v3"
)

func handlePush(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) < 1 {
		return fmt.Errorf("target is required")
	}
	if len(args) < 2 {
		return fmt.Errorf("at least one file is required")
	}
	target := args[0]
	files := args[1:]
	recipientsFile := cmd.String("recipients")
	chunkSizeMB := cmd.Int("chunk-size")
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

	fmt.Printf("Pushing %v to %s...\n", files, target)
	err = pusher.PushMultiple(ctx, files, recipients)
	if err != nil {
		return fmt.Errorf("push failed: %w", err)
	}

	fmt.Println("Push successful!")
	return nil
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
		return fmt.Errorf("at least one file is required")
	}
	target := args[0]
	files := args[1:]
	identityFile := cmd.String("identity")
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

	fmt.Printf("Appending %v to %s...\n", files, target)
	err = pusher.Append(ctx, files, identities, force)
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
