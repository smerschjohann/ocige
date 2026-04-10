package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"ocige/pkg/ociregistry"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "push":
		handlePush(os.Args[2:])
	case "pull":
		handlePull(os.Args[2:])
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Ocige - Secure File Sharing over OCI Registries")
	fmt.Println("Usage:")
	fmt.Println("  ocige push -r <registry-target> -R <recipients-file> <path1> [path2...]")
	fmt.Println("  ocige pull -r <registry-target> -i <identity-file> [-C <out-dir>]")
}

func handlePush(args []string) {
	pushCmd := flag.NewFlagSet("push", flag.ExitOnError)
	target := pushCmd.String("r", "", "OCI registry target (e.g. ghcr.io/user/file:tag)")
	recipientsFile := pushCmd.String("R", "", "Path to age recipients file")
	chunkSizeMB := pushCmd.Int64("chunk-size", 100, "Chunk size in MB")
	insecure := pushCmd.Bool("insecure", false, "Use plain HTTP for registry")
	
	pushCmd.Parse(args)

	if *target == "" || pushCmd.NArg() == 0 {
		fmt.Println("Missing required arguments for push")
		pushCmd.Usage()
		os.Exit(1)
	}

	// 1. Validate and Parse Recipients
	recipients, err := parseRecipients(*recipientsFile)
	if err != nil {
		fmt.Printf("Error parsing recipients: %v\n", err)
		os.Exit(1)
	}

	// 2. Setup Pusher
	pusher := ociregistry.NewPusher(*target, (*chunkSizeMB)*1024*1024)
	pusher.PlainHTTP = *insecure

	fmt.Printf("Pushing %v to %s...\n", pushCmd.Args(), *target)
	
	err = pusher.PushMultiple(context.Background(), pushCmd.Args(), recipients)
	if err != nil {
		fmt.Printf("Push failed: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("Push successful!")
}

func parseRecipients(path string) ([]age.Recipient, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return age.ParseRecipients(f)
}

func handlePull(args []string) {
	pullCmd := flag.NewFlagSet("pull", flag.ExitOnError)
	target := pullCmd.String("r", "", "OCI registry target (e.g. ghcr.io/user/file:tag)")
	identityFile := pullCmd.String("i", "", "Path to age identity file")
	destDir := pullCmd.String("C", ".", "Destination directory")
	insecure := pullCmd.Bool("insecure", false, "Use plain HTTP for registry")

	pullCmd.Parse(args)

	if *target == "" {
		fmt.Println("Missing required arguments for pull")
		pullCmd.Usage()
		os.Exit(1)
	}

	identities, err := parseIdentities(*identityFile)
	if err != nil {
		fmt.Printf("Error parsing identity: %v\n", err)
		os.Exit(1)
	}

	puller := ociregistry.NewPuller(*target)
	puller.PlainHTTP = *insecure

	fmt.Printf("Fetching index from %s...\n", *target)
	index, err := puller.FetchIndex(context.Background(), identities)
	if err != nil {
		fmt.Printf("Failed to fetch/decrypt index: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d files. Extracting to %s...\n", len(index.Files), *destDir)
	
	if err := os.MkdirAll(*destDir, 0755); err != nil {
		fmt.Printf("Failed to create destination directory: %v\n", err)
		os.Exit(1)
	}

	for _, entry := range index.Files {
		fmt.Printf("  -> Pulling %s...\n", entry.Path)
		fileReader, err := puller.PullFile(context.Background(), entry, identities)
		if err != nil {
			fmt.Printf("      Failed to decrypt %s: %v\n", entry.Path, err)
			continue
		}
		
		outPath := filepath.Join(*destDir, entry.Path)
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			fmt.Printf("      Failed to create directory for %s: %v\n", entry.Path, err)
			fileReader.Close()
			continue
		}

		out, err := os.Create(outPath)
		if err != nil {
			fmt.Printf("      Failed to create file %s: %v\n", outPath, err)
			fileReader.Close()
			continue
		}

		if _, err := io.Copy(out, fileReader); err != nil {
			fmt.Printf("      Failed to stream %s: %v\n", entry.Path, err)
		}
		out.Close()
		fileReader.Close()
	}

	fmt.Println("Pull successful!")
}

func parseIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return age.ParseIdentities(f)
}
