package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	case "ls":
		handleLs(os.Args[2:])
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
	fmt.Println("  ocige pull -r <registry-target> -i <identity-file> [-f <filename>] [-C <out-dir>]")
	fmt.Println("  ocige ls -r <registry-target> -i <identity-file>")
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

	recipients, err := parseRecipients(*recipientsFile)
	if err != nil {
		fmt.Printf("Error parsing recipients: %v\n", err)
		os.Exit(1)
	}

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

	recipients, err := age.ParseRecipients(f)
	if err != nil {
		return nil, err
	}

	for _, r := range recipients {
		if _, ok := r.(*age.HybridRecipient); !ok {
			return nil, fmt.Errorf("non-PQ recipient found: only Hybrid (PQ-safe) recipients are allowed")
		}
	}

	return recipients, nil
}

func handlePull(args []string) {
	pullCmd := flag.NewFlagSet("pull", flag.ExitOnError)
	target := pullCmd.String("r", "", "OCI registry target (e.g. ghcr.io/user/file:tag)")
	identityFile := pullCmd.String("i", "", "Path to age identity file")
	filterFile := pullCmd.String("f", "", "Selective pull: only extract this file")
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

	fmt.Printf("Fetching index and unlocking vault from %s...\n", *target)
	index, vaultIdentity, err := puller.FetchIndex(context.Background(), identities)
	if err != nil {
		fmt.Printf("Failed to unlock vault or fetch index: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Vault unlocked. Found %d files.\n", len(index.Files))
	
	if err := os.MkdirAll(*destDir, 0755); err != nil {
		fmt.Printf("Failed to create destination directory: %v\n", err)
		os.Exit(1)
	}

	found := false
	for _, entry := range index.Files {
		if *filterFile != "" && entry.Path != *filterFile {
			continue
		}
		found = true
		fmt.Printf("  -> Pulling %s...\n", entry.Path)
		fileReader, err := puller.PullFile(context.Background(), entry, vaultIdentity)
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

	if *filterFile != "" && !found {
		fmt.Printf("Error: file '%s' not found in artifact\n", *filterFile)
		os.Exit(1)
	}

	fmt.Println("Pull successful!")
}

func handleLs(args []string) {
	lsCmd := flag.NewFlagSet("ls", flag.ExitOnError)
	target := lsCmd.String("r", "", "OCI registry target (e.g. ghcr.io/user/file:tag)")
	identityFile := lsCmd.String("i", "", "Path to age identity file")
	insecure := lsCmd.Bool("insecure", false, "Use plain HTTP for registry")

	lsCmd.Parse(args)

	if *target == "" || *identityFile == "" {
		fmt.Println("Missing required arguments for ls")
		lsCmd.Usage()
		os.Exit(1)
	}

	identities, err := parseIdentities(*identityFile)
	if err != nil {
		fmt.Printf("Error parsing identity: %v\n", err)
		os.Exit(1)
	}

	puller := ociregistry.NewPuller(*target)
	puller.PlainHTTP = *insecure

	fmt.Printf("Unlocking vault and fetching index from %s...\n", *target)
	index, _, err := puller.FetchIndex(context.Background(), identities)
	if err != nil {
		fmt.Printf("Failed to unlock vault or fetch index: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n%-40s %-10s %s\n", "PATH", "SIZE", "SHA256 (Original)")
	fmt.Println(strings.Repeat("-", 80))
	for _, f := range index.Files {
		sizeStr := formatSize(f.Size)
		fmt.Printf("%-40s %-10s %s\n", f.Path, sizeStr, f.SHA256[:12])
	}
}

func formatSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func parseIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, err
	}

	for _, i := range identities {
		if _, ok := i.(*age.HybridIdentity); !ok {
			return nil, fmt.Errorf("non-PQ identity found: only Hybrid (PQ-safe) identities are allowed")
		}
	}

	return identities, nil
}
