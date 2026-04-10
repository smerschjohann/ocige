package fusefs

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"filippo.io/age"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"ocige/pkg/ociregistry"
)

// MountOptions contains configuration for the FUSE mount.
type MountOptions struct {
	Target       string
	Mountpoint   string
	Identities   []age.Identity
	BaseClient   *ociregistry.BaseClient
	CacheDir     string
	CacheMaxSize int64
	Concurrency  int
	AllowOther   bool
	Debug        bool
}

// Mount performs the full FUSE mount lifecycle.
func Mount(ctx context.Context, opts MountOptions) error {
	// 1. Fetch Index and Vault Key
	fmt.Printf("Unlocking vault at %s...\n", opts.Target)
	index, vaultIdentity, _, _, err := opts.BaseClient.FetchIndex(ctx, opts.Identities)
	if err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}
	fmt.Printf("Vault unlocked. Found %d files.\n", len(index.Files))

	// 2. Initialize Cache
	cachePath := filepath.Join(opts.CacheDir, "chunks")
	cache, err := NewDiskCache(cachePath, opts.CacheMaxSize)
	if err != nil {
		return fmt.Errorf("failed to initialize disk cache at %s: %w", cachePath, err)
	}
	defer cache.Close()

	// 3. Create Fetcher
	fetcher := NewChunkFetcher(ctx, opts.BaseClient, vaultIdentity, cache, opts.Concurrency)

	// 4. Create FUSE Root
	root := &VirtualRoot{
		index:   index,
		fetcher: fetcher,
	}

	// 5. Build Mount Options
	mOpts := &fs.Options{
		MountOptions: fuse.MountOptions{
			AllowOther: opts.AllowOther,
			Name:       "ocige",
			FsName:     fmt.Sprintf("ocige(%s)", opts.Target),
			Debug:      opts.Debug,
			Options:    []string{"ro"},
		},
		UID: uint32(os.Getuid()),
		GID: uint32(os.Getgid()),
	}

	// 6. Mount
	server, err := fs.Mount(opts.Mountpoint, root, mOpts)
	if err != nil {
		return fmt.Errorf("failed to mount: %w", err)
	}

	fmt.Printf("Successfully mounted %s at %s\n", opts.Target, opts.Mountpoint)
	fmt.Println("Press Ctrl+C to unmount.")

	// 7. Signal Handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigCh:
			fmt.Println("\nReceived signal, unmounting...")
		case <-ctx.Done():
			fmt.Println("\nContext cancelled, unmounting...")
		}
		err := server.Unmount()
		if err != nil {
			fmt.Printf("Error during unmount: %v\n", err)
		}
	}()

	// 8. Wait for unmount
	server.Wait()
	fmt.Println("Unmounted successfully.")

	return nil
}
