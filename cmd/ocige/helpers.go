package main

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
)

func parseRecipients(path string) ([]age.Recipient, error) {
	if path == "" {
		return nil, fmt.Errorf("recipients file path is empty")
	}
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

func parseIdentities(path string) ([]age.Identity, error) {
	if path == "" {
		return nil, fmt.Errorf("identity file path is empty")
	}
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

func defaultCacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "ocige")
	}
	// Fallback to home dir or temp if UserCacheDir fails
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache", "ocige")
	}
	return filepath.Join(os.TempDir(), "ocige-cache")
}
