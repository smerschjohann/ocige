package main

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
)

func parseRecipients(path string, allowNonPQ bool) ([]age.Recipient, error) {
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

	if !allowNonPQ {
		for _, r := range recipients {
			// Specifically block known non-PQ recipients (X25519).
			// We allow HybridRecipient (known PQ-safe) and Plugins (could be PQ-safe).
			if _, ok := r.(*age.X25519Recipient); ok {
				return nil, fmt.Errorf("non-PQ recipient found: X25519 (age1...) is not allowed, please use a Hybrid (age1pq1...) key or a PQ-safe plugin (or use --allow-non-pq to override)")
			}
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

	return age.ParseIdentities(f)
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

func IsBinary(data []byte) bool {
	// A simple but effective heuristic: check for null bytes
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}
