package ociregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	hasher := sha256.New()
	size, err := io.Copy(hasher, f)
	if err != nil {
		return "", 0, err
	}

	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), size, nil
}
