package ociregistry

import (
	"encoding/json"
)

const (
	MediaTypeConfig = "application/vnd.ocige.config.v1+json"
	MediaTypeLayer  = "application/vnd.ocige.layer.v1+encrypted"
	MediaTypeIndex  = "application/vnd.ocige.index.v1+encrypted"
	ArtifactType    = "application/vnd.ocige.artifact.v1"
)

// Config represents the OCI Config Blob.
type Config struct {
	Version string    `json:"version"`
	Vault   VaultMeta `json:"vault"`
	Index   IndexMeta `json:"index"`
}

type VaultMeta struct {
	VaultKeySheaf  string `json:"vault_keysheaf"`   // Vault Secret Key encrypted for user Recipients
	VaultPublicKey string `json:"vault_public_key"` // Vault Public Key (for reference)
}

type IndexMeta struct {
	Digest string `json:"digest"` // Digest of the encrypted Index blob layer
}

// Index represents the CONTENT of the encrypted Index blob.
// Note: the index and all files are encrypted for the Vault Public Key.
type Index struct {
	Files []FileEntry `json:"files"`
}

type FileEntry struct {
	Path   string      `json:"path"`
	Header string      `json:"keysheaf"` // Individual Age header (encrypted for Vault Public Key)
	Chunks []BlobChunk `json:"chunks"`
	Size   int64       `json:"size_original"`
	SHA256 string      `json:"sha256_original"`
}

type BlobChunk struct {
	Digest          string `json:"layer_digest"`
	Order           int    `json:"order"`
	SizeEncrypted   int64  `json:"size_encrypted"`
	IntegritySHA256 string `json:"integrity_sha256"`
}

func (c *Config) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

func (idx *Index) Marshal() ([]byte, error) {
	return json.Marshal(idx)
}
