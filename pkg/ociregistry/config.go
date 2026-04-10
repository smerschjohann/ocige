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
// It only contains technical metadata and the Age header for the Index Layer.
type Config struct {
	Version  string     `json:"version"`
	Index    IndexMeta  `json:"index"`
}

type IndexMeta struct {
	KeySheaf string `json:"keysheaf"` // Age header for the encrypted Index blob
	Digest   string `json:"digest"`   // Digest of the encrypted Index blob layer
}

// Index represents the CONTENT of the encrypted Index blob.
// It maps filenames to their individual Age headers and layer chunks.
type Index struct {
	Files []FileEntry `json:"files"`
}

type FileEntry struct {
	Path     string      `json:"path"`
	Header   string      `json:"keysheaf"` // Individual Age header for this file
	Chunks   []BlobChunk `json:"chunks"`   // Digests of the chunks of this file
	Size     int64       `json:"size_original"`
	SHA256   string      `json:"sha256_original"`
}

type BlobChunk struct {
	Digest         string `json:"layer_digest"`
	Order          int    `json:"order"`
	SizeEncrypted  int64  `json:"size_encrypted"`
	IntegritySHA256 string `json:"integrity_sha256"`
}

func (c *Config) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

func (idx *Index) Marshal() ([]byte, error) {
	return json.Marshal(idx)
}
