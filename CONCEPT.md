# OCI-Compliant Vault Concept for Ocige

This document describes the concept of **Ocige** for secure, multi-file-capable data storage in an OCI-compliant container registry. The focus is on **maximum privacy (metadata obfuscation)**, **quantum security**, and **scalability via chunking**.

## 1. Core Architecture: The "Secure Index" Method

Unlike standard images or simple tar archives, Ocige uses an indexing system that strictly separates metadata from user data, encrypting both layers independently.

An Ocige artifact consists of:
1.  **OCI Manifest**: A list of all data blobs and the index blob.
2.  **Encrypted Index Layer**: An encrypted blob containing the file tree (filenames, paths, file sizes, and individual Age headers).
3.  **Encrypted Payload Layers**: The actually encrypted file contents, split into chunks.
4.  **OCI Config**: The carrier for the Age header of the Index Layer.

## 2. Metadata Privacy & Total Obfuscation

To prevent registry administrators or monitoring tools from drawing conclusions about the content, all identifiable information is encrypted:

- **Manifest & Layer Annotations**: Instead of clear-text names, generic titles are used:
    - Manifest: `org.opencontainers.image.title": "ocige.artifact"`
    - Layer: `org.opencontainers.image.title": "ocige.chunk.<n>"`
- **Encrypted Index**: Clear-text filenames and the folder structure are stored **exclusively** within the encrypted index layer. Without the Age key, an attacker sees only a collection of anonymous blobs.
- **OCI Config**: The config file contains no information about the original file (no name, no size, no hashes). It only contains the `keysheaf` (encrypted Age header) for the index layer.

## 3. Individual Encryption & Random Access

Each file within the artifact is protected by its own Age encryption session:
1.  Each file receives its own random symmetric file key.
2.  The corresponding Age header is stored in the encrypted index.
3.  **Advantage**: This enables "Random Access". The client can load and decrypt the index, then specifically load only the data chunks for a specific file without having to download the entire archive.

## 4. OCI Manifest Structure (Example)

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.ocige.artifact.v1",
  "config": {
    "mediaType": "application/vnd.ocige.config.v1+json",
    "digest": "sha256:<hash-of-anonymous-config>"
  },
  "layers": [
    {
      "mediaType": "application/vnd.ocige.index.v1+encrypted",
      "digest": "sha256:<hash-of-encrypted-index>",
      "annotations": { "org.opencontainers.image.title": "ocige.index" }
    },
    {
      "mediaType": "application/vnd.ocige.layer.v1+encrypted",
      "digest": "sha256:<hash-of-file1-chunk1>",
      "annotations": { "org.opencontainers.image.title": "ocige.chunk.0" }
    }
  ]
}
```

## 5. The Index File Structure

The Index File is an encrypted JSON blob that acts as the "Secure Registry within the Registry". It is identified by the `application/vnd.ocige.index.v1+encrypted` media type.

Example of the decrypted Index JSON:
```json
{
  "files": [
    {
      "path": "docs/manual.pdf",
      "keysheaf": "<Base64 age header for this file>",
      "chunks": [
        {
          "layer_digest": "sha256:<blob-hash>",
          "order": 0,
          "size_encrypted": 52428800,
          "integrity_sha256": "<ciphertext-hash>"
        }
      ],
      "size_original": 48291022,
      "sha256_original": "<plaintext-hash>"
    }
  ]
}
```

Each file entry contains the technical information required to fetch and decrypt specifically that file. This hierarchical encryption (Config -> Index -> Files) ensures that even if one file key was somehow leaked, the names and structure of other files remain protected by the index encryption.

## 6. Garbage Collector Safety

The mechanism is fully compliant with the OCI Image Manifest specification. Since all blobs (index and data chunks) are explicitly listed in the `layers` array of the manifest, they are considered active by registry garbage collectors and not deleted as long as a tag (e.g., `:latest`) points to the manifest.

## 6. Quantum Secure Age Keys

Ocige leverages the post-quantum security of **Age (X25519 + Kyber768 hybrid keys)**.
- Public Keys start with `age1pq1...`.
- Secret Keys start with `AGE-SECRET-KEY-PQ-1...`.
- The application enforces the use of these keys to guarantee future-proof encryption against attacks by quantum computers.

## 7. Security Benefits Summary

| Feature | Standard OCI / ORAS | Ocige Architecture 2.0 |
| :--- | :--- | :--- |
| **Filenames** | Often visible in annotations | **Encrypted in the index** |
| **File structure** | Visible | **Encrypted in the index** |
| **Per-file sizes** | Visible | **Encrypted in the index** |
| **Access Control** | Registry Auth | **Age (End-to-End) + PQ Security** |
| **Selective Pull** | Yes (via Layers) | **Yes (via Index + individual headers)** |
