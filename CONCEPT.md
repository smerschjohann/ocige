# OCI-Compliant Vault Concept for Ocige

This document describes the concept of **Ocige** for secure, multi-file-capable data storage in an OCI-compliant container registry. The focus is on **maximum privacy (metadata obfuscation)**, **quantum security (PQ-safe)**, and **scalability**.

## 1. Core Architecture: The "Vault Identity" (Proxy Key) Method

Ocige uses a two-layer encryption strategy to decouple user access management from data storage. This allows for better scaling and instant re-keying without touching the actual data layers.

An Ocige artifact consists of:
1.  **Vault Identity**: A dedicated, random, and internal PQ-safe key pair (`age.HybridIdentity`) unique to each artifact.
2.  **Encrypted Index Layer**: A JSON blob containing the file tree and individual file headers, encrypted for the **Vault Identity**.
3.  **Encrypted Payload Layers**: Individual file chunks, encrypted for the **Vault Identity**.
4.  **OCI Config**: Stores the **Vault Identity's Secret Key**, encrypted for the actual **User Recipients** (`VaultKeySheaf`).

## 2. Encryption Workflow (Proxy Key Pattern)

1.  **Data Layer**: Every file and the index itself is encrypted using the `Vault Public Key`. This ensures that all data blobs are locked by a single, internal key.
2.  **Access Layer**: The `Vault Secret Key` is encrypted using the user's `Recipients` (Age identities).
3.  **Decryption**: To pull data, the user first decrypts the `Vault Secret Key` using their own identity, then uses that internal key to unlock the index and data layers.

### Advantage: Instant Re-Keying
To add or remove recipients, only the tiny **OCI Config** blob (containing the encrypted vault secret) needs to be updated. The potentially terabytes of data layers and the index layer remain unchanged and don't need to be re-uploaded.

## 3. Metadata Privacy & Total Obfuscation

To prevent registry administrators or monitoring tools from identifying contents, all information is encrypted or anonymized:

- **Anonymized Manifest**: Generic titles like `ocige.artifact` and `ocige.chunk.<n>` are used.
- **Encrypted Structure**: Filenames, folder structures, and individual file sizes are exclusively stored in the encrypted Index layer.
- **Config Privacy**: The OCI Config contains no clear-text metadata about the files; it only serves as the "Key Locker" for the Vault Identity.

## 4. OCI Manifest Structure (Example)

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.ocige.artifact.v1",
  "config": {
    "mediaType": "application/vnd.ocige.config.v1+json",
    "digest": "sha256:<anonymized-config-hash>"
  },
  "layers": [
    {
      "mediaType": "application/vnd.ocige.index.v1+encrypted",
      "digest": "sha256:<encrypted-index-hash>",
      "annotations": { "org.opencontainers.image.title": "ocige.index" }
    },
    {
      "mediaType": "application/vnd.ocige.layer.v1+encrypted",
      "digest": "sha256:<file-chunk-hash>",
      "annotations": { "org.opencontainers.image.title": "ocige.chunk.0" }
    }
  ]
}
```

## 5. The Index File Structure

The Index File is an encrypted JSON blob (`application/vnd.ocige.index.v1+encrypted`). It maps logical paths to OCI blobs.

Example of the decrypted Index JSON:
```json
{
  "files": [
    {
      "path": "docs/manual.pdf",
      "keysheaf": "<Base64 age header for this file - encrypted for Vault PK>",
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

## 6. Quantum Secure Age Keys

Ocige strictly enforces the use of **Post-Quantum Cryptography** (PQ-safe) for both the vault identity and user recipients:
- Uses **Hybrid Keys** (Kyber768 + X25519).
- Public Keys: `age1pq1...`
- Secret Keys: `AGE-SECRET-KEY-PQ-1...`

## 7. Security Matrix

| Feature | Standard OCI / ORAS | Ocige Vault Architecture |
| :--- | :--- | :--- |
| **Filenames** | Visible in annotations | **Encrypted in Index** |
| **Data Encryption** | Optional / External | **Native Age (Hybrid PQ)** |
| **Access Change** | Registry Permissions | **Cryptographic Re-Key (Vault Identity)** |
| **Metadata Privacy** | Low | **Absolute (Total Obfuscation)** |
| **Large File Support** | Chunked Layers | **Chunked Layers + Individual Headers** |
