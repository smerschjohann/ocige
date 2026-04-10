# Ocige
*Ocige* is a tool designed for exchanging files via a container registry. It utilizes Age encryption to secure files and leverages container registries for storage. To support large files, the content is split into chunks and packed as individual layers within the container image.
For key exchange, exclusively quantum-secure algorithms are used.
Designed as a CLI tool, it is distributed as a single binary with no external dependencies.

## Core Concept
Think of Ocige as a form of "secure file sharing" built upon container registry infrastructure. Instead of sharing files directly, they are packaged into a container image and stored in the registry. The recipient can then download and decrypt the file.
Since it uses Age, multiple recipients can receive the files by exchanging their public keys.