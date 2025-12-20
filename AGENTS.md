# qsh Project Overview

`qsh` (Quantum-Safe Shell) is a secure remote shell and file transfer utility designed to provide post-quantum security. It integrates **HPPK** (Homomorphic Public Key Cryptography) for authentication and key exchange, and **QPP** (Quantum Permutation Pad) for symmetric encryption of the communication channel.

## Core Features

*   **Secure Remote Shell**: Interactive terminal access similar to SSH.
*   **Secure File Copy**: `scp`-like functionality for uploading and downloading files.
*   **Post-Quantum Security**: Built on HPPK and QPP to resist quantum computing attacks.
*   **Single Binary**: Functions as both client and server based on CLI commands.
*   **Mutual Authentication**: Verifies both client and server identities.

## Architecture

The project follows a modular architecture:

### 1. Entry Point & CLI (`main.go`, `cmd_*.go`)
*   **`main.go`**: Uses `urfave/cli` to parse arguments and dispatch commands.
*   **`cmd_client.go`**: Implements the client-side logic for the interactive shell.
*   **`cmd_server.go`**: Implements the server-side listener and connection handling.
*   **`cmd_copy.go`**: Implements the file transfer client logic.
*   **`cmd_genkey.go`** (in `main.go`): Handles key pair generation.

### 2. Protocol & Data Serialization (`protocol/`)
*   **Protobuf**: All messages are serialized using Protocol Buffers (`protocol/messages.proto`).
*   **`Envelope`**: The top-level message container. It wraps handshake messages (`ClientHello`, `ServerHello`, etc.) and `SecureData`.
*   **`SecureData`**: Encrypted payload container used after the handshake. Contains ciphertext, MAC, nonce, and timestamp.
*   **`PlainPayload`**: The actual application data (terminal stream, resize events, file transfer chunks) inside the encrypted `SecureData`.

### 3. Security Layer (`channel.go`, `crypto/`)
*   **`encryptedChannel`**: Implements the `Transport` interface. It handles:
    *   **Encryption/Decryption**: Uses QPP pads derived from the session key.
    *   **Integrity**: Uses HMAC-SHA256 to verify message authenticity.
    *   **Replay Protection**: Uses a combination of timestamp validation (rejecting old/future packets) and a sliding window of nonces (using a min-heap) to prevent replay attacks.
*   **`crypto/`**: Contains helper functions for HPPK key loading, signature handling, and padding.
    *   **Memory Protection**: Uses `memguard` to protect private keys and passphrases in memory, preventing them from being swapped to disk or exposed in core dumps.

### 4. Session Management (`session.go`)
*   **Handshake**: Implements the multi-step handshake protocol to establish a secure session.
    1.  **ClientHello**: Client sends ID and mode.
    2.  **ServerHello**: Server sends public key and signature (verifying server identity).
    3.  **AuthChallenge**: Server sends an HPPK-encrypted challenge (KEM).
    4.  **AuthResponse**: Client decrypts the challenge and signs it (verifying client identity).
    5.  **AuthResult**: Server confirms authentication success.
*   **Session Lifecycle**: Manages the connection after the handshake, handling terminal resizing and I/O.

### 5. Identity Management (`registry.go`, `known_hosts.go`)
*   **`registry.go`**: Manages authorized client public keys on the server side.
*   **`known_hosts.go`**: Manages trusted server public keys on the client side (similar to `~/.ssh/known_hosts`).

### 6. File Transfer (`transfer.go`)
*   Implements the logic for sending and receiving files.
*   Supports both upload (Client -> Server) and download (Server -> Client).
*   Uses `FileTransferRequest`, `FileTransferChunk`, and `FileTransferResult` messages.

## Key Workflows

### Connection Establishment
1.  Client initiates TCP connection.
2.  `performClientHandshake` (client) and `handleHandshake` (server) execute the protocol.
3.  Upon success, an `encryptedChannel` is created wrapping the TCP connection.
4.  The session enters the interactive loop or file transfer mode.

### Command Execution (Shell)
1.  Client reads from `stdin`, wraps data in `PlainPayload`, encrypts it into `SecureData`, and sends it via `encryptedChannel`.
2.  Server decrypts `SecureData`, extracts `PlainPayload`, and writes to the PTY (Pseudo-Terminal).
3.  Server reads from PTY, encrypts, and sends back to Client.
4.  Client decrypts and writes to `stdout`.

## Development Notes

*   **Dependencies**:
    *   `github.com/xtaci/hppk`: Authentication & Key Exchange.
    *   `github.com/xtaci/qpp`: Symmetric Encryption.
    *   `github.com/awnumar/memguard`: Secure memory management for sensitive data.
    *   `github.com/urfave/cli/v2`: CLI framework.
    *   `google.golang.org/protobuf`: Protocol Buffers.
    *   `github.com/creack/pty`: PTY handling.

*   **Building**: Standard Go build process (`go build`).
