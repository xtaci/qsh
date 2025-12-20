qsh
------------

[![GoDoc][1]][2] [![Go Report Card][3]][4] [![CreatedAt][5]][6] 

[1]: https://godoc.org/github.com/xtaci/qsh?status.svg
[2]: https://pkg.go.dev/github.com/xtaci/qsh
[3]: https://goreportcard.com/badge/github.com/xtaci/qsh
[4]: https://goreportcard.com/report/github.com/xtaci/qsh
[5]: https://img.shields.io/github/created-at/xtaci/qsh
[6]: https://img.shields.io/github/created-at/xtaci/qsh

English | [简体中文](README-zh-CN.md)

Status: Developing

Overview
--------
`qsh` is a Go-based secure remote shell that mirrors an SSH login experience while relying on two research projects from the same author: [HPPK](https://github.com/xtaci/hppk) for post-quantum-friendly authentication and [QPP](https://github.com/xtaci/qpp) for stream encryption. The binary exposes both a server and client mode, plus a helper for generating compatible keypairs.

Key Features
------------
- **Strong authentication** – servers whitelist client IDs and verify HPPK signatures produced during the handshake.
- **Encrypted tunnel** – both directions derive unique pads via HKDF, feed them into QPP, and negotiate a random prime pad count (between 1024 and 2048) for each connection.
- **Proto-framed control channel** – all signaling (hello, challenges, resize notices, encrypted data) rides over a length-prefixed protobuf envelope defined in `protocol/`.
- **True terminal UX** – the server spawns a PTY via `/bin/sh`, mirrors stdout/stderr, and honors window resize events.
- **Built-in key management** – run `qsh genkey -o <path>` to create JSON-encoded private/public key files (private halves are encrypted with a passphrase).
- **Memory Protection** – uses `memguard` to securely handle private keys and passphrases in memory, preventing swap leaks and core dump exposure.

Quick Start
-----------
1. Generate keys (run once):

	```bash
	# Generate server host key
	qsh genkey -o ./server_hppk
	
	# Generate client key
	qsh genkey -o ./id_hppk
	```

	Copy `id_hppk.pub` to the server and reference it via `-c client-1=/path/to/id_hppk.pub`.

2. Start the server:

	```bash
	qsh server -l :2323 --host-key ./server_hppk -c client-1=/etc/qsh/id_hppk.pub
	```
	
	Or use a clients configuration file:
	
	```bash
	qsh server -l :2323 --host-key ./server_hppk --clients-config /etc/qsh/clients.json
	```

3. Connect from the client (client mode is the default when no subcommand is provided):

	```bash
	qsh -i ./id_hppk -P 2323 client-1@203.0.113.10
	```

	Omit `-P` to fall back to the default port `2222`, or provide `-n/--id` to override the client identifier when it is not embedded in the `client-id@host` target.

Copying Files
-------------
The `copy` subcommand reuses the same identity flags as the interactive client while accepting SCP-style targets in the form `client-id@host:/remote/path`. Exactly one endpoint must be remote.

- Upload a local file to the server (defaults to TCP port 2222 when no `:port` suffix is present):

	```bash
	qsh copy -i ./id_hppk ./notes.txt client-1@example.com:/tmp/notes.txt
	```

- Download a remote file to the current directory, overriding the port with `-P`:

	```bash
	qsh copy -i ./id_hppk -P 4242 client-1@example.com:/var/log/qsh.log ./qsh.log
	```

Both commands authenticate as `client-1` (taken either from the remote spec or via `-n/--id`) and automatically derive the encrypted file-transfer channel.

Client Registry Configuration
-----------------------------
Instead of listing every `--client` flag on the command line, the server can load its allowlist from a JSON file via `--clients-config`:

```json
{
	"clients": [
        { "id": "xtaci", "public_key": "/home/xtaci/xtaci.pub" },
		{ "id": "ops-admin", "public_key": "/etc/qsh/ops-admin.pub" }
	]
}
```

- Each entry must provide a unique `id` plus the filesystem path of the corresponding HPPK public key.
- Combine the JSON file with extra `--client id=/path` flags to layer temporary overrides.
- Send `SIGUSR1` to the running server process (e.g., `kill -USR1 <pid>`) whenever the file changes to trigger an in-place reload of the registry.

Protocol Highlights
-------------------
1. **ClientHello** – announces a client ID.
2. **AuthChallenge** – server returns a random challenge, KEM-wrapped session seed, and the negotiated prime pad count.
3. **AuthResponse** – client signs the challenge with its HPPK private key and proves possession.
4. **AuthResult** – server verifies the signature before both sides derive directional seeds (`qsh-c2s`, `qsh-s2c`) via HKDF and instantiate QPP pads.
5. **Secure streaming** – plaintext PTY data and resize events are wrapped inside `PlainPayload`, encrypted into `SecureData`, and exchanged until either side disconnects.

Development Notes
-----------------
- Requires Go 1.25.4+ (see `go.mod`).
- Run tests with `go test ./...` to exercise the protobuf auth flow.
- Key implementation files:
  - `main.go` – CLI entry point and command definitions.
  - `cmd_client.go`, `cmd_server.go`, `cmd_copy.go` – command handlers for client, server, and copy operations.
  - `session.go` – handshake protocol implementation for client and server.
  - `tty.go` – PTY management and terminal I/O forwarding.
  - `transfer.go` – file upload/download implementation.
  - `channel.go` – encrypted communication channel with replay protection.
  - `protocol/` – protobuf definitions plus length-prefixed codec helpers.
  - `crypto/` – key generation, encrypted key storage, HPPK signatures, and HKDF derivation.

License
-------
See `LICENSE` for the MIT terms that govern this project.
