qsh
===
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

Quick Start
-----------
1. Generate keys (run once):

	```bash
	qsh genkey -o ./id_hppk
	```

	Copy `id_hppk.pub` to the server and reference it via `-c client-1=/path/to/id_hppk.pub`.

2. Start the server:

	```bash
	qsh server -l :2323 -c client-1=/etc/qsh/id_hppk.pub
	```

3. Connect from the client (client mode is the default when no subcommand is provided):

	```bash
	qsh -i ./id_hppk -n client-1 203.0.113.10:2323
	```

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
  - `main.go` – CLI parsing, server/client orchestration, and PTY bridge.
  - `protocol/` – protobuf definitions plus length-prefixed codec helpers.
	- `channel.go` – streaming layer that encrypts/decrypts protobuf payloads with QPP pads.
	- `crypto.go` – key generation, encrypted key storage, and HPPK private key handling.
	- `signature.go` – marshalling helpers that convert HPPK signatures to/from protobufs.

License
-------
See `LICENSE` for the MIT terms that govern this project.
