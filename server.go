package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/creack/pty"
	cli "github.com/urfave/cli/v2"
	"github.com/xtaci/hppk"
	"github.com/xtaci/qpp"
	qcrypto "github.com/xtaci/qsh/crypto"
	"github.com/xtaci/qsh/protocol"
)

// clientEntry binds a client identifier to a local path containing its public key.
type clientEntry struct {
	id   string
	path string
}

// registryLoader defines a function that loads a client registry.
type registryLoader func() (clientRegistry, error)

// clientRegistryStore provides atomic access to the client registry.
type clientRegistryStore struct {
	value atomic.Value
}

// newClientRegistryStore creates a new clientRegistryStore initialized with reg.
func newClientRegistryStore(reg clientRegistry) *clientRegistryStore {
	store := &clientRegistryStore{}
	store.value.Store(reg)
	return store
}

// Get retrieves the current client registry.
func (s *clientRegistryStore) Get() clientRegistry {
	reg, _ := s.value.Load().(clientRegistry)
	return reg
}

// Replace updates the client registry with reg.
func (s *clientRegistryStore) Replace(reg clientRegistry) {
	s.value.Store(reg)
}

// parseClientEntries parses client entries from command-line arguments.
func parseClientEntries(values []string) ([]clientEntry, error) {
	var entries []clientEntry
	for _, value := range values {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid client entry %q (expected id=/path/to/key)", value)
		}
		id := strings.TrimSpace(parts[0])
		path := strings.TrimSpace(parts[1])
		if id == "" || path == "" {
			return nil, fmt.Errorf("invalid client entry %q", value)
		}
		entries = append(entries, clientEntry{id: id, path: path})
	}
	return entries, nil
}

// server command implementation.
func runServerCommand(c *cli.Context) error {
	addr := c.String("listen")
	if addr == "" {
		return exitWithExample("server command requires --listen", exampleServer)
	}
	configPath := c.String("clients-config")
	entries, err := parseClientEntries(c.StringSlice("client"))
	if err != nil {
		return exitWithExample(err.Error(), exampleServer)
	}
	if configPath == "" && len(entries) == 0 {
		return exitWithExample("server command requires --clients-config or at least one --client entry", exampleServer)
	}
	loader := func() (clientRegistry, error) {
		return loadRegistryFromSources(entries, configPath)
	}
	registry, err := loader()
	if err != nil {
		return err
	}
	store := newClientRegistryStore(registry)
	return runServer(addr, store, loader, configPath != "")
}

// clientRegistry maps client IDs onto their trusted public keys.
type clientRegistry map[string]*hppk.PublicKey

// loadClientRegistry loads each allowed client's public key once at startup.
func loadClientRegistry(entries []clientEntry) (clientRegistry, error) {
	reg := make(clientRegistry)
	for _, entry := range entries {
		pub, err := qcrypto.LoadPublicKey(entry.path)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", entry.path, err)
		}
		reg[entry.id] = pub
	}
	return reg, nil
}

// runServer accepts TCP clients and performs the secure handshake per session.
func runServer(addr string, store *clientRegistryStore, loader registryLoader, watchReload bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("listening on %s", addr)
	if watchReload && loader != nil {
		go watchRegistryReload(store, loader)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go func() {
			if err := handleServerConn(conn, store); err != nil {
				log.Printf("connection closed: %v", err)
			}
		}()
	}
}

// watchRegistryReload listens for SIGUSR1 and reloads the client registry.
func watchRegistryReload(store *clientRegistryStore, loader registryLoader) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1)
	defer signal.Stop(sigCh)
	for range sigCh {
		log.Printf("received SIGUSR1, reloading client registry")
		registry, err := loader()
		if err != nil {
			log.Printf("client registry reload failed: %v", err)
			continue
		}
		store.Replace(registry)
		log.Printf("client registry reloaded (%d clients)", len(registry))
	}
}

// handleServerConn runs the handshake and launches the PTY bridge for a client.
func handleServerConn(conn net.Conn, store *clientRegistryStore) error {
	defer conn.Close()
	clientID, mode, writer, recvQPP, recvMac, err := performServerHandshake(conn, store)
	if err != nil {
		return err
	}
	log.Printf("client %s authenticated", clientID)
	switch mode {
	case protocol.ClientMode_CLIENT_MODE_COPY:
		return handleFileTransferSession(conn, writer, recvQPP, recvMac)
	default:
		return handleInteractiveShell(conn, writer, recvQPP, recvMac)
	}
}

// performServerHandshake authenticates the client and derives QPP pads.
func performServerHandshake(conn net.Conn, store *clientRegistryStore) (string, protocol.ClientMode, *encryptedWriter, *qpp.QuantumPermutationPad, []byte, error) {
	// 1. Receive ClientHello
	env := &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return "", 0, nil, nil, nil, err
	}

	if env.ClientHello == nil {
		_ = sendAuthResult(conn, false, "expected client hello")
		return "", 0, nil, nil, nil, errors.New("handshake: missing client hello")
	}

	mode := env.ClientHello.Mode
	if mode != protocol.ClientMode_CLIENT_MODE_COPY {
		mode = protocol.ClientMode_CLIENT_MODE_SHELL
	}

	// 2. Lookup client public key
	clientID := env.ClientHello.ClientId
	registry := store.Get()
	if registry == nil {
		_ = sendAuthResult(conn, false, "registry unavailable")
		return "", 0, nil, nil, nil, errors.New("handshake: registry unavailable")
	}
	pub, ok := registry[clientID]
	if !ok {
		_ = sendAuthResult(conn, false, "unknown client")
		return "", 0, nil, nil, nil, fmt.Errorf("unknown client %s", clientID)
	}

	// 3. Get random nonce as challenge
	challenge := make([]byte, 48)
	if _, err := rand.Read(challenge); err != nil {
		return "", 0, nil, nil, nil, err
	}

	padCount, err := qcrypto.RandomPrimePadCount()
	if err != nil {
		return "", 0, nil, nil, nil, err
	}

	// 4. Generate KEM for master secret(session key).
	// 	NOTE(x): the length of masterSeed must match SessionKeyBytes,
	// 	and the length of the key should be sent to the client.
	masterSeed := make([]byte, qcrypto.SessionKeyBytes)
	if _, err := rand.Read(masterSeed); err != nil {
		return "", 0, nil, nil, nil, err
	}

	kem, err := hppk.Encrypt(pub, masterSeed)
	if err != nil {
		return "", 0, nil, nil, nil, err
	}

	// 5. Send session key and challenge to client
	challengeMsg := &protocol.Envelope{AuthChallenge: &protocol.AuthChallenge{
		Challenge:      challenge,
		KemP:           kem.P.Bytes(),
		KemQ:           kem.Q.Bytes(),
		Pads:           uint32(padCount),
		SessionKeySize: qcrypto.SessionKeyBytes,
	}}

	if err := protocol.WriteMessage(conn, challengeMsg); err != nil {
		return "", 0, nil, nil, nil, err
	}

	// 5. Receive AuthResponse and decode signature
	env = &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return "", 0, nil, nil, nil, err
	}

	if env.AuthResponse == nil {
		_ = sendAuthResult(conn, false, "expected auth response")
		return "", 0, nil, nil, nil, errors.New("handshake: missing auth response")
	}

	if env.AuthResponse.ClientId != clientID {
		_ = sendAuthResult(conn, false, "client id mismatch")
		return "", 0, nil, nil, nil, errors.New("handshake: client id mismatch")
	}

	sig, err := qcrypto.SignatureFromProto(env.AuthResponse.Signature)
	if err != nil {
		_ = sendAuthResult(conn, false, "invalid signature payload")
		return "", 0, nil, nil, nil, fmt.Errorf("decode signature: %w", err)
	}

	// 6. Verify signature over challenge
	if !hppk.VerifySignature(sig, challenge, pub) {
		_ = sendAuthResult(conn, false, "signature verification failed")
		return "", 0, nil, nil, nil, errors.New("handshake: signature verification failed")
	}
	if err := sendAuthResult(conn, true, "authentication success"); err != nil {
		return "", 0, nil, nil, nil, err
	}

	// 7. Prepare QPP pads for symmetric encryption
	c2sSeed, err := qcrypto.DeriveDirectionalSeed(masterSeed, "qsh-c2s")
	if err != nil {
		return "", 0, nil, nil, nil, err
	}
	s2cSeed, err := qcrypto.DeriveDirectionalSeed(masterSeed, "qsh-s2c")
	if err != nil {
		return "", 0, nil, nil, nil, err
	}
	c2sMac, err := qcrypto.DeriveDirectionalMAC(masterSeed, "qsh-c2s-mac")
	if err != nil {
		return "", 0, nil, nil, nil, err
	}
	s2cMac, err := qcrypto.DeriveDirectionalMAC(masterSeed, "qsh-s2c-mac")
	if err != nil {
		return "", 0, nil, nil, nil, err
	}

	// initialize encrypted writer and QPP receiver
	writer := newEncryptedWriter(conn, qpp.NewQPP(s2cSeed, padCount), s2cMac)
	recv := qpp.NewQPP(c2sSeed, padCount)

	return clientID, mode, writer, recv, c2sMac, nil
}

// sendAuthResult sends a simple AuthResult envelope to the peer.
func sendAuthResult(conn net.Conn, ok bool, message string) error {
	env := &protocol.Envelope{AuthResult: &protocol.AuthResult{Success: ok, Message: message}}
	return protocol.WriteMessage(conn, env)
}

// handleInteractiveShell bridges the remote PTY with the encrypted stream.
func handleInteractiveShell(conn net.Conn, writer *encryptedWriter, recvQPP *qpp.QuantumPermutationPad, recvMac []byte) error {
	cmd := exec.Command("/bin/sh")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptmx.Close()

	errCh := make(chan error, 2)
	go func() { errCh <- forwardPTYToClient(ptmx, writer) }()
	go func() { errCh <- forwardClientToPTY(conn, recvQPP, recvMac, ptmx) }()

	err = <-errCh
	conn.Close()
	cmd.Process.Kill()
	cmd.Wait()
	return err
}

// forwardPTYToClient streams PTY output toward the client.
func forwardPTYToClient(ptmx *os.File, writer *encryptedWriter) error {
	buf := make([]byte, 4096)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			if sendErr := writer.Send(&protocol.PlainPayload{Stream: chunk}); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// forwardClientToPTY feeds decrypted client data back into the PTY.
func forwardClientToPTY(conn net.Conn, recvQPP *qpp.QuantumPermutationPad, recvMac []byte, ptmx *os.File) error {
	for {
		payload, err := receivePayload(conn, recvQPP, recvMac)
		if err != nil {
			return err
		}
		if len(payload.Stream) > 0 {
			if _, err := ptmx.Write(payload.Stream); err != nil {
				return err
			}
		}
		if payload.Resize != nil {
			applyResize(ptmx, payload.Resize)
		}
	}
}

// applyResize resizes the PTY; errors are ignored because resize is best-effort.
func applyResize(ptmx *os.File, resize *protocol.Resize) {
	rows := uint16(resize.Rows)
	cols := uint16(resize.Cols)
	_ = pty.Setsize(ptmx, &pty.Winsize{Rows: rows, Cols: cols})
}
