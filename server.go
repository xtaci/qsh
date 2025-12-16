package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/creack/pty"
	cli "github.com/urfave/cli/v2"
	"github.com/xtaci/hppk"
	"github.com/xtaci/qpp"
	"github.com/xtaci/qsh/protocol"
	"golang.org/x/crypto/hkdf"
)

// clientEntry binds a client identifier to a local path containing its public key.
type clientEntry struct {
	id   string
	path string
}

type registryLoader func() (clientRegistry, error)

type clientRegistryStore struct {
	value atomic.Value
}

func newClientRegistryStore(reg clientRegistry) *clientRegistryStore {
	store := &clientRegistryStore{}
	store.value.Store(reg)
	return store
}

func (s *clientRegistryStore) Get() clientRegistry {
	reg, _ := s.value.Load().(clientRegistry)
	return reg
}

func (s *clientRegistryStore) Replace(reg clientRegistry) {
	s.value.Store(reg)
}

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
		pub, err := loadPublicKey(entry.path)
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

// handleFileTransferSession currently acts as a placeholder so the tree builds while the
// copy subcommand is under development.
func handleFileTransferSession(conn net.Conn, writer *encryptedWriter, recvQPP *qpp.QuantumPermutationPad, recvMac []byte) error {
	payload, err := receivePayload(conn, recvQPP, recvMac)
	if err != nil {
		return err
	}
	req := payload.FileRequest
	if req == nil {
		_ = sendCopyResult(writer, false, "expected file transfer request", 0, true, 0)
		return errors.New("copy: missing file transfer request")
	}
	switch req.Direction {
	case protocol.FileDirection_FILE_DIRECTION_UPLOAD:
		return handleUploadTransfer(conn, writer, recvQPP, recvMac, req)
	case protocol.FileDirection_FILE_DIRECTION_DOWNLOAD:
		return handleDownloadTransfer(writer, req)
	default:
		_ = sendCopyResult(writer, false, fmt.Sprintf("unsupported direction %v", req.Direction), 0, true, 0)
		return fmt.Errorf("copy: unsupported direction %v", req.Direction)
	}
}

func handleUploadTransfer(conn net.Conn, writer *encryptedWriter, recvQPP *qpp.QuantumPermutationPad, recvMac []byte, req *protocol.FileTransferRequest) error {
	path, err := sanitizeCopyPath(req.Path)
	if err != nil {
		_ = sendCopyResult(writer, false, err.Error(), 0, true, 0)
		return err
	}
	perm := os.FileMode(req.Perm)
	if perm == 0 {
		perm = 0o600
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		_ = sendCopyResult(writer, false, err.Error(), 0, true, uint32(perm))
		return err
	}
	defer file.Close()
	if err := sendCopyResult(writer, true, "ready", req.Size, false, uint32(perm)); err != nil {
		return err
	}
	var written uint64
	for {
		payload, err := receivePayload(conn, recvQPP, recvMac)
		if err != nil {
			_ = sendCopyResult(writer, false, err.Error(), written, true, uint32(perm))
			return err
		}
		chunk := payload.FileChunk
		if chunk == nil {
			msg := "missing file chunk"
			_ = sendCopyResult(writer, false, msg, written, true, uint32(perm))
			return errors.New("copy: missing file chunk")
		}
		if chunk.Offset != written {
			msg := fmt.Sprintf("unexpected chunk offset %d (expected %d)", chunk.Offset, written)
			_ = sendCopyResult(writer, false, msg, written, true, uint32(perm))
			return errors.New(msg)
		}
		if len(chunk.Data) > 0 {
			if _, err := file.Write(chunk.Data); err != nil {
				_ = sendCopyResult(writer, false, err.Error(), written, true, uint32(perm))
				return err
			}
			written += uint64(len(chunk.Data))
		}
		if chunk.Eof {
			break
		}
	}
	if err := file.Sync(); err != nil {
		_ = sendCopyResult(writer, false, err.Error(), written, true, uint32(perm))
		return err
	}
	return sendCopyResult(writer, true, "upload complete", written, true, uint32(perm))
}

func handleDownloadTransfer(writer *encryptedWriter, req *protocol.FileTransferRequest) error {
	path, err := sanitizeCopyPath(req.Path)
	if err != nil {
		_ = sendCopyResult(writer, false, err.Error(), 0, true, 0)
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		_ = sendCopyResult(writer, false, err.Error(), 0, true, 0)
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		_ = sendCopyResult(writer, false, err.Error(), 0, true, 0)
		return err
	}
	size := uint64(info.Size())
	perm := uint32(info.Mode().Perm())
	if err := sendCopyResult(writer, true, "starting download", size, false, perm); err != nil {
		return err
	}
	buf := make([]byte, 32*1024)
	var offset uint64
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			chunk := &protocol.FileTransferChunk{Data: append([]byte(nil), buf[:n]...), Offset: offset}
			offset += uint64(n)
			if err := writer.Send(&protocol.PlainPayload{FileChunk: chunk}); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = sendCopyResult(writer, false, readErr.Error(), offset, true, perm)
			return readErr
		}
	}
	if err := writer.Send(&protocol.PlainPayload{FileChunk: &protocol.FileTransferChunk{Offset: offset, Eof: true}}); err != nil {
		return err
	}
	return sendCopyResult(writer, true, "download complete", offset, true, perm)
}

func sanitizeCopyPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", errors.New("empty path")
	}
	return filepath.Clean(trimmed), nil
}

func sendCopyResult(writer *encryptedWriter, ok bool, message string, size uint64, done bool, perm uint32) error {
	res := &protocol.FileTransferResult{Success: ok, Message: message, Size: size, Done: done, Perm: perm}
	return writer.Send(&protocol.PlainPayload{FileResult: res})
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

	padCount, err := randomPrimePadCount()
	if err != nil {
		return "", 0, nil, nil, nil, err
	}

	// 4. Generate KEM for master secret(session key).
	// 	NOTE(x): the length of masterSeed must match sessionKeyBytes,
	// 	and the length of the key should be sent to the client.
	masterSeed := make([]byte, sessionKeyBytes)
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
		SessionKeySize: sessionKeyBytes,
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

	sig, err := signatureFromProto(env.AuthResponse.Signature)
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
	c2sSeed, err := deriveDirectionalSeed(masterSeed, "qsh-c2s")
	if err != nil {
		return "", 0, nil, nil, nil, err
	}
	s2cSeed, err := deriveDirectionalSeed(masterSeed, "qsh-s2c")
	if err != nil {
		return "", 0, nil, nil, nil, err
	}
	c2sMac, err := deriveDirectionalMAC(masterSeed, "qsh-c2s-mac")
	if err != nil {
		return "", 0, nil, nil, nil, err
	}
	s2cMac, err := deriveDirectionalMAC(masterSeed, "qsh-s2c-mac")
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

// deriveDirectionalSeed deterministically expands the shared master secret per direction.
func deriveDirectionalSeed(master []byte, label string) ([]byte, error) {
	return deriveKeyMaterial(master, label, sessionKeyBytes)
}

func deriveDirectionalMAC(master []byte, label string) ([]byte, error) {
	return deriveKeyMaterial(master, label, hmacKeyBytes)
}

func deriveKeyMaterial(master []byte, label string, size int) ([]byte, error) {
	h := hkdf.New(sha256.New, master, nil, []byte(label))
	out := make([]byte, size)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
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
