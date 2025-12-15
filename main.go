package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/xtaci/hppk"
	"github.com/xtaci/qpp"
	"github.com/xtaci/qsh/protocol"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"
)

// sessionKeyBytes defines how many bytes of keying material we derive for each
// QPP pad direction.
const sessionKeyBytes = 32

var (
	flagServerAddr     = flag.String("s", "", "server mode: listen address (e.g. :2323)")
	flagIdentity       = flag.String("identity", "./id_hppk", "client mode: path to HPPK private key")
	flagClientID       = flag.String("id", "client-1", "client identifier presented during authentication")
	flagPads           = flag.Int("pads", 977, "server mode: number of QPP pads (prime recommended)")
	flagGenKeyPath     = flag.String("genkey", "", "generate an HPPK keypair at the provided path (writes path and path.pub)")
	flagGenKeyStrength = flag.Int("genkey-strength", 8, "security parameter passed to HPPK key generation")
	allowedClients     clientFlagList
)

func init() {
	flag.Var(&allowedClients, "client", "server mode: allowed client entry in the form id=/path/to/id_hppk.pub (repeatable)")
}

// main dispatches between key generation, server mode, and client mode.
func main() {
	flag.Parse()

	if *flagGenKeyPath != "" {
		if err := generateKeyPair(*flagGenKeyPath, *flagGenKeyStrength); err != nil {
			log.Fatal(err)
		}
		return
	}

	if *flagServerAddr != "" {
		pads := validatePads(*flagPads)
		if len(allowedClients.entries) == 0 {
			log.Fatal("server mode requires at least one -client entry")
		}
		registry, err := loadClientRegistry(allowedClients.entries)
		if err != nil {
			log.Fatal(err)
		}
		if err := runServer(*flagServerAddr, pads, registry); err != nil {
			log.Fatal(err)
		}
		return
	}

	if flag.NArg() != 1 {
		fmt.Println("usage:")
		fmt.Println("  qsh -s ip:port -pads 977 -client client-1=/path/to/id_hppk.pub")
		fmt.Println("  qsh [flags] ip:port")
		fmt.Println("  qsh -genkey ./id_hppk")
		flag.PrintDefaults()
		return
	}

	priv, err := loadPrivateKey(*flagIdentity)
	if err != nil {
		log.Fatal(err)
	}

	if err := runClient(flag.Arg(0), priv, *flagClientID); err != nil {
		log.Fatal(err)
	}
}

// clientEntry binds a client identifier to a local path containing its public key.
type clientEntry struct {
	id   string
	path string
}

// clientFlagList collects repeated -client flags.
type clientFlagList struct {
	entries []clientEntry
}

// String implements flag.Value for human-readable diagnostics.
func (l *clientFlagList) String() string {
	var parts []string
	for _, entry := range l.entries {
		parts = append(parts, fmt.Sprintf("%s=%s", entry.id, entry.path))
	}
	return strings.Join(parts, ",")
}

// Set parses "id=path" pairs supplied via repeated -client flags.
func (l *clientFlagList) Set(value string) error {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid client entry %q (expected id=/path/to/key)", value)
	}
	id := strings.TrimSpace(parts[0])
	path := strings.TrimSpace(parts[1])
	if id == "" || path == "" {
		return fmt.Errorf("invalid client entry %q", value)
	}
	l.entries = append(l.entries, clientEntry{id: id, path: path})
	return nil
}

// validatePads ensures the pad count fits inside a uint16 accepted by QPP.
func validatePads(v int) uint16 {
	if v <= 0 || v > 0xFFFF {
		log.Fatalf("invalid pad count %d", v)
	}
	return uint16(v)
}

// ============================= SERVER =============================

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
func runServer(addr string, pads uint16, registry clientRegistry) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go func() {
			if err := handleServerConn(conn, pads, registry); err != nil {
				log.Printf("connection closed: %v", err)
			}
		}()
	}
}

// handleServerConn runs the handshake and launches the PTY bridge for a client.
func handleServerConn(conn net.Conn, pads uint16, registry clientRegistry) error {
	defer conn.Close()
	clientID, writer, recvQPP, err := performServerHandshake(conn, pads, registry)
	if err != nil {
		return err
	}
	log.Printf("client %s authenticated", clientID)
	return handleInteractiveShell(conn, writer, recvQPP)
}

// performServerHandshake authenticates the client and derives QPP pads.
func performServerHandshake(conn net.Conn, pads uint16, registry clientRegistry) (string, *encryptedWriter, *qpp.QuantumPermutationPad, error) {
	env := &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return "", nil, nil, err
	}
	if env.ClientHello == nil {
		_ = sendAuthResult(conn, false, "expected client hello")
		return "", nil, nil, errors.New("handshake: missing client hello")
	}
	clientID := env.ClientHello.ClientId
	pub, ok := registry[clientID]
	if !ok {
		_ = sendAuthResult(conn, false, "unknown client")
		return "", nil, nil, fmt.Errorf("unknown client %s", clientID)
	}

	challenge := make([]byte, 48)
	if _, err := rand.Read(challenge); err != nil {
		return "", nil, nil, err
	}
	masterSeed := make([]byte, sessionKeyBytes)
	if _, err := rand.Read(masterSeed); err != nil {
		return "", nil, nil, err
	}
	kem, err := hppk.Encrypt(pub, masterSeed)
	if err != nil {
		return "", nil, nil, err
	}

	challengeMsg := &protocol.Envelope{AuthChallenge: &protocol.AuthChallenge{
		Challenge:      challenge,
		KemP:           kem.P.Bytes(),
		KemQ:           kem.Q.Bytes(),
		Pads:           uint32(pads),
		SessionKeySize: sessionKeyBytes,
	}}
	if err := protocol.WriteMessage(conn, challengeMsg); err != nil {
		return "", nil, nil, err
	}

	env = &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return "", nil, nil, err
	}
	if env.AuthResponse == nil {
		_ = sendAuthResult(conn, false, "expected auth response")
		return "", nil, nil, errors.New("handshake: missing auth response")
	}
	if env.AuthResponse.ClientId != clientID {
		_ = sendAuthResult(conn, false, "client id mismatch")
		return "", nil, nil, errors.New("handshake: client id mismatch")
	}
	sig, err := signatureFromProto(env.AuthResponse.Signature)
	if err != nil {
		_ = sendAuthResult(conn, false, "invalid signature payload")
		return "", nil, nil, fmt.Errorf("decode signature: %w", err)
	}
	if !hppk.VerifySignature(sig, challenge, pub) {
		_ = sendAuthResult(conn, false, "signature verification failed")
		return "", nil, nil, errors.New("handshake: signature verification failed")
	}
	if err := sendAuthResult(conn, true, "authentication success"); err != nil {
		return "", nil, nil, err
	}

	c2sSeed, err := deriveDirectionalSeed(masterSeed, "qsh-c2s")
	if err != nil {
		return "", nil, nil, err
	}
	s2cSeed, err := deriveDirectionalSeed(masterSeed, "qsh-s2c")
	if err != nil {
		return "", nil, nil, err
	}
	writer := newEncryptedWriter(conn, qpp.NewQPP(s2cSeed, pads))
	recv := qpp.NewQPP(c2sSeed, pads)

	return clientID, writer, recv, nil
}

// sendAuthResult sends a simple AuthResult envelope to the peer.
func sendAuthResult(conn net.Conn, ok bool, message string) error {
	env := &protocol.Envelope{AuthResult: &protocol.AuthResult{Success: ok, Message: message}}
	return protocol.WriteMessage(conn, env)
}

// deriveDirectionalSeed deterministically expands the shared master secret per direction.
func deriveDirectionalSeed(master []byte, label string) ([]byte, error) {
	h := hkdf.New(sha256.New, master, nil, []byte(label))
	out := make([]byte, sessionKeyBytes)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

// handleInteractiveShell bridges the remote PTY with the encrypted stream.
func handleInteractiveShell(conn net.Conn, writer *encryptedWriter, recvQPP *qpp.QuantumPermutationPad) error {
	cmd := exec.Command("/bin/sh")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptmx.Close()

	errCh := make(chan error, 2)
	go func() { errCh <- forwardPTYToClient(ptmx, writer) }()
	go func() { errCh <- forwardClientToPTY(conn, recvQPP, ptmx) }()

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
func forwardClientToPTY(conn net.Conn, recvQPP *qpp.QuantumPermutationPad, ptmx *os.File) error {
	for {
		payload, err := receivePayload(conn, recvQPP)
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

// ============================= CLIENT =============================

// runClient dials the server, completes the handshake, and attaches local TTY IO.
func runClient(addr string, priv *hppk.PrivateKey, clientID string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	writer, recvQPP, err := performClientHandshake(conn, priv, clientID)
	if err != nil {
		return err
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	rows, cols := getWinsize()
	_ = writer.Send(&protocol.PlainPayload{Resize: &protocol.Resize{Rows: uint32(rows), Cols: uint32(cols)}})

	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	errCh := make(chan error, 2)
	go func() { errCh <- forwardStdIn(writer) }()
	go func() { errCh <- readServerOutput(conn, recvQPP) }()
	go handleClientResize(writer, done)

	err = <-errCh
	conn.Close()
	stop()
	return err
}

// performClientHandshake mirrors the server handshake and prepares stream pads.
func performClientHandshake(conn net.Conn, priv *hppk.PrivateKey, clientID string) (*encryptedWriter, *qpp.QuantumPermutationPad, error) {
	if err := protocol.WriteMessage(conn, &protocol.Envelope{ClientHello: &protocol.ClientHello{ClientId: clientID}}); err != nil {
		return nil, nil, err
	}
	env := &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, nil, err
	}
	challenge := env.AuthChallenge
	if challenge == nil {
		return nil, nil, errors.New("handshake: expected challenge")
	}
	kem := &hppk.KEM{P: new(big.Int).SetBytes(challenge.KemP), Q: new(big.Int).SetBytes(challenge.KemQ)}
	secret, err := priv.Decrypt(kem)
	if err != nil {
		return nil, nil, err
	}
	keySize := int(challenge.SessionKeySize)
	if keySize <= 0 {
		keySize = sessionKeyBytes
	}
	masterSeed := make([]byte, keySize)
	secret.FillBytes(masterSeed)

	sig, err := priv.Sign(challenge.Challenge)
	if err != nil {
		return nil, nil, err
	}
	response := &protocol.Envelope{AuthResponse: &protocol.AuthResponse{ClientId: clientID, Signature: signatureToProto(sig)}}
	if err := protocol.WriteMessage(conn, response); err != nil {
		return nil, nil, err
	}
	env = &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, nil, err
	}
	if env.AuthResult == nil || !env.AuthResult.Success {
		msg := "authentication failed"
		if env.AuthResult != nil && env.AuthResult.Message != "" {
			msg = env.AuthResult.Message
		}
		return nil, nil, errors.New(msg)
	}

	pads := uint16(challenge.Pads)
	if pads == 0 {
		pads = 977
	}
	c2sSeed, err := deriveDirectionalSeed(masterSeed, "qsh-c2s")
	if err != nil {
		return nil, nil, err
	}
	s2cSeed, err := deriveDirectionalSeed(masterSeed, "qsh-s2c")
	if err != nil {
		return nil, nil, err
	}
	writer := newEncryptedWriter(conn, qpp.NewQPP(c2sSeed, pads))
	recv := qpp.NewQPP(s2cSeed, pads)
	return writer, recv, nil
}

// forwardStdIn encrypts and forwards local keystrokes to the server.
func forwardStdIn(writer *encryptedWriter) error {
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			if sendErr := writer.Send(&protocol.PlainPayload{Stream: chunk}); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			return err
		}
	}
}

// readServerOutput decrypts server payloads and writes them to stdout.
func readServerOutput(conn net.Conn, recvQPP *qpp.QuantumPermutationPad) error {
	for {
		payload, err := receivePayload(conn, recvQPP)
		if err != nil {
			return err
		}
		if len(payload.Stream) > 0 {
			if _, err := os.Stdout.Write(payload.Stream); err != nil {
				return err
			}
		}
	}
}

// handleClientResize pushes terminal size updates to the remote PTY.
func handleClientResize(writer *encryptedWriter, done <-chan struct{}) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-done:
			return
		case <-sigCh:
			rows, cols := getWinsize()
			_ = writer.Send(&protocol.PlainPayload{Resize: &protocol.Resize{Rows: uint32(rows), Cols: uint32(cols)}})
		}
	}
}

// ============================= SHARED HELPERS =============================

// loadPrivateKey reads an HPPK private key encoded as JSON.
func loadPrivateKey(path string) (*hppk.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var priv hppk.PrivateKey
	if err := json.NewDecoder(f).Decode(&priv); err != nil {
		return nil, err
	}
	return &priv, nil
}

// loadPublicKey reads a JSON-encoded HPPK public key.
func loadPublicKey(path string) (*hppk.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var pub hppk.PublicKey
	if err := json.NewDecoder(f).Decode(&pub); err != nil {
		return nil, err
	}
	return &pub, nil
}

// getWinsize returns the caller TTY dimensions, falling back to 80x24.
func getWinsize() (rows, cols uint16) {
	w, h, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return 24, 80
	}
	return uint16(h), uint16(w)
}

// generateKeyPair creates a new HPPK keypair and persists both halves.
func generateKeyPair(path string, strength int) error {
	if path == "" {
		return errors.New("genkey requires a target path")
	}
	if strength <= 0 {
		return fmt.Errorf("invalid genkey strength %d", strength)
	}
	priv, err := hppk.GenerateKey(strength)
	if err != nil {
		return err
	}
	if err := writeJSONFile(path, 0o600, priv); err != nil {
		return err
	}
	pubPath := path + ".pub"
	if err := writeJSONFile(pubPath, 0o644, priv.Public()); err != nil {
		return err
	}
	fmt.Printf("generated HPPK keypair: %s (private), %s (public)\n", path, pubPath)
	return nil
}

// writeJSONFile writes indented JSON to disk, creating parents as needed.
func writeJSONFile(path string, perm os.FileMode, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
