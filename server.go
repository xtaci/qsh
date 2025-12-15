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
	"strings"

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
	entries, err := parseClientEntries(c.StringSlice("client"))
	if err != nil {
		return exitWithExample(err.Error(), exampleServer)
	}
	if len(entries) == 0 {
		return exitWithExample("server command requires at least one --client entry", exampleServer)
	}
	registry, err := loadClientRegistry(entries)
	if err != nil {
		return err
	}
	return runServer(addr, registry)
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
func runServer(addr string, registry clientRegistry) error {
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
			if err := handleServerConn(conn, registry); err != nil {
				log.Printf("connection closed: %v", err)
			}
		}()
	}
}

// handleServerConn runs the handshake and launches the PTY bridge for a client.
func handleServerConn(conn net.Conn, registry clientRegistry) error {
	defer conn.Close()
	clientID, writer, recvQPP, err := performServerHandshake(conn, registry)
	if err != nil {
		return err
	}
	log.Printf("client %s authenticated", clientID)
	return handleInteractiveShell(conn, writer, recvQPP)
}

// performServerHandshake authenticates the client and derives QPP pads.
func performServerHandshake(conn net.Conn, registry clientRegistry) (string, *encryptedWriter, *qpp.QuantumPermutationPad, error) {
	// Receive ClientHello
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

	// Challenge client with random nonce
	challenge := make([]byte, 48)
	if _, err := rand.Read(challenge); err != nil {
		return "", nil, nil, err
	}

	padCount, err := randomPrimePadCount()
	if err != nil {
		return "", nil, nil, err
	}

	// Generate KEM for master secret.
	// NOTE(x): the length of masterSeed must match sessionKeyBytes,
	// 	and the length of the key should be sent to the client.
	masterSeed := make([]byte, sessionKeyBytes)
	if _, err := rand.Read(masterSeed); err != nil {
		return "", nil, nil, err
	}

	kem, err := hppk.Encrypt(pub, masterSeed)
	if err != nil {
		return "", nil, nil, err
	}

	// Send session key and challenge to client
	challengeMsg := &protocol.Envelope{AuthChallenge: &protocol.AuthChallenge{
		Challenge:      challenge,
		KemP:           kem.P.Bytes(),
		KemQ:           kem.Q.Bytes(),
		Pads:           uint32(padCount),
		SessionKeySize: sessionKeyBytes,
	}}

	if err := protocol.WriteMessage(conn, challengeMsg); err != nil {
		return "", nil, nil, err
	}

	// Receive AuthResponse and decode signature
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

	// Verify signature over challenge
	if !hppk.VerifySignature(sig, challenge, pub) {
		_ = sendAuthResult(conn, false, "signature verification failed")
		return "", nil, nil, errors.New("handshake: signature verification failed")
	}
	if err := sendAuthResult(conn, true, "authentication success"); err != nil {
		return "", nil, nil, err
	}

	// Derive directional QPP seeds
	c2sSeed, err := deriveDirectionalSeed(masterSeed, "qsh-c2s")
	if err != nil {
		return "", nil, nil, err
	}
	s2cSeed, err := deriveDirectionalSeed(masterSeed, "qsh-s2c")
	if err != nil {
		return "", nil, nil, err
	}

	// Initialize encrypted writer and QPP receiver
	writer := newEncryptedWriter(conn, qpp.NewQPP(s2cSeed, padCount))
	recv := qpp.NewQPP(c2sSeed, padCount)

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
