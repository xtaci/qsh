package main

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	cli "github.com/urfave/cli/v2"
	"github.com/xtaci/hppk"
	"github.com/xtaci/qpp"
	"github.com/xtaci/qsh/protocol"
	"golang.org/x/term"
)

// runClientCommand handles the default command execution(client mode).
func runClientCommand(c *cli.Context) error {
	if c.NArg() != 1 {
		if c.Command != nil && c.Command.Name == "client" {
			_ = cli.ShowCommandHelp(c, c.Command.Name)
		} else {
			_ = cli.ShowAppHelp(c)
		}
		return exitWithExample("client mode requires the remote target", exampleClient)
	}

	target := strings.TrimSpace(c.Args().First())
	if target == "" {
		return exitWithExample("client mode requires the remote target", exampleClient)
	}
	clientID := strings.TrimSpace(c.String("id"))
	hostPart := target
	if at := strings.Index(target, "@"); at != -1 {
		candidateID := strings.TrimSpace(target[:at])
		hostPart = strings.TrimSpace(target[at+1:])
		if candidateID != "" {
			clientID = candidateID
		}
	}
	if hostPart == "" {
		return exitWithExample("client command requires a host", exampleClient)
	}
	if clientID == "" {
		return exitWithExample("client command requires a client identifier", exampleClient)
	}
	addr := hostPart
	if !strings.Contains(hostPart, ":") {
		port := c.Int("port")
		if port <= 0 {
			port = 2222
		}
		addr = fmt.Sprintf("%s:%d", hostPart, port)
	}

	// Load client identity private key.
	identity := c.String("identity")
	if identity == "" {
		return exitWithExample("client command requires --identity", exampleClient)
	}
	priv, err := loadPrivateKey(identity)
	if err != nil {
		return fmt.Errorf("%w\nExample: %s", err, exampleClient)
	}

	// Run client connection with the private key
	if err := runClient(addr, priv, clientID); err != nil {
		if isIdentityError(err) {
			return fmt.Errorf("client connection failed (verify identity %s): %v", identity, err)
		}
		return fmt.Errorf("client connection failed: %v", err)
	}
	return nil
}

// isIdentityError checks if the error is likely due to identity/key issues.
func isIdentityError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "handshake") ||
		strings.Contains(msg, "cipher") ||
		strings.Contains(msg, "authentication") ||
		strings.Contains(msg, "passphrase") ||
		strings.Contains(msg, "decrypt")
}

// runClient dials the server, completes the handshake, and attaches local TTY IO.
func runClient(addr string, priv *hppk.PrivateKey, clientID string) error {
	// Connect to server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Perform handshake
	writer, recvQPP, recvMac, err := performClientHandshake(conn, priv, clientID, protocol.ClientMode_CLIENT_MODE_SHELL)
	if err != nil {
		return err
	}

	// Set terminal to raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	// Send initial terminal size
	rows, cols := getWinsize()
	_ = writer.Send(&protocol.PlainPayload{Resize: &protocol.Resize{Rows: uint32(rows), Cols: uint32(cols)}})

	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	// Start terminal resize handler goroutine
	go handleClientResize(writer, done)

	// Start IO forwarding
	errCh := make(chan error, 2)
	go func() { errCh <- forwardStdIn(writer) }()
	go func() { errCh <- readServerOutput(conn, recvQPP, recvMac) }()

	// Wait for any IO error
	err = <-errCh
	stop()
	return err
}

// performClientHandshake mirrors the server handshake and prepares stream pads.
func performClientHandshake(conn net.Conn, priv *hppk.PrivateKey, clientID string, mode protocol.ClientMode) (*encryptedWriter, *qpp.QuantumPermutationPad, []byte, error) {
	// 1. Send ClientHello
	if err := protocol.WriteMessage(conn, &protocol.Envelope{ClientHello: &protocol.ClientHello{ClientId: clientID, Mode: mode}}); err != nil {
		return nil, nil, nil, err
	}
	env := &protocol.Envelope{}

	// 2. Receive AuthChallenge
	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, nil, nil, err
	}
	challenge := env.AuthChallenge
	if challenge == nil {
		return nil, nil, nil, errors.New("handshake: expected challenge")
	}

	// 3. Decrypt KEM and derive master seed
	kem := &hppk.KEM{P: new(big.Int).SetBytes(challenge.KemP), Q: new(big.Int).SetBytes(challenge.KemQ)}
	secret, err := priv.Decrypt(kem)
	if err != nil {
		return nil, nil, nil, err
	}
	keySize := int(challenge.SessionKeySize)
	if keySize <= 0 {
		keySize = sessionKeyBytes
	}
	secretBytes := secret.Bytes()
	if len(secretBytes) > keySize {
		return nil, nil, nil, fmt.Errorf("handshake: decrypted secret is %d bytes but expected <= %d (wrong key?)", len(secretBytes), keySize)
	}

	// As secret is a big.Int, it may be shorter than keySize bytes, so we left-pad with 0s
	// to ensure consistent length
	masterSeed := make([]byte, keySize)
	copy(masterSeed[keySize-len(secretBytes):], secretBytes)

	// 4. Sign challenge and send AuthResponse
	sig, err := priv.Sign(challenge.Challenge)
	if err != nil {
		return nil, nil, nil, err
	}
	response := &protocol.Envelope{AuthResponse: &protocol.AuthResponse{ClientId: clientID, Signature: signatureToProto(sig)}}
	if err := protocol.WriteMessage(conn, response); err != nil {
		return nil, nil, nil, err
	}

	// 5. Receive AuthResult
	env = &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, nil, nil, err
	}
	if env.AuthResult == nil || !env.AuthResult.Success {
		msg := "authentication failed"
		if env.AuthResult != nil && env.AuthResult.Message != "" {
			msg = env.AuthResult.Message
		}
		return nil, nil, nil, errors.New(msg)
	}

	// 6. Prepare QPP pads for symmetric encryption
	pads := uint16(challenge.Pads)
	if !validatePadCount(pads) {
		return nil, nil, nil, fmt.Errorf("unsupported pad count %d (expected prime between %d and %d)", pads, minPadCount, maxPadCount)
	}

	// Derive directional seeds and create QPP instances
	c2sSeed, err := deriveDirectionalSeed(masterSeed, "qsh-c2s")
	if err != nil {
		return nil, nil, nil, err
	}
	s2cSeed, err := deriveDirectionalSeed(masterSeed, "qsh-s2c")
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive directional MAC keys
	c2sMacKey, err := deriveDirectionalMAC(masterSeed, "qsh-c2s-mac")
	if err != nil {
		return nil, nil, nil, err
	}
	s2cMacKey, err := deriveDirectionalMAC(masterSeed, "qsh-s2c-mac")
	if err != nil {
		return nil, nil, nil, err
	}

	// Create encrypted writer and receiver
	writer := newEncryptedWriter(conn, qpp.NewQPP(c2sSeed, pads), c2sMacKey)
	recv := qpp.NewQPP(s2cSeed, pads)
	return writer, recv, s2cMacKey, nil
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
func readServerOutput(conn net.Conn, recvQPP *qpp.QuantumPermutationPad, s2cMacKey []byte) error {
	for {
		payload, err := receivePayload(conn, recvQPP, s2cMacKey)
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

// getWinsize returns the caller TTY dimensions, falling back to 80x24.
func getWinsize() (rows, cols uint16) {
	w, h, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return 24, 80
	}
	return uint16(h), uint16(w)
}
