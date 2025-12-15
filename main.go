package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
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
	cli "github.com/urfave/cli/v2"
	"github.com/xtaci/hppk"
	"github.com/xtaci/qpp"
	"github.com/xtaci/qsh/protocol"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// sessionKeyBytes defines how many bytes of keying material we derive for each
// QPP pad direction.
const sessionKeyBytes = 32

const (
	encryptedKeyType = "encrypted-hppk"
	exampleGenKey    = "qsh genkey -o ./id_hppk"
	exampleServer    = "qsh server -l :2323 -pads 977 -c client-1=/etc/qsh/id_hppk.pub"
	exampleClient    = "qsh client -identity ./id_hppk -id client-1 127.0.0.1:2323"
)

// main dispatches between key generation, server mode, and client mode.
func main() {
	app := &cli.App{
		Name:  "qsh",
		Usage: "Secure remote shell using HPPK authentication and QPP encryption",
		Commands: []*cli.Command{
			{
				Name:  "genkey",
				Usage: "Generate an HPPK keypair",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "path for the private key (public key stored as path.pub)", Required: true},
					&cli.IntFlag{Name: "strength", Value: 8, Usage: "security parameter passed to HPPK key generation"},
				},
				Action: runGenKeyCommand,
			},
			{
				Name:  "server",
				Usage: "Run qsh in server mode",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "listen", Aliases: []string{"l"}, Usage: "listen address (e.g. :2323)", Required: true},
					&cli.IntFlag{Name: "pads", Value: 977, Usage: "number of QPP pads (prime recommended)"},
					&cli.StringSliceFlag{Name: "client", Aliases: []string{"c"}, Usage: "allowed client entry in the form id=/path/to/id_hppk.pub (repeatable)"},
				},
				Action: runServerCommand,
			},
			{
				Name:  "client",
				Usage: "Connect to a qsh server",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "identity", Value: "./id_hppk", Usage: "path to the HPPK private key"},
					&cli.StringFlag{Name: "id", Value: "client-1", Usage: "client identifier presented during authentication"},
				},
				Action: runClientCommand,
			},
		},
		Action: func(c *cli.Context) error {
			_ = cli.ShowAppHelp(c)
			return cli.Exit("please specify a subcommand (genkey, server, client)", 1)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

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

func runGenKeyCommand(c *cli.Context) error {
	path := c.String("output")
	if path == "" {
		return exitWithExample("genkey command requires --output", exampleGenKey)
	}
	strength := c.Int("strength")
	if strength <= 0 {
		return exitWithExample("--strength must be a positive integer", exampleGenKey)
	}
	pass, err := promptPassword("Enter passphrase for new private key: ", true)
	if err != nil {
		return err
	}
	if len(pass) == 0 {
		return exitWithExample("passphrase cannot be empty", exampleGenKey)
	}
	defer zeroBytes(pass)
	if err := generateKeyPair(path, strength, pass); err != nil {
		return fmt.Errorf("%w\nExample: %s", err, exampleGenKey)
	}
	return nil
}

func runServerCommand(c *cli.Context) error {
	addr := c.String("listen")
	if addr == "" {
		return exitWithExample("server command requires --listen", exampleServer)
	}
	pads, err := validatePads(c.Int("pads"))
	if err != nil {
		return exitWithExample(err.Error(), exampleServer)
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
	return runServer(addr, pads, registry)
}

func runClientCommand(c *cli.Context) error {
	if c.NArg() != 1 {
		_ = cli.ShowCommandHelp(c, c.Command.Name)
		return exitWithExample("client command requires the remote address", exampleClient)
	}
	identity := c.String("identity")
	if identity == "" {
		return exitWithExample("client command requires --identity", exampleClient)
	}
	priv, err := loadPrivateKey(identity)
	if err != nil {
		return fmt.Errorf("%w\nExample: %s", err, exampleClient)
	}
	return runClient(c.Args().First(), priv, c.String("id"))
}

func exitWithExample(message, example string) error {
	return cli.Exit(fmt.Sprintf("%s\nExample: %s", message, example), 1)
}

// validatePads ensures the pad count fits inside a uint16 accepted by QPP.
func validatePads(v int) (uint16, error) {
	if v <= 0 || v > 0xFFFF {
		return 0, fmt.Errorf("invalid pad count %d", v)
	}
	return uint16(v), nil
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

// loadPrivateKey reads an HPPK private key and decrypts it if needed.
func loadPrivateKey(path string) (*hppk.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var encrypted encryptedKeyFile
	if err := json.Unmarshal(data, &encrypted); err == nil && encrypted.Type == encryptedKeyType {
		pass, err := promptPassword(fmt.Sprintf("Enter passphrase for %s: ", path), false)
		if err != nil {
			return nil, err
		}
		if len(pass) == 0 {
			return nil, errors.New("passphrase required to decrypt private key")
		}
		defer zeroBytes(pass)
		plain, err := decryptPrivateKey(&encrypted, pass)
		if err != nil {
			return nil, err
		}
		var priv hppk.PrivateKey
		if err := json.Unmarshal(plain, &priv); err != nil {
			return nil, err
		}
		return &priv, nil
	}
	var priv hppk.PrivateKey
	if err := json.Unmarshal(data, &priv); err != nil {
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

// generateKeyPair creates a new HPPK keypair, encrypts the private key, and persists both halves.
func generateKeyPair(path string, strength int, passphrase []byte) error {
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
	encBlob, err := encryptPrivateKey(priv, passphrase)
	if err != nil {
		return err
	}
	if err := writeJSONFile(path, 0o600, encBlob); err != nil {
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

type encryptedKeyFile struct {
	Type       string          `json:"type"`
	Version    int             `json:"version"`
	KDF        string          `json:"kdf"`
	ScryptN    int             `json:"scrypt_n"`
	ScryptR    int             `json:"scrypt_r"`
	ScryptP    int             `json:"scrypt_p"`
	Salt       []byte          `json:"salt"`
	Nonce      []byte          `json:"nonce"`
	Ciphertext []byte          `json:"ciphertext"`
	PublicKey  *hppk.PublicKey `json:"public_key,omitempty"`
}

const (
	kdfName     = "scrypt"
	scryptCostN = 1 << 15
	scryptCostR = 8
	scryptCostP = 1
)

func encryptPrivateKey(priv *hppk.PrivateKey, passphrase []byte) (*encryptedKeyFile, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("empty passphrase not allowed")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key(passphrase, salt, scryptCostN, scryptCostR, scryptCostP, 32)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(priv)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	zeroBytes(plain)
	return &encryptedKeyFile{
		Type:       encryptedKeyType,
		Version:    1,
		KDF:        kdfName,
		ScryptN:    scryptCostN,
		ScryptR:    scryptCostR,
		ScryptP:    scryptCostP,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		PublicKey:  priv.Public(),
	}, nil
}

func decryptPrivateKey(enc *encryptedKeyFile, passphrase []byte) ([]byte, error) {
	if enc.KDF != kdfName {
		return nil, fmt.Errorf("unsupported kdf %s", enc.KDF)
	}
	N, r, p := enc.ScryptN, enc.ScryptR, enc.ScryptP
	if N == 0 {
		N = scryptCostN
	}
	if r == 0 {
		r = scryptCostR
	}
	if p == 0 {
		p = scryptCostP
	}
	key, err := scrypt.Key(passphrase, enc.Salt, N, r, p, 32)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(enc.Nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size in key file")
	}
	plain, err := gcm.Open(nil, enc.Nonce, enc.Ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func promptPassword(prompt string, confirm bool) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		confirmPass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			zeroBytes(pass)
			zeroBytes(confirmPass)
			return nil, err
		}
		if !bytes.Equal(pass, confirmPass) {
			zeroBytes(pass)
			zeroBytes(confirmPass)
			return nil, errors.New("passphrases do not match")
		}
		zeroBytes(confirmPass)
	}
	return pass, nil
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
