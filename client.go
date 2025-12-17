package main

import (
	"fmt"
	"net"
	"strings"

	cli "github.com/urfave/cli/v2"
	"github.com/xtaci/hppk"
	qcrypto "github.com/xtaci/qsh/crypto"
	"github.com/xtaci/qsh/protocol"
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
	priv, err := qcrypto.LoadPrivateKey(identity)
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
	session, err := performClientHandshake(conn, priv, clientID, protocol.ClientMode_CLIENT_MODE_SHELL)
	if err != nil {
		return err
	}

	return session.startInteractiveShell()
}
