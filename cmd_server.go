package main

import (
	"fmt"
	"log"
	"net"

	cli "github.com/urfave/cli/v2"
	"github.com/xtaci/hppk"
	qcrypto "github.com/xtaci/qsh/crypto"
	"github.com/xtaci/qsh/protocol"
)

// server command implementation.
func runServerCommand(c *cli.Context) error {
	addr := c.String("listen")
	if addr == "" {
		return exitWithExample("server command requires --listen", exampleServer)
	}
	hostKeyPath := c.String("host-key")
	if hostKeyPath == "" {
		return exitWithExample("server command requires --host-key", exampleServer)
	}
	hostKey, err := qcrypto.LoadPrivateKey(hostKeyPath)
	if err != nil {
		return fmt.Errorf("load host key %s: %w", hostKeyPath, err)
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
	return runServer(addr, store, loader, configPath != "", hostKey)
}

// runServer accepts TCP clients and performs the secure handshake per session.
func runServer(addr string, store *clientRegistryStore, loader registryLoader, watchReload bool, hostKey *hppk.PrivateKey) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("listening on %s", addr)

	// Start registry reload watcher if enabled.
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
			if err := handleServerConn(conn, store, hostKey); err != nil {
				log.Printf("connection closed: %v", err)
			}
		}()
	}
}

// handleServerConn runs the handshake and launches the PTY bridge for a client.
func handleServerConn(conn net.Conn, store *clientRegistryStore, hostKey *hppk.PrivateKey) error {
	defer conn.Close()
	session, err := performServerHandshake(conn, store, hostKey)
	if err != nil {
		return err
	}
	log.Printf("client %s authenticated", session.ClientID)
	switch session.Mode {
	case protocol.ClientMode_CLIENT_MODE_COPY:
		return session.handleFileTransferSession()
	default:
		return session.handleInteractiveShell()
	}
}
