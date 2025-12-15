package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/hppk"
	"github.com/xtaci/qpp"
	"github.com/xtaci/qsh/protocol"
)

// TestHPPKAuthSuccess verifies that a client can sign a challenge and the server verifies it.
func TestHPPKAuthSuccess(t *testing.T) {
	client, err := hppk.GenerateKey(8)
	require.NoError(t, err)

	challenge := make([]byte, 48)
	_, err = rand.Read(challenge)
	require.NoError(t, err)

	sig, err := client.Sign(challenge)
	require.NoError(t, err)

	require.True(t, hppk.VerifySignature(sig, challenge, client.Public()))
}

// TestHPPKAuthFailOnTamper ensures tampering with the challenge invalidates the signature.
func TestHPPKAuthFailOnTamper(t *testing.T) {
	client, err := hppk.GenerateKey(8)
	require.NoError(t, err)

	challenge := make([]byte, 48)
	_, err = rand.Read(challenge)
	require.NoError(t, err)

	sig, err := client.Sign(challenge)
	require.NoError(t, err)

	tampered := append([]byte(nil), challenge...)
	tampered[0] ^= 0xFF

	require.False(t, hppk.VerifySignature(sig, tampered, client.Public()))
}

// TestPerformHandshakesEndToEnd simulates the full handshake and encrypted exchange over an in-memory pipe.
func TestPerformHandshakesEndToEnd(t *testing.T) {
	client, err := hppk.GenerateKey(8)
	require.NoError(t, err)

	const clientID = "client-1"
	registry := clientRegistry{clientID: client.Public()}

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})

	type serverResult struct {
		clientID string
		writer   *encryptedWriter
		recv     *qpp.QuantumPermutationPad
		err      error
	}
	srvCh := make(chan serverResult, 1)
	go func() {
		id, writer, recv, err := performServerHandshake(serverConn, registry)
		srvCh <- serverResult{clientID: id, writer: writer, recv: recv, err: err}
	}()

	clientWriter, clientRecv, err := performClientHandshake(clientConn, client, clientID)
	require.NoError(t, err)

	srv := <-srvCh
	require.NoError(t, srv.err)
	require.Equal(t, clientID, srv.clientID)
	require.NotNil(t, srv.writer)
	require.NotNil(t, srv.recv)
	require.NotNil(t, clientWriter)
	require.NotNil(t, clientRecv)

	const c2sMsg = "ping from client"
	c2sErr := make(chan error, 1)
	go func() {
		payload, err := receivePayload(serverConn, srv.recv)
		if err != nil {
			c2sErr <- err
			return
		}
		if string(payload.Stream) != c2sMsg {
			c2sErr <- fmt.Errorf("unexpected server payload: %s", payload.Stream)
			return
		}
		c2sErr <- nil
	}()
	require.NoError(t, clientWriter.Send(&protocol.PlainPayload{Stream: []byte(c2sMsg)}))
	require.NoError(t, <-c2sErr)

	const s2cMsg = "pong from server"
	s2cErr := make(chan error, 1)
	go func() {
		payload, err := receivePayload(clientConn, clientRecv)
		if err != nil {
			s2cErr <- err
			return
		}
		if string(payload.Stream) != s2cMsg {
			s2cErr <- fmt.Errorf("unexpected client payload: %s", payload.Stream)
			return
		}
		s2cErr <- nil
	}()
	require.NoError(t, srv.writer.Send(&protocol.PlainPayload{Stream: []byte(s2cMsg)}))
	require.NoError(t, <-s2cErr)
}
