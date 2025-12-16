package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	store := newClientRegistryStore(registry)

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})

	type serverResult struct {
		session *ServerSession
		err     error
	}
	srvCh := make(chan serverResult, 1)
	go func() {
		session, err := performServerHandshake(serverConn, store)
		srvCh <- serverResult{session: session, err: err}
	}()

	clientSession, err := performClientHandshake(clientConn, client, clientID, protocol.ClientMode_CLIENT_MODE_SHELL)
	require.NoError(t, err)
	require.NotNil(t, clientSession)

	srv := <-srvCh
	require.NoError(t, srv.err)
	require.NotNil(t, srv.session)
	require.Equal(t, clientID, srv.session.ClientID)
	require.Equal(t, protocol.ClientMode_CLIENT_MODE_SHELL, srv.session.Mode)
	require.NotNil(t, srv.session.Writer)
	require.NotNil(t, srv.session.RecvPad)
	require.NotNil(t, clientSession.Writer)
	require.NotNil(t, clientSession.RecvPad)

	const c2sMsg = "ping from client"
	c2sErr := make(chan error, 1)
	go func() {
		payload, err := receivePayload(serverConn, srv.session.RecvPad, srv.session.RecvMac)
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
	require.NoError(t, clientSession.Writer.Send(&protocol.PlainPayload{Stream: []byte(c2sMsg)}))
	require.NoError(t, <-c2sErr)

	const s2cMsg = "pong from server"
	s2cErr := make(chan error, 1)
	go func() {
		payload, err := receivePayload(clientConn, clientSession.RecvPad, clientSession.RecvMac)
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
	require.NoError(t, srv.session.Writer.Send(&protocol.PlainPayload{Stream: []byte(s2cMsg)}))
	require.NoError(t, <-s2cErr)
}

func TestFileUploadTransfer(t *testing.T) {
	session := setupCopySession(t)
	data := []byte("hello qsh upload")
	dest := filepath.Join(t.TempDir(), "upload.txt")
	req := &protocol.FileTransferRequest{
		Direction: protocol.FileDirection_FILE_DIRECTION_UPLOAD,
		Path:      dest,
		Size:      uint64(len(data)),
		Perm:      0o640,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- session.server.handleFileTransferSession()
	}()
	require.NoError(t, session.client.Writer.Send(&protocol.PlainPayload{FileRequest: req}))
	ready := expectFileResult(t, session.client.Conn, session.client.RecvPad, session.client.RecvMac)
	require.True(t, ready.Success)
	require.False(t, ready.Done)
	require.Equal(t, uint64(len(data)), ready.Size)
	chunk := &protocol.FileTransferChunk{Data: data, Offset: 0, Eof: true}
	require.NoError(t, session.client.Writer.Send(&protocol.PlainPayload{FileChunk: chunk}))
	final := expectFileResult(t, session.client.Conn, session.client.RecvPad, session.client.RecvMac)
	require.True(t, final.Success)
	require.True(t, final.Done)
	require.NoError(t, <-errCh)
	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	require.Equal(t, data, got)
	info, err := os.Stat(dest)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestFileDownloadTransfer(t *testing.T) {
	session := setupCopySession(t)
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "download.txt")
	content := []byte("download payload for qsh")
	require.NoError(t, os.WriteFile(srcPath, content, 0o640))
	req := &protocol.FileTransferRequest{
		Direction: protocol.FileDirection_FILE_DIRECTION_DOWNLOAD,
		Path:      srcPath,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- session.server.handleFileTransferSession()
	}()
	require.NoError(t, session.client.Writer.Send(&protocol.PlainPayload{FileRequest: req}))
	start := expectFileResult(t, session.client.Conn, session.client.RecvPad, session.client.RecvMac)
	require.True(t, start.Success)
	require.False(t, start.Done)
	require.Equal(t, uint64(len(content)), start.Size)
	var received bytes.Buffer
	for {
		payload, err := receivePayload(session.client.Conn, session.client.RecvPad, session.client.RecvMac)
		require.NoError(t, err)
		if payload.FileChunk == nil {
			t.Fatalf("expected file chunk, got %+v", payload)
		}
		chunk := payload.FileChunk
		if len(chunk.Data) > 0 {
			received.Write(chunk.Data)
		}
		if chunk.Eof {
			break
		}
	}
	final := expectFileResult(t, session.client.Conn, session.client.RecvPad, session.client.RecvMac)
	require.True(t, final.Success)
	require.True(t, final.Done)
	require.Equal(t, content, received.Bytes())
	require.NoError(t, <-errCh)
}

type copySession struct {
	server *ServerSession
	client *ClientSession
}

func setupCopySession(t *testing.T) copySession {
	t.Helper()
	clientKey, err := hppk.GenerateKey(8)
	require.NoError(t, err)
	const clientID = "copy-client"
	registry := clientRegistry{clientID: clientKey.Public()}
	store := newClientRegistryStore(registry)
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})
	type srvRes struct {
		session *ServerSession
		err     error
	}
	srvCh := make(chan srvRes, 1)
	go func() {
		session, err := performServerHandshake(serverConn, store)
		srvCh <- srvRes{session: session, err: err}
	}()
	clientSession, err := performClientHandshake(clientConn, clientKey, clientID, protocol.ClientMode_CLIENT_MODE_COPY)
	require.NoError(t, err)
	require.NotNil(t, clientSession)
	srv := <-srvCh
	require.NoError(t, srv.err)
	require.NotNil(t, srv.session)
	require.Equal(t, clientID, srv.session.ClientID)
	require.Equal(t, protocol.ClientMode_CLIENT_MODE_COPY, srv.session.Mode)
	return copySession{server: srv.session, client: clientSession}
}

func expectFileResult(t *testing.T, conn net.Conn, pad *qpp.QuantumPermutationPad, mac []byte) *protocol.FileTransferResult {
	t.Helper()
	payload, err := receivePayload(conn, pad, mac)
	require.NoError(t, err)
	if payload.FileResult == nil {
		t.Fatalf("expected file result, got %+v", payload)
	}
	return payload.FileResult
}
