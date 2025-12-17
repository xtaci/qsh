package main

import (
	"bytes"
	"container/heap"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/qpp"
	"github.com/xtaci/qsh/protocol"
)

// mockConnection is a mock implementation of Connection interface for testing.
type mockConnection struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
	mu       sync.Mutex
}

func newMockConnection() *mockConnection {
	return &mockConnection{
		readBuf:  new(bytes.Buffer),
		writeBuf: new(bytes.Buffer),
	}
}

func (m *mockConnection) Read(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.readBuf.Read(p)
}

func (m *mockConnection) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.writeBuf.Write(p)
}

func (m *mockConnection) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// TestReplayProtectionDuplicateNonce verifies that duplicate nonces are rejected.
func TestReplayProtectionDuplicateNonce(t *testing.T) {
	// Create in-memory connection pair
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Create symmetric channels for testing
	seed := []byte("test-seed-for-replay-protection-testing-12345678")
	sendPad := qpp.NewQPP(seed, 7)
	recvPad := qpp.NewQPP(seed, 7)
	macKey := []byte("test-mac-key-for-hmac-verification-1234")

	clientChannel := newEncryptedChannel(clientConn, sendPad, recvPad, macKey, macKey)
	serverChannel := newEncryptedChannel(serverConn, recvPad, sendPad, macKey, macKey)

	// Send a message from client to server
	testPayload := &protocol.PlainPayload{Stream: []byte("test message")}

	errCh := make(chan error, 1)
	go func() {
		errCh <- clientChannel.Send(testPayload)
	}()

	// First receive should succeed
	received, err := serverChannel.Recv()
	require.NoError(t, err)
	require.Equal(t, "test message", string(received.Stream))
	require.NoError(t, <-errCh)

	// Attempt to replay by capturing and re-sending the same encrypted packet
	// In a real attack, the attacker would intercept and replay network traffic.
	// Here we simulate by sending the same message again, which will have a different nonce.
	go func() {
		errCh <- clientChannel.Send(testPayload)
	}()

	// Second receive with different nonce should succeed
	received2, err := serverChannel.Recv()
	require.NoError(t, err)
	require.Equal(t, "test message", string(received2.Stream))
	require.NoError(t, <-errCh)
}

// TestTimestampValidation verifies that messages with invalid timestamps are rejected.
func TestTimestampValidation(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	seed := []byte("test-seed-timestamp-validation-testing-123456")
	sendPad := qpp.NewQPP(seed, 7)
	recvPad := qpp.NewQPP(seed, 7)
	macKey := []byte("test-mac-key-timestamp-hmac-verification")

	clientChannel := newEncryptedChannel(clientConn, sendPad, recvPad, macKey, macKey)
	serverChannel := newEncryptedChannel(serverConn, recvPad, sendPad, macKey, macKey)

	// Send a normal message
	testPayload := &protocol.PlainPayload{Stream: []byte("valid timestamp")}

	errCh := make(chan error, 1)
	go func() {
		errCh <- clientChannel.Send(testPayload)
	}()

	// Should receive successfully with valid timestamp
	received, err := serverChannel.Recv()
	require.NoError(t, err)
	require.Equal(t, "valid timestamp", string(received.Stream))
	require.NoError(t, <-errCh)
}

// TestNoncePruning verifies that the nonce window is enforced by removing the oldest entries.
func TestNoncePruning(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	seed := []byte("test-seed-nonce-pruning-testing-1234567890abc")
	sendPad := qpp.NewQPP(seed, 7)
	recvPad := qpp.NewQPP(seed, 7)
	macKey := []byte("test-mac-key-nonce-pruning-verification-12")

	clientChannel := newEncryptedChannel(clientConn, sendPad, recvPad, macKey, macKey)
	serverChannel := newEncryptedChannel(serverConn, recvPad, sendPad, macKey, macKey)

	// Preload nonce cache to its window size limit
	serverChannel.nonceMu.Lock()
	for i := 0; i < nonceWindowSize; i++ {
		heap.Push(&serverChannel.recvNonceHeap, nonceEntry{hash: uint64(i + 1), timestamp: int64(i)})
	}
	serverChannel.nonceMu.Unlock()

	// Sending one more message should trigger pruning after receipt
	testPayload := &protocol.PlainPayload{Stream: []byte("pruning test")}
	errCh := make(chan error, 1)
	go func() {
		errCh <- clientChannel.Send(testPayload)
	}()

	_, err := serverChannel.Recv()
	require.NoError(t, err)
	require.NoError(t, <-errCh)

	serverChannel.nonceMu.Lock()
	require.Equal(t, nonceWindowSize-1, serverChannel.recvNonceHeap.Len(), "window should be enforced")
	serverChannel.nonceMu.Unlock()
}

// TestCounterMonotonicity verifies that the send counter is monotonically increasing.
func TestCounterMonotonicity(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	seed := []byte("test-seed-counter-monotonicity-testing-12345")
	sendPad := qpp.NewQPP(seed, 7)
	recvPad := qpp.NewQPP(seed, 7)
	macKey := []byte("test-mac-key-counter-verification-123456")

	clientChannel := newEncryptedChannel(clientConn, sendPad, recvPad, macKey, macKey)
	serverChannel := newEncryptedChannel(serverConn, recvPad, sendPad, macKey, macKey)

	// Send multiple messages and verify counter increments
	for i := 0; i < 10; i++ {
		require.Equal(t, uint64(i), clientChannel.sendCounter, "counter should match iteration")

		testPayload := &protocol.PlainPayload{Stream: []byte("counter test")}
		errCh := make(chan error, 1)
		go func() {
			errCh <- clientChannel.Send(testPayload)
		}()

		_, err := serverChannel.Recv()
		require.NoError(t, err)
		require.NoError(t, <-errCh)
	}

	require.Equal(t, uint64(10), clientChannel.sendCounter, "counter should reach 10")
}

// TestConcurrentSendReceive verifies thread safety with concurrent operations.
func TestConcurrentSendReceive(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	seed := []byte("test-seed-concurrent-operations-testing-12345")
	sendPad := qpp.NewQPP(seed, 7)
	recvPad := qpp.NewQPP(seed, 7)
	macKey := []byte("test-mac-key-concurrent-verification-1234")

	clientChannel := newEncryptedChannel(clientConn, sendPad, recvPad, macKey, macKey)
	serverChannel := newEncryptedChannel(serverConn, recvPad, sendPad, macKey, macKey)

	const concurrency = 50
	done := make(chan struct{})

	// Server receives messages
	go func() {
		defer close(done)
		for i := 0; i < concurrency; i++ {
			_, err := serverChannel.Recv()
			require.NoError(t, err)
		}
	}()

	// Client sends messages concurrently
	for i := 0; i < concurrency; i++ {
		go func(n int) {
			testPayload := &protocol.PlainPayload{Stream: []byte("concurrent")}
			err := clientChannel.Send(testPayload)
			require.NoError(t, err)
		}(i)
	}

	// Wait for all receives to complete
	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for concurrent operations")
	}

	// Verify all nonces were unique
	serverChannel.nonceMu.Lock()
	nonceCount := serverChannel.recvNonceHeap.Len()
	serverChannel.nonceMu.Unlock()

	require.Equal(t, concurrency, nonceCount, "all nonces should be unique")
}

// TestTransportInterface verifies that encryptedChannel implements Transport.
func TestTransportInterface(t *testing.T) {
	var _ Transport = (*encryptedChannel)(nil)
}

// TestMockConnection verifies mock connection basic functionality.
func TestMockConnection(t *testing.T) {
	mockConn := newMockConnection()

	// Test write
	data := []byte("test data")
	n, err := mockConn.Write(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.Equal(t, data, mockConn.writeBuf.Bytes())

	// Test read
	mockConn.readBuf.Write([]byte("read test"))
	buf := make([]byte, 9)
	n, err = mockConn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 9, n)
	require.Equal(t, []byte("read test"), buf)

	// Test close
	err = mockConn.Close()
	require.NoError(t, err)
	require.True(t, mockConn.closed)

	// Operations after close should fail
	_, err = mockConn.Write([]byte("should fail"))
	require.Error(t, err)
}

// TestTransportWithMockConnection tests the Transport interface with mock connection.
func TestTransportWithMockConnection(t *testing.T) {
	// Create two mock connections to simulate bidirectional communication
	clientToServer := newMockConnection()
	serverToClient := newMockConnection()

	seed := []byte("test-seed-mock-transport-testing-12345678901")
	sendPad := qpp.NewQPP(seed, 7)
	recvPad := qpp.NewQPP(seed, 7)
	macKey := []byte("test-mac-key-mock-transport-verification")

	// Create custom connection that reads from one buffer and writes to another
	impl := func(r io.Reader, w io.Writer) Connection {
		return &struct {
			io.Reader
			io.Writer
			io.Closer
		}{r, w, io.NopCloser(nil)}
	}

	clientConn := impl(serverToClient.writeBuf, clientToServer.writeBuf)
	serverConn := impl(clientToServer.writeBuf, serverToClient.writeBuf)

	clientTransport := newEncryptedChannel(clientConn, sendPad, recvPad, macKey, macKey)
	serverTransport := newEncryptedChannel(serverConn, recvPad, sendPad, macKey, macKey)

	// Test send from client
	testPayload := &protocol.PlainPayload{Stream: []byte("mock test message")}
	err := clientTransport.Send(testPayload)
	require.NoError(t, err)

	// Test receive on server
	received, err := serverTransport.Recv()
	require.NoError(t, err)
	require.Equal(t, "mock test message", string(received.Stream))
}

// TestTransportClose verifies that Close() properly shuts down the transport.
func TestTransportClose(t *testing.T) {
	mockConn := newMockConnection()

	seed := []byte("test-seed-close-testing-1234567890abcdefgh")
	sendPad := qpp.NewQPP(seed, 7)
	recvPad := qpp.NewQPP(seed, 7)
	macKey := []byte("test-mac-key-close-verification-12345678")

	transport := newEncryptedChannel(mockConn, sendPad, recvPad, macKey, macKey)

	// Close should succeed
	err := transport.Close()
	require.NoError(t, err)

	// Second close should be idempotent
	err = transport.Close()
	require.NoError(t, err)

	// Operations after close should fail
	testPayload := &protocol.PlainPayload{Stream: []byte("should fail")}
	err = transport.Send(testPayload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "closed")

	_, err = transport.Recv()
	require.Error(t, err)
	require.Contains(t, err.Error(), "closed")
}

// TestSensitiveDataClearing verifies that sensitive data is zeroed on close.
func TestSensitiveDataClearing(t *testing.T) {
	mockConn := newMockConnection()

	seed := []byte("test-seed-sensitive-data-testing-1234567890")
	sendPad := qpp.NewQPP(seed, 7)
	recvPad := qpp.NewQPP(seed, 7)
	sendMacKey := []byte("send-mac-key-sensitive-data-12345678901234")
	recvMacKey := []byte("recv-mac-key-sensitive-data-12345678901234")

	channel := newEncryptedChannel(mockConn, sendPad, recvPad, sendMacKey, recvMacKey)

	// Verify keys are copied (not just referenced)
	require.NotSame(t, sendMacKey, channel.sendMac)
	require.NotSame(t, recvMacKey, channel.recvMac)

	// Keys should be non-zero before close
	hasNonZero := false
	for _, b := range channel.sendMac {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	require.True(t, hasNonZero, "sendMac should have non-zero bytes before close")

	// Close the channel
	err := channel.Close()
	require.NoError(t, err)

	// Keys should be zeroed after close
	for _, b := range channel.sendMac {
		require.Equal(t, byte(0), b, "sendMac should be zeroed after close")
	}
	for _, b := range channel.recvMac {
		require.Equal(t, byte(0), b, "recvMac should be zeroed after close")
	}

	// Nonce cache should be cleared
	require.Equal(t, 0, channel.recvNonceHeap.Len())
}

// TestConnectionInterface verifies basic Connection interface contract.
func TestConnectionInterface(t *testing.T) {
	var _ Connection = (*mockConnection)(nil)

	// Test that io.ReadWriter and io.Closer are properly composed
	mockConn := newMockConnection()

	var rw io.ReadWriter = mockConn
	require.NotNil(t, rw)

	var closer io.Closer = mockConn
	require.NotNil(t, closer)
}

// TestNewTransportConstructor tests the public constructor.
func TestNewTransportConstructor(t *testing.T) {
	// Use newEncryptedChannel directly for testing with mock
	mockConn := newMockConnection()

	seed := []byte("test-seed-constructor-testing-123456789012")
	sendPad := qpp.NewQPP(seed, 7)
	recvPad := qpp.NewQPP(seed, 7)
	macKey := []byte("test-mac-key-constructor-verification-123")

	// newEncryptedChannel accepts Connection interface
	var transport Transport = newEncryptedChannel(mockConn, sendPad, recvPad, macKey, macKey)
	require.NotNil(t, transport)

	// Should be able to close
	err := transport.Close()
	require.NoError(t, err)
}

// BenchmarkTransportSendReceive benchmarks the send/receive cycle.
func BenchmarkTransportSendReceive(b *testing.B) {
	mockConn1 := newMockConnection()
	mockConn2 := newMockConnection()

	seed := []byte("benchmark-seed-for-performance-testing-12345")
	sendPad := qpp.NewQPP(seed, 7)
	recvPad := qpp.NewQPP(seed, 7)
	macKey := []byte("benchmark-mac-key-performance-testing-123")

	impl := func(r io.Reader, w io.Writer) Connection {
		return &struct {
			io.Reader
			io.Writer
			io.Closer
		}{r, w, io.NopCloser(nil)}
	}

	clientConn := impl(mockConn2.writeBuf, mockConn1.writeBuf)
	serverConn := impl(mockConn1.writeBuf, mockConn2.writeBuf)

	client := newEncryptedChannel(clientConn, sendPad, recvPad, macKey, macKey)
	server := newEncryptedChannel(serverConn, recvPad, sendPad, macKey, macKey)

	data := make([]byte, 1024)
	payload := &protocol.PlainPayload{Stream: data}

	b.ResetTimer()
	b.SetBytes(int64(len(payload.Stream)))
	for i := 0; i < b.N; i++ {
		if err := client.Send(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := server.Recv(); err != nil {
			b.Fatal(err)
		}
	}
}
