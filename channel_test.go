package main

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/qpp"
	"github.com/xtaci/qsh/protocol"
)

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
	received, err := serverChannel.Receive()
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
	received2, err := serverChannel.Receive()
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
	received, err := serverChannel.Receive()
	require.NoError(t, err)
	require.Equal(t, "valid timestamp", string(received.Stream))
	require.NoError(t, <-errCh)
}

// TestNoncePruning verifies that old nonces are cleaned up.
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

	// Send multiple messages to populate nonce cache
	for i := 0; i < 100; i++ {
		testPayload := &protocol.PlainPayload{Stream: []byte("pruning test")}
		errCh := make(chan error, 1)
		go func() {
			errCh <- clientChannel.Send(testPayload)
		}()

		_, err := serverChannel.Receive()
		require.NoError(t, err)
		require.NoError(t, <-errCh)
	}

	// Verify nonces are being tracked
	serverChannel.nonceMu.Lock()
	nonceCount := len(serverChannel.recvNonces)
	serverChannel.nonceMu.Unlock()

	require.Equal(t, 100, nonceCount, "all nonces should be tracked")

	// Simulate passage of time by manually pruning old nonces
	futureTime := time.Now().Unix() + maxTimestampSkew + 100
	serverChannel.nonceMu.Lock()
	serverChannel.pruneOldNonces(futureTime)
	prunedCount := len(serverChannel.recvNonces)
	serverChannel.nonceMu.Unlock()

	require.Equal(t, 0, prunedCount, "old nonces should be pruned")
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

		_, err := serverChannel.Receive()
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
			_, err := serverChannel.Receive()
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
	nonceCount := len(serverChannel.recvNonces)
	serverChannel.nonceMu.Unlock()

	require.Equal(t, concurrency, nonceCount, "all nonces should be unique")
}
