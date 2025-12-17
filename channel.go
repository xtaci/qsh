package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/xtaci/qpp"
	"github.com/xtaci/qsh/protocol"
)

const (
	// nonceSize defines the length of nonces for replay protection
	nonceSize = 16
	// maxTimestampSkew defines the maximum acceptable clock difference in seconds
	maxTimestampSkew = 300 // 5 minutes
	// nonceWindowSize defines how many recent nonces to track for replay detection
	nonceWindowSize = 10000
)

// Transport defines the interface for secure bidirectional communication.
// This abstraction allows different implementations (TCP, WebSocket, QUIC, mock)
// without changing the core encryption/authentication logic.
type Transport interface {
	// Send encrypts and transmits a PlainPayload to the remote peer.
	Send(payload *protocol.PlainPayload) error

	// Receive blocks until the next PlainPayload is available, decrypts it,
	// and validates authenticity before returning.
	Receive() (*protocol.PlainPayload, error)

	// Close releases all resources and closes the underlying connection.
	Close() error
}

// Connection abstracts the underlying network connection for testing and flexibility.
type Connection interface {
	io.ReadWriter
	io.Closer
}

// encryptedChannel wraps the bidirectional authenticated stream, providing
// serialized Send operations and HMAC verification for Receive operations.
// It implements the Transport interface.
type encryptedChannel struct {
	conn    Connection
	sendPad *qpp.QuantumPermutationPad
	recvPad *qpp.QuantumPermutationPad
	sendMac []byte
	recvMac []byte
	sendMu  sync.Mutex
	recvMu  sync.Mutex
	closed  bool
	closeMu sync.Mutex

	// Replay protection
	sendCounter uint64
	recvNonces  map[string]int64 // nonce -> timestamp
	nonceMu     sync.Mutex
}

// Ensure encryptedChannel implements Transport interface
var _ Transport = (*encryptedChannel)(nil)

// newEncryptedChannel prepares a full-duplex channel with independent pads
// and MAC keys for each direction.
func newEncryptedChannel(conn Connection, sendPad, recvPad *qpp.QuantumPermutationPad, sendMacKey, recvMacKey []byte) *encryptedChannel {
	return &encryptedChannel{
		conn:       conn,
		sendPad:    sendPad,
		recvPad:    recvPad,
		sendMac:    append([]byte(nil), sendMacKey...),
		recvMac:    append([]byte(nil), recvMacKey...),
		recvNonces: make(map[string]int64),
	}
}

// NewTransport creates a new Transport from a net.Conn with the given encryption parameters.
// This is the primary constructor for production use.
func NewTransport(conn net.Conn, sendPad, recvPad *qpp.QuantumPermutationPad, sendMacKey, recvMacKey []byte) Transport {
	return newEncryptedChannel(conn, sendPad, recvPad, sendMacKey, recvMacKey)
}

// Send marshals a PlainPayload, encrypts it, and writes a SecureData envelope.
// Calls are serialized because QPP mutates its internal pad state per use.
func (c *encryptedChannel) Send(payload *protocol.PlainPayload) error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return fmt.Errorf("channel is closed")
	}
	c.closeMu.Unlock()

	if payload == nil {
		return fmt.Errorf("payload is nil")
	}
	plain, err := proto.Marshal(payload)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	// Generate unique nonce for replay protection
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	// Add monotonic counter to nonce for extra uniqueness
	binary.BigEndian.PutUint64(nonce[8:], c.sendCounter)
	c.sendCounter++

	// Get current timestamp
	timestamp := time.Now().Unix()

	cipher := c.encryptBuffer(plain)
	mac := c.computePayloadHMAC(c.sendMac, plain, nonce, timestamp)
	env := &protocol.Envelope{SecureData: &protocol.SecureData{
		Ciphertext: cipher,
		Mac:        mac,
		Nonce:      nonce,
		Timestamp:  timestamp,
	}}
	return protocol.WriteMessage(c.conn, env)
}

// Receive blocks for the next SecureData envelope, decrypts it, and returns the
// embedded PlainPayload after verifying its MAC and checking for replay attacks.
func (c *encryptedChannel) Receive() (*protocol.PlainPayload, error) {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return nil, fmt.Errorf("channel is closed")
	}
	c.closeMu.Unlock()

	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	env := &protocol.Envelope{}
	if err := protocol.ReadMessage(c.conn, env); err != nil {
		return nil, err
	}
	if env.SecureData == nil {
		return nil, fmt.Errorf("unexpected non-secure message received")
	}

	// Validate timestamp to prevent replay attacks with old messages
	now := time.Now().Unix()
	if env.SecureData.Timestamp == 0 {
		return nil, fmt.Errorf("missing timestamp in secure data")
	}
	timeDiff := now - env.SecureData.Timestamp
	if timeDiff < -maxTimestampSkew || timeDiff > maxTimestampSkew {
		return nil, fmt.Errorf("timestamp out of acceptable range (diff: %d seconds)", timeDiff)
	}

	// Check nonce for replay detection
	if len(env.SecureData.Nonce) != nonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d", len(env.SecureData.Nonce))
	}
	nonceKey := string(env.SecureData.Nonce)
	c.nonceMu.Lock()
	if _, exists := c.recvNonces[nonceKey]; exists {
		c.nonceMu.Unlock()
		return nil, fmt.Errorf("replay attack detected: duplicate nonce")
	}
	// Store nonce with timestamp
	c.recvNonces[nonceKey] = env.SecureData.Timestamp
	// Clean up old nonces if window is too large
	if len(c.recvNonces) > nonceWindowSize {
		c.pruneOldNonces(now)
	}
	c.nonceMu.Unlock()

	plain := c.decryptBuffer(env.SecureData.Ciphertext)
	expected := c.computePayloadHMAC(c.recvMac, plain, env.SecureData.Nonce, env.SecureData.Timestamp)
	if !hmac.Equal(expected, env.SecureData.Mac) {
		return nil, fmt.Errorf("payload hmac mismatch")
	}
	payload := &protocol.PlainPayload{}
	if err := proto.Unmarshal(plain, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// encryptBuffer copies data and encrypts the duplicate in place so callers keep
// ownership of their buffers.
func (c *encryptedChannel) encryptBuffer(data []byte) []byte {
	buf := append([]byte(nil), data...)
	c.sendPad.Encrypt(buf)
	return buf
}

// decryptBuffer mirrors encryptBuffer for the receive side.
func (c *encryptedChannel) decryptBuffer(data []byte) []byte {
	buf := append([]byte(nil), data...)
	c.recvPad.Decrypt(buf)
	return buf
}

// computePayloadHMAC computes an HMAC-SHA256 over data, nonce, and timestamp using key.
func (c *encryptedChannel) computePayloadHMAC(key, data, nonce []byte, timestamp int64) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	h.Write(nonce)
	// Include timestamp in MAC to bind it cryptographically
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(timestamp))
	h.Write(tsBytes)
	return h.Sum(nil)
}

// pruneOldNonces removes nonces older than the acceptable time window.
// Must be called with nonceMu held.
func (c *encryptedChannel) pruneOldNonces(now int64) {
	cutoff := now - maxTimestampSkew
	for nonce, ts := range c.recvNonces {
		if ts < cutoff {
			delete(c.recvNonces, nonce)
		}
	}
}

// Close shuts down the encrypted channel and releases all resources.
// After Close is called, Send and Receive will return errors.
func (c *encryptedChannel) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	// Clear sensitive data
	clear(c.sendMac)
	clear(c.recvMac)

	// Clear nonce cache
	c.nonceMu.Lock()
	c.recvNonces = nil
	c.nonceMu.Unlock()

	return c.conn.Close()
}
