package main

import (
	"container/heap"
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

// Transport defines the interface for secure bidirectional communication.
// This abstraction allows different implementations (TCP, WebSocket, QUIC, mock)
// without changing the core encryption/authentication logic.
type Transport interface {
	// Send encrypts and transmits a PlainPayload to the remote peer.
	Send(payload *protocol.PlainPayload) error

	// Receive blocks until the next PlainPayload is available, decrypts it,
	// and validates authenticity before returning.
	Recv() (*protocol.PlainPayload, error)

	// Close releases all resources and closes the underlying connection.
	Close() error
}

// Connection abstracts the underlying network connection for testing and flexibility.
type Connection interface {
	io.ReadWriteCloser
}

// encryptedChannel wraps the bidirectional authenticated stream, providing
// serialized Send operations and HMAC verification for Receive operations.
// It implements the Transport interface.
type encryptedChannel struct {
	conn Connection

	// QPP pads for each direction
	sendPad *qpp.QuantumPermutationPad
	recvPad *qpp.QuantumPermutationPad

	// MAC keys for each direction
	sendMacKey []byte
	recvMacKey []byte

	// Synchronization for sending and receiving
	sendMu sync.Mutex
	recvMu sync.Mutex

	// Closed state
	closed  bool
	closeMu sync.Mutex

	// Replay protection
	sendCounter uint64
	nonceHeap   *nonceMinHeap
	nonceMu     sync.Mutex
}

// nonceEntry represents a tracked nonce with its hash and timestamp.
type nonceEntry struct {
	hash      uint64 // compact nonce to reduce memory usage
	timestamp int64
}

// hashNonceValue compact a nonce for memory-efficient storage.
func hashNonceValue(nonce []byte) uint64 {
	sum := sha256.Sum256(nonce)
	return binary.BigEndian.Uint64(sum[:8])
}

// nonceMinHeap implements a min-heap for nonce entries based on timestamp,
type nonceMinHeap struct {
	entries     []nonceEntry // heap of nonce entries
	nonceHashes map[uint64]struct{}
}

func newNonceMinHeap() *nonceMinHeap {
	return &nonceMinHeap{
		entries:     make([]nonceEntry, 0),
		nonceHashes: make(map[uint64]struct{}),
	}
}

func (h nonceMinHeap) Len() int { return len(h.entries) }
func (h nonceMinHeap) Less(i, j int) bool {
	return h.entries[i].timestamp < h.entries[j].timestamp
}
func (h nonceMinHeap) Swap(i, j int) { h.entries[i], h.entries[j] = h.entries[j], h.entries[i] }

func (h *nonceMinHeap) ensureNonceMap() {
	if h.nonceHashes == nil {
		h.nonceHashes = make(map[uint64]struct{})
	}
}

// Hash returns whether the provided nonce hash is already tracked.
func (h *nonceMinHeap) Hash(nonce uint64) bool {
	h.ensureNonceMap()
	_, exists := h.nonceHashes[nonce]
	return exists
}

func (h *nonceMinHeap) Push(x interface{}) {
	entry := x.(nonceEntry)
	h.ensureNonceMap()
	h.entries = append(h.entries, entry)
	h.nonceHashes[entry.hash] = struct{}{}
}

func (h *nonceMinHeap) Pop() interface{} {
	old := h.entries
	n := len(old)
	item := old[n-1]
	h.entries = old[:n-1]
	if h.nonceHashes != nil {
		delete(h.nonceHashes, item.hash)
	}
	return item
}

func (h *nonceMinHeap) Reset() {
	h.entries = nil
	h.nonceHashes = nil
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
		sendMacKey: append([]byte(nil), sendMacKey...),
		recvMacKey: append([]byte(nil), recvMacKey...),
		nonceHeap:  newNonceMinHeap(),
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
	mac := c.computePayloadHMAC(c.sendMacKey, plain, nonce, timestamp)
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
func (c *encryptedChannel) Recv() (*protocol.PlainPayload, error) {
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

	// Ensure timestamp is present so it stays bound to MAC
	if env.SecureData.Timestamp == 0 {
		return nil, fmt.Errorf("missing timestamp in secure data")
	}

	// Check nonce for replay detection
	if len(env.SecureData.Nonce) != nonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d", len(env.SecureData.Nonce))
	}
	nonceHash := hashNonceValue(env.SecureData.Nonce)
	c.nonceMu.Lock()
	if c.nonceHeap.Hash(nonceHash) {
		c.nonceMu.Unlock()
		return nil, fmt.Errorf("replay attack detected: duplicate nonce")
	}
	// Store nonce with timestamp
	heap.Push(c.nonceHeap, nonceEntry{hash: nonceHash, timestamp: env.SecureData.Timestamp})
	// Clean up old nonces if the window is exceeded
	c.pruneOldNonces()
	c.nonceMu.Unlock()

	plain := c.decryptBuffer(env.SecureData.Ciphertext)
	expected := c.computePayloadHMAC(c.recvMacKey, plain, env.SecureData.Nonce, env.SecureData.Timestamp)
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

// pruneOldNonces enforces the nonce window size by discarding the oldest entries.
// Must be called with nonceMu held.
func (c *encryptedChannel) pruneOldNonces() {
	for c.nonceHeap.Len() >= nonceWindowSize {
		heap.Pop(c.nonceHeap)
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
	clear(c.sendMacKey)
	clear(c.recvMacKey)

	// Clear nonce cache
	c.nonceMu.Lock()
	c.nonceHeap.Reset()
	c.nonceMu.Unlock()

	return c.conn.Close()
}
