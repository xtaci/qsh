package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/xtaci/qpp"
	"github.com/xtaci/qsh/protocol"
)

// encryptedChannel wraps the bidirectional authenticated stream, providing
// serialized Send operations and HMAC verification for Receive operations.
type encryptedChannel struct {
	conn    net.Conn
	sendPad *qpp.QuantumPermutationPad
	recvPad *qpp.QuantumPermutationPad
	sendMac []byte
	recvMac []byte
	sendMu  sync.Mutex
	recvMu  sync.Mutex
}

// newEncryptedChannel prepares a full-duplex channel with independent pads
// and MAC keys for each direction.
func newEncryptedChannel(conn net.Conn, sendPad, recvPad *qpp.QuantumPermutationPad, sendMacKey, recvMacKey []byte) *encryptedChannel {
	return &encryptedChannel{
		conn:    conn,
		sendPad: sendPad,
		recvPad: recvPad,
		sendMac: append([]byte(nil), sendMacKey...),
		recvMac: append([]byte(nil), recvMacKey...),
	}
}

// Send marshals a PlainPayload, encrypts it, and writes a SecureData envelope.
// Calls are serialized because QPP mutates its internal pad state per use.
func (c *encryptedChannel) Send(payload *protocol.PlainPayload) error {
	if payload == nil {
		return fmt.Errorf("payload is nil")
	}
	plain, err := proto.Marshal(payload)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	cipher := c.encryptBuffer(plain)
	mac := c.computePayloadHMAC(c.sendMac, plain)
	env := &protocol.Envelope{SecureData: &protocol.SecureData{Ciphertext: cipher, Mac: mac}}
	return protocol.WriteMessage(c.conn, env)
}

// Receive blocks for the next SecureData envelope, decrypts it, and returns the
// embedded PlainPayload after verifying its MAC.
func (c *encryptedChannel) Receive() (*protocol.PlainPayload, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	env := &protocol.Envelope{}
	if err := protocol.ReadMessage(c.conn, env); err != nil {
		return nil, err
	}
	if env.SecureData == nil {
		return nil, fmt.Errorf("unexpected non-secure message received")
	}
	plain := c.decryptBuffer(env.SecureData.Ciphertext)
	expected := c.computePayloadHMAC(c.recvMac, plain)
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

// computePayloadHMAC computes an HMAC-SHA256 over data using key.
func (c *encryptedChannel) computePayloadHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
