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

// encryptedWriter serializes plaintext payloads, encrypts them, and writes
// framed envelopes on the shared connection.
type encryptedWriter struct {
	conn   net.Conn
	enc    *qpp.QuantumPermutationPad
	macKey []byte
	mu     sync.Mutex
}

// newEncryptedWriter wraps a connection with the provided QPP encryptor.
func newEncryptedWriter(conn net.Conn, enc *qpp.QuantumPermutationPad, macKey []byte) *encryptedWriter {
	return &encryptedWriter{conn: conn, enc: enc, macKey: append([]byte(nil), macKey...)}
}

// Send marshals a PlainPayload, encrypts the bytes, and writes a SecureData
// envelope. Calls are serialized because QPP mutates internal pad state.
func (w *encryptedWriter) Send(payload *protocol.PlainPayload) error {
	if payload == nil {
		return fmt.Errorf("payload is nil")
	}
	plain, err := proto.Marshal(payload)
	if err != nil {
		return err
	}
	cipher := encryptBuffer(w.enc, plain)
	mac := computePayloadHMAC(w.macKey, plain)
	env := &protocol.Envelope{SecureData: &protocol.SecureData{Ciphertext: cipher, Mac: mac}}
	w.mu.Lock()
	defer w.mu.Unlock()
	return protocol.WriteMessage(w.conn, env)
}

// receivePayload reads the next SecureData envelope, decrypts it, and returns
// the contained PlainPayload.
func receivePayload(conn net.Conn, dec *qpp.QuantumPermutationPad, macKey []byte) (*protocol.PlainPayload, error) {
	env := &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, err
	}
	if env.SecureData == nil {
		return nil, fmt.Errorf("unexpected non-secure message received")
	}
	plain := decryptBuffer(dec, env.SecureData.Ciphertext)
	expected := computePayloadHMAC(macKey, plain)
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
func encryptBuffer(qp *qpp.QuantumPermutationPad, data []byte) []byte {
	buf := append([]byte(nil), data...)
	qp.Encrypt(buf)
	return buf
}

// decryptBuffer mirrors encryptBuffer for the receive side.
func decryptBuffer(qp *qpp.QuantumPermutationPad, data []byte) []byte {
	buf := append([]byte(nil), data...)
	qp.Decrypt(buf)
	return buf
}

// computePayloadHMAC computes an HMAC-SHA256 over data using key.
func computePayloadHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
