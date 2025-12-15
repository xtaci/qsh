package main

import (
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
	conn net.Conn
	enc  *qpp.QuantumPermutationPad
	mu   sync.Mutex
}

// newEncryptedWriter wraps a connection with the provided QPP encryptor.
func newEncryptedWriter(conn net.Conn, enc *qpp.QuantumPermutationPad) *encryptedWriter {
	return &encryptedWriter{conn: conn, enc: enc}
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
	env := &protocol.Envelope{SecureData: &protocol.SecureData{Ciphertext: cipher}}
	w.mu.Lock()
	defer w.mu.Unlock()
	return protocol.WriteMessage(w.conn, env)
}

// receivePayload reads the next SecureData envelope, decrypts it, and returns
// the contained PlainPayload.
func receivePayload(conn net.Conn, dec *qpp.QuantumPermutationPad) (*protocol.PlainPayload, error) {
	env := &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, err
	}
	if env.SecureData == nil {
		return nil, fmt.Errorf("unexpected non-secure message received")
	}
	plain := decryptBuffer(dec, env.SecureData.Ciphertext)
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
