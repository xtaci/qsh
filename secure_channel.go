package main

import (
	"fmt"
	"net"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/xtaci/qpp"
	"github.com/xtaci/qsh/protocol"
)

type encryptedWriter struct {
	conn net.Conn
	enc  *qpp.QuantumPermutationPad
	mu   sync.Mutex
}

func newEncryptedWriter(conn net.Conn, enc *qpp.QuantumPermutationPad) *encryptedWriter {
	return &encryptedWriter{conn: conn, enc: enc}
}

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

func encryptBuffer(qp *qpp.QuantumPermutationPad, data []byte) []byte {
	buf := append([]byte(nil), data...)
	qp.Encrypt(buf)
	return buf
}

func decryptBuffer(qp *qpp.QuantumPermutationPad, data []byte) []byte {
	buf := append([]byte(nil), data...)
	qp.Decrypt(buf)
	return buf
}
