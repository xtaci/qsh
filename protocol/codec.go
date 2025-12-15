package protocol

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/golang/protobuf/proto"
)

const maxMessageSize = 16 * 1024 * 1024

// WriteMessage writes a length-prefixed protobuf message to the writer.

func WriteMessage(w io.Writer, msg proto.Message) error {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	if len(payload) > maxMessageSize {
		return errors.New("protocol: message too large")
	}
	head := make([]byte, 4)
	binary.BigEndian.PutUint32(head, uint32(len(payload)))
	if _, err := w.Write(head); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// ReadMessage reads a length-prefixed protobuf message into msg.
func ReadMessage(r io.Reader, msg proto.Message) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(head)
	if length > maxMessageSize {
		return errors.New("protocol: message too large")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	return proto.Unmarshal(payload, msg)
}
