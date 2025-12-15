package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/xtaci/hppk"
)

// TestClientServerProtoAuthOverTCP spins up a loopback server/client and lets them exchange protobuf auth messages.
func TestClientServerProtoAuthOverTCP(t *testing.T) {
	client, err := hppk.GenerateKey(8)
	assert.Nil(t, err)

	clientID := "client-1"
	serverKnownKeys := map[string]*hppk.PublicKey{
		clientID: client.Public(),
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer listener.Close()

	challenge := make([]byte, 48)
	_, err = rand.Read(challenge)
	assert.Nil(t, err)

	serverErr := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		if err := writeProtoMessage(conn, &authChallengePB{Challenge: challenge}); err != nil {
			serverErr <- err
			return
		}

		resp := &authResponsePB{}
		if err := readProtoMessage(conn, resp); err != nil {
			serverErr <- err
			return
		}

		pub, ok := serverKnownKeys[resp.ClientId]
		if !ok {
			_ = writeProtoMessage(conn, &authResultPB{Success: false, Message: "unknown client"})
			serverErr <- errors.New("unknown client")
			return
		}

		var sig hppk.Signature
		if err := json.Unmarshal(resp.SignatureJson, &sig); err != nil {
			serverErr <- err
			return
		}

		verified := hppk.VerifySignature(&sig, challenge, pub)
		result := &authResultPB{Success: verified}
		if verified {
			result.Message = "authentication success"
		} else {
			result.Message = "authentication failed"
		}

		if err := writeProtoMessage(conn, result); err != nil {
			serverErr <- err
			return
		}

		if verified {
			serverErr <- nil
		} else {
			serverErr <- errors.New("signature verification failed")
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	assert.Nil(t, err)
	defer conn.Close()

	receivedChallenge := &authChallengePB{}
	assert.Nil(t, readProtoMessage(conn, receivedChallenge))

	sig, err := client.Sign(receivedChallenge.Challenge)
	assert.Nil(t, err)

	sigJSON, err := json.Marshal(sig)
	assert.Nil(t, err)

	respMsg := &authResponsePB{
		ClientId:      clientID,
		SignatureJson: sigJSON,
	}
	assert.Nil(t, writeProtoMessage(conn, respMsg))

	resultMsg := &authResultPB{}
	assert.Nil(t, readProtoMessage(conn, resultMsg))
	assert.True(t, resultMsg.Success)
	assert.Equal(t, "authentication success", resultMsg.Message)

	assert.Nil(t, <-serverErr)
}

func writeProtoMessage(conn net.Conn, msg proto.Message) error {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	if len(payload) > 16*1024*1024 {
		return errors.New("message too large")
	}
	head := make([]byte, 4)
	binary.BigEndian.PutUint32(head, uint32(len(payload)))
	if _, err := conn.Write(head); err != nil {
		return err
	}
	_, err = conn.Write(payload)
	return err
}

func readProtoMessage(conn net.Conn, msg proto.Message) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(head)
	if length > 16*1024*1024 {
		return errors.New("message too large")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return err
	}
	return proto.Unmarshal(payload, msg)
}

type authChallengePB struct {
	Challenge []byte `protobuf:"bytes,1,opt,name=challenge,proto3" json:"challenge,omitempty"`
}

func (m *authChallengePB) Reset()         { *m = authChallengePB{} }
func (m *authChallengePB) String() string { return proto.CompactTextString(m) }
func (*authChallengePB) ProtoMessage()    {}

type authResponsePB struct {
	ClientId      string `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	SignatureJson []byte `protobuf:"bytes,2,opt,name=signature_json,json=signatureJson,proto3" json:"signature_json,omitempty"`
}

func (m *authResponsePB) Reset()         { *m = authResponsePB{} }
func (m *authResponsePB) String() string { return proto.CompactTextString(m) }
func (*authResponsePB) ProtoMessage()    {}

type authResultPB struct {
	Success bool   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Message string `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
}

func (m *authResultPB) Reset()         { *m = authResultPB{} }
func (m *authResultPB) String() string { return proto.CompactTextString(m) }
func (*authResultPB) ProtoMessage()    {}
