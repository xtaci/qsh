package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net"

	"github.com/xtaci/hppk"
	"github.com/xtaci/qpp"
	qcrypto "github.com/xtaci/qsh/crypto"
	"github.com/xtaci/qsh/protocol"
)

// clientSession bundles the encryption primitives established during the client handshake.
type clientSession struct {
	Conn    net.Conn
	Channel *encryptedChannel
}

// performClientHandshake mirrors the server handshake, including server authentication.
func performClientHandshake(conn net.Conn, priv *hppk.PrivateKey, clientID, serverLabel string, mode protocol.ClientMode) (*clientSession, error) {
	serverChallenge := make([]byte, serverChallengeSize)
	if _, err := rand.Read(serverChallenge); err != nil {
		return nil, err
	}
	clientHello := &protocol.Envelope{ClientHello: &protocol.ClientHello{
		ClientId:        clientID,
		Mode:            mode,
		ServerChallenge: serverChallenge,
	}}
	if err := protocol.WriteMessage(conn, clientHello); err != nil {
		return nil, err
	}
	env := &protocol.Envelope{}

	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, err
	}
	serverHello := env.ServerHello
	if serverHello == nil {
		return nil, errors.New("handshake: expected server hello")
	}
	hostPub, err := qcrypto.UnmarshalPublicKey(serverHello.HostPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode server public key: %w", err)
	}
	sig, err := qcrypto.SignatureFromProto(serverHello.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode server signature: %w", err)
	}
	if !hppk.VerifySignature(sig, computeServerChallengeDigest(serverChallenge), hostPub) {
		return nil, errors.New("handshake: server signature verification failed")
	}
	if serverLabel != "" {
		if err := ensureTrustedHost(serverLabel, hostPub); err != nil {
			return nil, err
		}
	}

	env = &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, err
	}
	challenge := env.AuthChallenge
	if challenge == nil {
		return nil, errors.New("handshake: expected challenge")
	}

	// 3. Decrypt KEM and derive master seed
	kem := &hppk.KEM{P: new(big.Int).SetBytes(challenge.KemP), Q: new(big.Int).SetBytes(challenge.KemQ)}
	secret, err := priv.Decrypt(kem)
	if err != nil {
		return nil, err
	}
	keySize := int(challenge.SessionKeySize)
	if keySize <= 0 {
		keySize = qcrypto.SessionKeyBytes
	}
	secretBytes := secret.Bytes()
	if len(secretBytes) > keySize {
		return nil, fmt.Errorf("handshake: decrypted secret is %d bytes but expected <= %d (wrong key?)", len(secretBytes), keySize)
	}

	// As secret is a big.Int, it may be shorter than keySize bytes, so we left-pad with 0s
	// to ensure consistent length
	masterSeed := make([]byte, keySize)
	copy(masterSeed[keySize-len(secretBytes):], secretBytes)

	// 4. Sign challenge and send AuthResponse
	clientSig, err := priv.Sign(challenge.Challenge)
	if err != nil {
		return nil, err
	}
	response := &protocol.Envelope{AuthResponse: &protocol.AuthResponse{ClientId: clientID, Signature: qcrypto.SignatureToProto(clientSig)}}
	if err := protocol.WriteMessage(conn, response); err != nil {
		return nil, err
	}

	// 5. Receive AuthResult
	env = &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, err
	}
	if env.AuthResult == nil || !env.AuthResult.Success {
		msg := "authentication failed"
		if env.AuthResult != nil && env.AuthResult.Message != "" {
			msg = env.AuthResult.Message
		}
		return nil, errors.New(msg)
	}

	// 6. Prepare QPP pads for symmetric encryption and MAC keys for message authentication
	// NOTE(x): the pad count MUST be a valid prime number within supported range.
	pads := uint16(challenge.Pads)
	if !qcrypto.ValidatePadCount(pads) {
		return nil, fmt.Errorf("unsupported pad count %d (expected prime between %d and %d)", pads, qcrypto.MinPadCount, qcrypto.MaxPadCount)
	}

	c2sSeed, err := qcrypto.DeriveDirectionalSeed(masterSeed, seedLabelClientToServer)
	if err != nil {
		return nil, err
	}
	s2cSeed, err := qcrypto.DeriveDirectionalSeed(masterSeed, seedLabelServerToClient)
	if err != nil {
		return nil, err
	}
	c2sMacKey, err := qcrypto.DeriveDirectionalMAC(masterSeed, macLabelClientToServer)
	if err != nil {
		return nil, err
	}
	s2cMacKey, err := qcrypto.DeriveDirectionalMAC(masterSeed, macLabelServerToClient)
	if err != nil {
		return nil, err
	}

	// Create full-duplex encrypted channel
	channel := newEncryptedChannel(conn, qpp.NewQPP(c2sSeed, pads), qpp.NewQPP(s2cSeed, pads), c2sMacKey, s2cMacKey)
	return &clientSession{Conn: conn, Channel: channel}, nil
}

// serverSession encapsulates per-client state derived during the handshake.
type serverSession struct {
	Conn     net.Conn
	Channel  *encryptedChannel
	ClientID string
	Mode     protocol.ClientMode
}

// performServerHandshake authenticates the client and derives QPP pads.
func performServerHandshake(conn net.Conn, store *clientRegistryStore, hostKey *hppk.PrivateKey) (*serverSession, error) {
	if hostKey == nil {
		return nil, errors.New("handshake: server host key unavailable")
	}
	session := &serverSession{Conn: conn}
	// 1. Receive ClientHello
	env := &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, err
	}

	if env.ClientHello == nil {
		_ = session.sendAuthResult(false, "expected client hello")
		return nil, errors.New("handshake: missing client hello")
	}
	if len(env.ClientHello.ServerChallenge) == 0 {
		return nil, errors.New("handshake: missing server challenge")
	}
	if len(env.ClientHello.ServerChallenge) != serverChallengeSize {
		return nil, fmt.Errorf("handshake: invalid server challenge size %d", len(env.ClientHello.ServerChallenge))
	}
	if err := sendServerHello(conn, hostKey, env.ClientHello.ServerChallenge); err != nil {
		return nil, err
	}

	mode := env.ClientHello.Mode
	if mode != protocol.ClientMode_CLIENT_MODE_COPY {
		mode = protocol.ClientMode_CLIENT_MODE_SHELL
	}
	session.Mode = mode

	// 2. Lookup client public key
	clientID := env.ClientHello.ClientId
	session.ClientID = clientID
	registry := store.Get()
	if registry == nil {
		_ = session.sendAuthResult(false, "registry unavailable")
		return nil, errors.New("handshake: registry unavailable")
	}
	pub, ok := registry[clientID]
	if !ok {
		_ = session.sendAuthResult(false, "unknown client")
		return nil, fmt.Errorf("unknown client %s", clientID)
	}

	// 3. Get random nonce as challenge
	challenge := make([]byte, 48)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}

	padCount, err := qcrypto.RandomPrimePadCount()
	if err != nil {
		return nil, err
	}

	// 4. Generate KEM for master secret(session key).
	// 	NOTE(x): the length of masterSeed must match SessionKeyBytes,
	// 	and the length of the key should be sent to the client.
	masterSeed := make([]byte, qcrypto.SessionKeyBytes)
	if _, err := rand.Read(masterSeed); err != nil {
		return nil, err
	}

	kem, err := hppk.Encrypt(pub, masterSeed)
	if err != nil {
		return nil, err
	}

	// 5. Send session key and challenge to client
	challengeMsg := &protocol.Envelope{AuthChallenge: &protocol.AuthChallenge{
		Challenge:      challenge,
		KemP:           kem.P.Bytes(),
		KemQ:           kem.Q.Bytes(),
		Pads:           uint32(padCount),
		SessionKeySize: qcrypto.SessionKeyBytes,
	}}

	if err := protocol.WriteMessage(conn, challengeMsg); err != nil {
		return nil, err
	}

	// 5. Receive AuthResponse and decode signature
	env = &protocol.Envelope{}
	if err := protocol.ReadMessage(conn, env); err != nil {
		return nil, err
	}

	if env.AuthResponse == nil {
		_ = session.sendAuthResult(false, "expected auth response")
		return nil, errors.New("handshake: missing auth response")
	}

	if env.AuthResponse.ClientId != clientID {
		_ = session.sendAuthResult(false, "client id mismatch")
		return nil, errors.New("handshake: client id mismatch")
	}

	// 6. Verify signature over challenge
	sig, err := qcrypto.SignatureFromProto(env.AuthResponse.Signature)
	if err != nil {
		_ = session.sendAuthResult(false, "invalid signature payload")
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	if !hppk.VerifySignature(sig, challenge, pub) {
		_ = session.sendAuthResult(false, "signature verification failed")
		return nil, errors.New("handshake: signature verification failed")
	}
	if err := session.sendAuthResult(true, "authentication success"); err != nil {
		return nil, err
	}

	// 7. Prepare QPP pads for symmetric encryption and MAC keys for message authentication
	c2sSeed, err := qcrypto.DeriveDirectionalSeed(masterSeed, seedLabelClientToServer)
	if err != nil {
		return nil, err
	}
	s2cSeed, err := qcrypto.DeriveDirectionalSeed(masterSeed, seedLabelServerToClient)
	if err != nil {
		return nil, err
	}
	c2sMac, err := qcrypto.DeriveDirectionalMAC(masterSeed, macLabelClientToServer)
	if err != nil {
		return nil, err
	}
	s2cMac, err := qcrypto.DeriveDirectionalMAC(masterSeed, macLabelServerToClient)
	if err != nil {
		return nil, err
	}

	// Create full-duplex encrypted channel
	session.Channel = newEncryptedChannel(conn, qpp.NewQPP(s2cSeed, padCount), qpp.NewQPP(c2sSeed, padCount), s2cMac, c2sMac)

	return session, nil
}

// sendAuthResult sends a simple AuthResult envelope to the peer.
func (s *serverSession) sendAuthResult(ok bool, message string) error {
	env := &protocol.Envelope{AuthResult: &protocol.AuthResult{Success: ok, Message: message}}
	return protocol.WriteMessage(s.Conn, env)
}

func sendServerHello(conn net.Conn, hostKey *hppk.PrivateKey, challenge []byte) error {
	pubBytes, err := qcrypto.MarshalPublicKey(hostKey.Public())
	if err != nil {
		return err
	}
	sig, err := hostKey.Sign(computeServerChallengeDigest(challenge))
	if err != nil {
		return err
	}
	env := &protocol.Envelope{ServerHello: &protocol.ServerHello{
		HostPublicKey: pubBytes,
		Signature:     qcrypto.SignatureToProto(sig),
	}}
	return protocol.WriteMessage(conn, env)
}

func computeServerChallengeDigest(challenge []byte) []byte {
	h := sha256.New()
	h.Write([]byte(serverChallengeLabel))
	h.Write(challenge)
	return h.Sum(nil)
}
