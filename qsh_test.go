package main

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/hppk"
)

// TestHPPKAuthSuccess verifies that a client can sign a challenge and the server verifies it.
func TestHPPKAuthSuccess(t *testing.T) {
	client, err := hppk.GenerateKey(8)
	require.NoError(t, err)

	challenge := make([]byte, 48)
	_, err = rand.Read(challenge)
	require.NoError(t, err)

	sig, err := client.Sign(challenge)
	require.NoError(t, err)

	require.True(t, hppk.VerifySignature(sig, challenge, client.Public()))
}

// TestHPPKAuthFailOnTamper ensures tampering with the challenge invalidates the signature.
func TestHPPKAuthFailOnTamper(t *testing.T) {
	client, err := hppk.GenerateKey(8)
	require.NoError(t, err)

	challenge := make([]byte, 48)
	_, err = rand.Read(challenge)
	require.NoError(t, err)

	sig, err := client.Sign(challenge)
	require.NoError(t, err)

	tampered := append([]byte(nil), challenge...)
	tampered[0] ^= 0xFF

	require.False(t, hppk.VerifySignature(sig, tampered, client.Public()))
}
