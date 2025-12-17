package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/hppk"
	qcrypto "github.com/xtaci/qsh/crypto"
)

func TestEnsureTrustedHostAddsEntry(t *testing.T) {
	prevDir := knownHostsDirOverride
	knownHostsDirOverride = t.TempDir()
	t.Cleanup(func() { knownHostsDirOverride = prevDir })
	prevPrompt := promptHostApproval
	promptHostApproval = func(host, fingerprint string) (bool, error) {
		return true, nil
	}
	t.Cleanup(func() { promptHostApproval = prevPrompt })

	hostKey, err := hppk.GenerateKey(8)
	require.NoError(t, err)
	require.NoError(t, ensureTrustedHost("example.com", hostKey.Public()))
	path, err := knownHostsPath()
	require.NoError(t, err)
	entries, err := readKnownHosts(path)
	require.NoError(t, err)
	fingerprint, err := qcrypto.FingerprintPublicKey(hostKey.Public())
	require.NoError(t, err)
	require.Equal(t, fingerprint, entries["example.com"])
}

func TestEnsureTrustedHostDetectsMismatch(t *testing.T) {
	prevDir := knownHostsDirOverride
	tempDir := t.TempDir()
	knownHostsDirOverride = tempDir
	t.Cleanup(func() { knownHostsDirOverride = prevDir })
	hostA, err := hppk.GenerateKey(8)
	require.NoError(t, err)
	hostB, err := hppk.GenerateKey(8)
	require.NoError(t, err)
	fingerprint, err := qcrypto.FingerprintPublicKey(hostA.Public())
	require.NoError(t, err)
	path, err := knownHostsPath()
	require.NoError(t, err)
	require.NoError(t, appendKnownHost(path, "example.com", fingerprint))
	prevPrompt := promptHostApproval
	promptHostApproval = func(host, fp string) (bool, error) {
		return false, nil
	}
	t.Cleanup(func() { promptHostApproval = prevPrompt })
	err = ensureTrustedHost("example.com", hostB.Public())
	require.Error(t, err)
}

func TestEnsureTrustedHostSkipsPromptWhenKnown(t *testing.T) {
	prevDir := knownHostsDirOverride
	knownHostsDirOverride = t.TempDir()
	t.Cleanup(func() { knownHostsDirOverride = prevDir })
	hostKey, err := hppk.GenerateKey(8)
	require.NoError(t, err)
	fingerprint, err := qcrypto.FingerprintPublicKey(hostKey.Public())
	require.NoError(t, err)
	path, err := knownHostsPath()
	require.NoError(t, err)
	require.NoError(t, appendKnownHost(path, "cached", fingerprint))
	called := false
	prevPrompt := promptHostApproval
	promptHostApproval = func(host, fp string) (bool, error) {
		called = true
		return false, nil
	}
	t.Cleanup(func() { promptHostApproval = prevPrompt })
	require.NoError(t, ensureTrustedHost("cached", hostKey.Public()))
	require.False(t, called)
}

func TestKnownHostsPathCreatesDir(t *testing.T) {
	prevDir := knownHostsDirOverride
	tempDir := t.TempDir()
	knownHostsDirOverride = tempDir
	t.Cleanup(func() { knownHostsDirOverride = prevDir })
	path, err := knownHostsPath()
	require.NoError(t, err)
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))
	require.NoError(t, appendKnownHost(path, "host", "fingerprint"))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.False(t, info.IsDir())
}
