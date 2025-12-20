package crypto

import (
"encoding/json"
"testing"

"github.com/awnumar/memguard"
"github.com/xtaci/hppk"
)

func TestEncryptDecryptPrivateKey(t *testing.T) {
	// Generate a key
	priv, err := hppk.GenerateKey(8)
	if err != nil {
		t.Fatal(err)
	}

	pass := []byte("testpass")
	passBuf := memguard.NewBufferFromBytes(pass)
	defer passBuf.Destroy()

	// Encrypt
	enc, err := encryptPrivateKey(priv, passBuf)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt
	plainBuf, err := decryptPrivateKey(enc, passBuf)
	if err != nil {
		t.Fatal(err)
	}
	defer plainBuf.Destroy()

	var priv2 hppk.PrivateKey
	if err := json.Unmarshal(plainBuf.Bytes(), &priv2); err != nil {
		t.Fatal(err)
	}

	// Check if public keys match
	pub1 := priv.Public()
	pub2 := priv2.Public()
	
	// hppk.PublicKey might not be comparable directly if it contains slices
	// But we can marshal them to compare
	p1, _ := json.Marshal(pub1)
	p2, _ := json.Marshal(pub2)
	
	if string(p1) != string(p2) {
		t.Fatal("Decrypted key does not match original")
	}
}

func TestGenerateAndLoadUnencrypted(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := tmpDir + "/key"
	
	// Generate without password
	err := GenerateKeyPair(keyPath, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	
	// Load
	priv, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if priv == nil {
		t.Fatal("Loaded key is nil")
	}
}
