package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xtaci/hppk"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// loadPrivateKey reads an HPPK private key and decrypts it if needed.
func loadPrivateKey(path string) (*hppk.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var encrypted encryptedKeyFile
	if err := json.Unmarshal(data, &encrypted); err == nil && encrypted.Type == encryptedKeyType {
		pass, err := promptPassword(fmt.Sprintf("Enter passphrase for %s: ", path), false)
		if err != nil {
			return nil, err
		}
		if len(pass) == 0 {
			return nil, errors.New("passphrase required to decrypt private key")
		}
		defer clear(pass)
		plain, err := decryptPrivateKey(&encrypted, pass)
		if err != nil {
			return nil, err
		}
		var priv hppk.PrivateKey
		if err := json.Unmarshal(plain, &priv); err != nil {
			return nil, err
		}
		return &priv, nil
	}
	var priv hppk.PrivateKey
	if err := json.Unmarshal(data, &priv); err != nil {
		return nil, err
	}
	return &priv, nil
}

// loadPublicKey reads a JSON-encoded HPPK public key.
func loadPublicKey(path string) (*hppk.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var pub hppk.PublicKey
	if err := json.NewDecoder(f).Decode(&pub); err != nil {
		return nil, err
	}
	return &pub, nil
}

// generateKeyPair creates a new HPPK keypair, encrypts the private key, and persists both halves.
func generateKeyPair(path string, strength int, passphrase []byte) error {
	if path == "" {
		return errors.New("genkey requires a target path")
	}
	if strength <= 0 {
		return fmt.Errorf("invalid genkey strength %d", strength)
	}
	priv, err := hppk.GenerateKey(strength)
	if err != nil {
		return err
	}
	encBlob, err := encryptPrivateKey(priv, passphrase)
	if err != nil {
		return err
	}
	if err := writeJSONFile(path, 0o600, encBlob); err != nil {
		return err
	}
	pubPath := path + ".pub"
	if err := writeJSONFile(pubPath, 0o644, priv.Public()); err != nil {
		return err
	}
	fmt.Printf("generated HPPK keypair: %s (private), %s (public)\n", path, pubPath)
	return nil
}

// writeJSONFile writes indented JSON to disk, creating parents as needed.
func writeJSONFile(path string, perm os.FileMode, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// encryptedKeyType defines the fromat of encrypted private key files.
type encryptedKeyFile struct {
	Type       string          `json:"type"`
	Version    int             `json:"version"`
	KDF        string          `json:"kdf"`
	ScryptN    int             `json:"scrypt_n"`
	ScryptR    int             `json:"scrypt_r"`
	ScryptP    int             `json:"scrypt_p"`
	Salt       []byte          `json:"salt"`
	Nonce      []byte          `json:"nonce"`
	Ciphertext []byte          `json:"ciphertext"`
	PublicKey  *hppk.PublicKey `json:"public_key,omitempty"`
}

const (
	kdfName     = "scrypt"
	scryptCostN = 1 << 15
	scryptCostR = 8
	scryptCostP = 1
)

// encryptPrivateKey encrypts an HPPK private key using the given passphrase.
func encryptPrivateKey(priv *hppk.PrivateKey, passphrase []byte) (*encryptedKeyFile, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("empty passphrase not allowed")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key(passphrase, salt, scryptCostN, scryptCostR, scryptCostP, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(priv)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	clear(plain)
	return &encryptedKeyFile{
		Type:       encryptedKeyType,
		Version:    1,
		KDF:        kdfName,
		ScryptN:    scryptCostN,
		ScryptR:    scryptCostR,
		ScryptP:    scryptCostP,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		PublicKey:  priv.Public(),
	}, nil
}

// decryptPrivateKey decrypts an encrypted private key file using the given passphrase.
func decryptPrivateKey(enc *encryptedKeyFile, passphrase []byte) ([]byte, error) {
	if enc.KDF != kdfName {
		return nil, fmt.Errorf("unsupported kdf %s", enc.KDF)
	}
	N, r, p := enc.ScryptN, enc.ScryptR, enc.ScryptP
	if N == 0 {
		N = scryptCostN
	}
	if r == 0 {
		r = scryptCostR
	}
	if p == 0 {
		p = scryptCostP
	}
	key, err := scrypt.Key(passphrase, enc.Salt, N, r, p, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(enc.Nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size in key file")
	}
	plain, err := gcm.Open(nil, enc.Nonce, enc.Ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// promptPassword prompts the user for a password, optionally confirming it.
func promptPassword(prompt string, confirm bool) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		confirmPass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			clear(pass)
			clear(confirmPass)
			return nil, err
		}
		if !bytes.Equal(pass, confirmPass) {
			clear(pass)
			clear(confirmPass)
			return nil, errors.New("passphrases do not match")
		}
		clear(confirmPass)
	}
	return pass, nil
}
