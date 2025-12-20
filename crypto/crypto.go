package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/awnumar/memguard"
	"github.com/xtaci/hppk"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// LoadPrivateKey reads an HPPK private key and decrypts it if needed.
func LoadPrivateKey(path string) (*hppk.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fileBuf := memguard.NewBufferFromBytes(data)
	defer fileBuf.Destroy()

	var encrypted encryptedKeyFile
	if err := json.Unmarshal(fileBuf.Bytes(), &encrypted); err == nil && encrypted.Type == EncryptedKeyType {
		passBuf, err := PromptPassword(fmt.Sprintf("Enter passphrase for %s: ", path), false)
		if err != nil {
			return nil, err
		}
		defer passBuf.Destroy()

		if passBuf.Size() == 0 {
			return nil, errors.New("passphrase required to decrypt private key")
		}
		plainBuf, err := decryptPrivateKey(&encrypted, passBuf)
		if err != nil {
			return nil, err
		}
		defer plainBuf.Destroy()

		var priv hppk.PrivateKey
		if err := json.Unmarshal(plainBuf.Bytes(), &priv); err != nil {
			return nil, err
		}
		return &priv, nil
	}
	var priv hppk.PrivateKey
	if err := json.Unmarshal(fileBuf.Bytes(), &priv); err != nil {
		return nil, err
	}
	return &priv, nil
}

// LoadPublicKey reads a JSON-encoded HPPK public key.
func LoadPublicKey(path string) (*hppk.PublicKey, error) {
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

// GenerateKeyPair creates a new HPPK keypair, optionally encrypts the private key, and persists both halves.
func GenerateKeyPair(path string, strength int, passphrase *memguard.LockedBuffer) error {
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
	var privatePayload any
	if passphrase == nil || passphrase.Size() == 0 {
		privatePayload = priv
	} else {
		encBlob, err := encryptPrivateKey(priv, passphrase)
		if err != nil {
			return err
		}
		privatePayload = encBlob
	}
	if err := writeJSONFile(path, 0o600, privatePayload); err != nil {
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

// encryptPrivateKey encrypts an HPPK private key using the given passphrase.
func encryptPrivateKey(priv *hppk.PrivateKey, passphrase *memguard.LockedBuffer) (*encryptedKeyFile, error) {
	if passphrase.Size() == 0 {
		return nil, errors.New("empty passphrase not allowed")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key(passphrase.Bytes(), salt, ScryptCostN, ScryptCostR, ScryptCostP, 32)
	if err != nil {
		return nil, err
	}
	keyBuf := memguard.NewBufferFromBytes(key)
	defer keyBuf.Destroy()

	block, err := aes.NewCipher(keyBuf.Bytes())
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
	plainBuf := memguard.NewBufferFromBytes(plain)
	defer plainBuf.Destroy()

	ciphertext := gcm.Seal(nil, nonce, plainBuf.Bytes(), nil)
	return &encryptedKeyFile{
		Type:       EncryptedKeyType,
		Version:    1,
		KDF:        KdfName,
		ScryptN:    ScryptCostN,
		ScryptR:    ScryptCostR,
		ScryptP:    ScryptCostP,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		PublicKey:  priv.Public(),
	}, nil
}

// decryptPrivateKey decrypts an encrypted private key file using the given passphrase.
func decryptPrivateKey(enc *encryptedKeyFile, passphrase *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	if enc.KDF != KdfName {
		return nil, fmt.Errorf("unsupported kdf %s", enc.KDF)
	}
	N, r, p := enc.ScryptN, enc.ScryptR, enc.ScryptP
	if N == 0 {
		N = ScryptCostN
	}
	if r == 0 {
		r = ScryptCostR
	}
	if p == 0 {
		p = ScryptCostP
	}
	key, err := scrypt.Key(passphrase.Bytes(), enc.Salt, N, r, p, 32)
	if err != nil {
		return nil, err
	}
	keyBuf := memguard.NewBufferFromBytes(key)
	defer keyBuf.Destroy()

	block, err := aes.NewCipher(keyBuf.Bytes())
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
	return memguard.NewBufferFromBytes(plain), nil
}

// PromptPassword prompts the user for a password, optionally confirming it.
func PromptPassword(prompt string, confirm bool) (*memguard.LockedBuffer, error) {
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	buf := memguard.NewBufferFromBytes(pass)
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		confirmPass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			buf.Destroy()
			return nil, err
		}
		confBuf := memguard.NewBufferFromBytes(confirmPass)
		defer confBuf.Destroy()

		if !bytes.Equal(buf.Bytes(), confBuf.Bytes()) {
			buf.Destroy()
			return nil, errors.New("passphrases do not match")
		}
	}
	return buf, nil
}

// DeriveDirectionalSeed deterministically expands the shared master secret per direction.
func DeriveDirectionalSeed(master []byte, label string) ([]byte, error) {
	return deriveKeyMaterial(master, label, SessionKeyBytes)
}

// DeriveDirectionalMAC returns the per-direction MAC key.
func DeriveDirectionalMAC(master []byte, label string) ([]byte, error) {
	return deriveKeyMaterial(master, label, HmacKeyBytes)
}

func deriveKeyMaterial(master []byte, label string, size int) ([]byte, error) {
	h := hkdf.New(sha256.New, master, nil, []byte(label))
	out := make([]byte, size)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalPublicKey serializes an HPPK public key to canonical JSON.
func MarshalPublicKey(pub *hppk.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}
	return json.Marshal(pub)
}

// UnmarshalPublicKey decodes an HPPK public key from JSON.
func UnmarshalPublicKey(data []byte) (*hppk.PublicKey, error) {
	if len(data) == 0 {
		return nil, errors.New("public key payload is empty")
	}
	var pub hppk.PublicKey
	if err := json.Unmarshal(data, &pub); err != nil {
		return nil, err
	}
	return &pub, nil
}

// FingerprintPublicKey returns a short deterministic fingerprint for display/trust decisions.
func FingerprintPublicKey(pub *hppk.PublicKey) (string, error) {
	payload, err := MarshalPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}
