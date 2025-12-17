package crypto

const (
	// SessionKeyBytes defines how many bytes of keying material we derive for each
	// QPP pad direction.
	SessionKeyBytes = 256

	// HmacKeyBytes defines the length of the per-direction integrity key.
	HmacKeyBytes = 32
)

const (
	// MinPadCount defines the minimum allowed pad count for QPP.
	MinPadCount = 1024

	// MaxPadCount defines the maximum allowed pad count for QPP.
	MaxPadCount = 2048
)

const (
	// KdfName defines the key derivation function used for encrypting private keys.
	KdfName = "scrypt"

	// ScryptCostN defines the CPU/memory cost parameter for scrypt.
	ScryptCostN = 1 << 15

	// ScryptCostR defines the block size parameter for scrypt.
	ScryptCostR = 8

	// ScryptCostP defines the parallelization parameter for scrypt.
	ScryptCostP = 1

	// EncryptedKeyType defines the format identifier for encrypted private key files.
	EncryptedKeyType = "encrypted-hppk"
)
