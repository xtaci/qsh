package main

const (
	// Replay protection parameters shared across client and server.
	nonceSize       = 16
	nonceWindowSize = 10000

	// HKDF-style labels for deriving directional pads and MAC keys.
	seedLabelClientToServer = "qsh-c2s"
	seedLabelServerToClient = "qsh-s2c"
	macLabelClientToServer  = "qsh-c2s-mac"
	macLabelServerToClient  = "qsh-s2c-mac"

	// file copy buffersize
	fileCopyBufferSize = 128 * 1024

	// Server authentication challenge parameters.
	serverChallengeSize = 48

	// maxPacketAge defines the maximum age of a packet before it is rejected.
	// This prevents replay attacks with old packets that have been pruned from the nonce heap.
	maxPacketAge = 120 // seconds
)
