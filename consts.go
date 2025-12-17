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
)
