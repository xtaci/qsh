package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadClientEntriesFromConfig_RelativePaths(t *testing.T) {
	// Create a temporary directory structure
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	keysDir := filepath.Join(configDir, "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0755))

	// Create dummy public key files
	key1Path := filepath.Join(keysDir, "alice.pub")
	key2Path := filepath.Join(tmpDir, "bob.pub")
	require.NoError(t, os.WriteFile(key1Path, []byte("alice-key"), 0644))
	require.NoError(t, os.WriteFile(key2Path, []byte("bob-key"), 0644))

	// Create config file with mixed absolute and relative paths
	configPath := filepath.Join(configDir, "clients.json")
	config := clientConfigFile{
		Clients: []clientConfigEntry{
			{ID: "alice", PublicKey: "./keys/alice.pub"},   // relative path
			{ID: "bob", PublicKey: key2Path},               // absolute path
			{ID: "charlie", PublicKey: "keys/charlie.pub"}, // relative path without ./
		},
	}
	configData, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, configData, 0644))

	// Load and verify entries
	entries, err := loadClientEntriesFromConfig(configPath)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	// Find entries by ID (they are sorted)
	entryMap := make(map[string]clientEntry)
	for _, e := range entries {
		entryMap[e.id] = e
	}

	// Verify alice's relative path was resolved correctly
	alice := entryMap["alice"]
	require.Equal(t, "alice", alice.id)
	require.True(t, filepath.IsAbs(alice.path), "alice's path should be absolute")
	require.Equal(t, key1Path, alice.path)

	// Verify bob's absolute path was preserved
	bob := entryMap["bob"]
	require.Equal(t, "bob", bob.id)
	require.True(t, filepath.IsAbs(bob.path), "bob's path should be absolute")
	require.Equal(t, key2Path, bob.path)

	// Verify charlie's relative path was resolved correctly
	charlie := entryMap["charlie"]
	require.Equal(t, "charlie", charlie.id)
	require.True(t, filepath.IsAbs(charlie.path), "charlie's path should be absolute")
	expectedCharliePath := filepath.Join(configDir, "keys", "charlie.pub")
	require.Equal(t, expectedCharliePath, charlie.path)
}

func TestLoadClientEntriesFromConfig_EmptyFields(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "clients.json")

	tests := []struct {
		name        string
		config      clientConfigFile
		expectError string
	}{
		{
			name: "empty id",
			config: clientConfigFile{
				Clients: []clientConfigEntry{
					{ID: "", PublicKey: "/tmp/key.pub"},
				},
			},
			expectError: "contains empty id or public_key",
		},
		{
			name: "empty public_key",
			config: clientConfigFile{
				Clients: []clientConfigEntry{
					{ID: "alice", PublicKey: ""},
				},
			},
			expectError: "contains empty id or public_key",
		},
		{
			name: "whitespace only",
			config: clientConfigFile{
				Clients: []clientConfigEntry{
					{ID: "  ", PublicKey: "  "},
				},
			},
			expectError: "contains empty id or public_key",
		},
		{
			name: "no clients",
			config: clientConfigFile{
				Clients: []clientConfigEntry{},
			},
			expectError: "does not list any clients",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configData, err := json.MarshalIndent(tt.config, "", "  ")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(configPath, configData, 0644))

			_, err = loadClientEntriesFromConfig(configPath)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestLoadClientEntriesFromConfig_SortedOutput(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "clients.json")

	config := clientConfigFile{
		Clients: []clientConfigEntry{
			{ID: "zebra", PublicKey: "/tmp/z.pub"},
			{ID: "alice", PublicKey: "/tmp/a.pub"},
			{ID: "mike", PublicKey: "/tmp/m.pub"},
			{ID: "bob", PublicKey: "/tmp/b.pub"},
		},
	}
	configData, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, configData, 0644))

	entries, err := loadClientEntriesFromConfig(configPath)
	require.NoError(t, err)
	require.Len(t, entries, 4)

	// Verify sorted by ID
	require.Equal(t, "alice", entries[0].id)
	require.Equal(t, "bob", entries[1].id)
	require.Equal(t, "mike", entries[2].id)
	require.Equal(t, "zebra", entries[3].id)
}
