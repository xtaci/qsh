package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseClientEntriesWithBaseDir_RelativePaths(t *testing.T) {
	baseDir := "/opt/qsh"

	tests := []struct {
		name     string
		input    []string
		expected []clientEntry
	}{
		{
			name:  "relative path with dot-slash",
			input: []string{"alice=./keys/alice.pub"},
			expected: []clientEntry{
				{id: "alice", path: filepath.Join(baseDir, "./keys/alice.pub")},
			},
		},
		{
			name:  "relative path without dot",
			input: []string{"bob=keys/bob.pub"},
			expected: []clientEntry{
				{id: "bob", path: filepath.Join(baseDir, "keys/bob.pub")},
			},
		},
		{
			name:  "absolute path unchanged",
			input: []string{"charlie=/etc/qsh/charlie.pub"},
			expected: []clientEntry{
				{id: "charlie", path: "/etc/qsh/charlie.pub"},
			},
		},
		{
			name: "mixed paths",
			input: []string{
				"alice=./alice.pub",
				"bob=/tmp/bob.pub",
				"charlie=keys/charlie.pub",
			},
			expected: []clientEntry{
				{id: "alice", path: filepath.Join(baseDir, "./alice.pub")},
				{id: "bob", path: "/tmp/bob.pub"},
				{id: "charlie", path: filepath.Join(baseDir, "keys/charlie.pub")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := parseClientEntriesWithBaseDir(tt.input, baseDir)
			require.NoError(t, err)
			require.Equal(t, len(tt.expected), len(entries))
			for i, expected := range tt.expected {
				require.Equal(t, expected.id, entries[i].id)
				require.True(t, filepath.IsAbs(entries[i].path), "path should be absolute")
				require.Equal(t, expected.path, entries[i].path)
			}
		})
	}
}

func TestParseClientEntriesWithBaseDir_EmptyInput(t *testing.T) {
	entries, err := parseClientEntriesWithBaseDir([]string{}, "/opt/qsh")
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestParseClientEntriesWithBaseDir_InvalidFormats(t *testing.T) {
	baseDir := "/opt/qsh"
	tests := []struct {
		name        string
		input       []string
		expectError string
	}{
		{
			name:        "missing equals",
			input:       []string{"alice"},
			expectError: "invalid client entry",
		},
		{
			name:        "missing path",
			input:       []string{"alice="},
			expectError: "invalid client entry",
		},
		{
			name:        "missing id",
			input:       []string{"=/tmp/key.pub"},
			expectError: "invalid client entry",
		},
		{
			name:        "only whitespace",
			input:       []string{"  =  "},
			expectError: "invalid client entry",
		},
		{
			name:        "whitespace id",
			input:       []string{"   =./key.pub"},
			expectError: "invalid client entry",
		},
		{
			name:        "whitespace path",
			input:       []string{"alice=   "},
			expectError: "invalid client entry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseClientEntriesWithBaseDir(tt.input, baseDir)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestParseClientEntriesWithBaseDir_Whitespace(t *testing.T) {
	entries, err := parseClientEntriesWithBaseDir([]string{"  alice  =  ./key.pub  "}, "/opt/qsh")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "alice", entries[0].id)
	require.Equal(t, filepath.Join("/opt/qsh", "./key.pub"), entries[0].path)
}

func TestParseClientEntriesWithBaseDir_DifferentBaseDirs(t *testing.T) {
	tests := []struct {
		name         string
		baseDir      string
		input        string
		expectedPath string
	}{
		{
			name:         "unix style path",
			baseDir:      "/usr/local/qsh",
			input:        "alice=keys/alice.pub",
			expectedPath: "/usr/local/qsh/keys/alice.pub",
		},
		{
			name:         "nested relative path",
			baseDir:      "/home/user/qsh",
			input:        "bob=../../keys/bob.pub",
			expectedPath: filepath.Join("/home/user/qsh", "../../keys/bob.pub"),
		},
		{
			name:         "current dir relative",
			baseDir:      "/tmp",
			input:        "charlie=./charlie.pub",
			expectedPath: "/tmp/charlie.pub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := parseClientEntriesWithBaseDir([]string{tt.input}, tt.baseDir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			require.Equal(t, tt.expectedPath, entries[0].path)
		})
	}
}
