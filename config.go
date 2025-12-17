package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// clientConfigFile represents the structure of the JSON configuration file
type clientConfigFile struct {
	Clients []clientConfigEntry `json:"clients"`
}

// clientConfigEntry represents a single client entry in the configuration file
type clientConfigEntry struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

// loadClientEntriesFromConfig reads and parses the client configuration file
func loadClientEntriesFromConfig(path string) ([]clientEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg clientConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(cfg.Clients) == 0 {
		return nil, fmt.Errorf("config %s does not list any clients", path)
	}
	configDir := filepath.Dir(path)
	entries := make([]clientEntry, 0, len(cfg.Clients))
	for _, client := range cfg.Clients {
		id := strings.TrimSpace(client.ID)
		keyPath := strings.TrimSpace(client.PublicKey)
		if id == "" || keyPath == "" {
			return nil, fmt.Errorf("config %s contains empty id or public_key", path)
		}
		// Convert relative paths to absolute paths relative to config file directory
		if !filepath.IsAbs(keyPath) {
			keyPath = filepath.Join(configDir, keyPath)
		}
		entries = append(entries, clientEntry{id: id, path: keyPath})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	return entries, nil
}

// loadRegistryFromSources combines client entries from CLI and config file, and loads the registry
func loadRegistryFromSources(cliEntries []clientEntry, configPath string) (clientRegistry, error) {
	combined := make([]clientEntry, 0, len(cliEntries))
	if configPath != "" {
		cfgEntries, err := loadClientEntriesFromConfig(configPath)
		if err != nil {
			return nil, err
		}
		combined = append(combined, cfgEntries...)
	}
	combined = append(combined, cliEntries...)
	if len(combined) == 0 {
		return nil, errors.New("no clients configured for server")
	}
	return loadClientRegistry(combined)
}
