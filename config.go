package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

type clientConfigFile struct {
	Clients []clientConfigEntry `json:"clients"`
}

type clientConfigEntry struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

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
	entries := make([]clientEntry, 0, len(cfg.Clients))
	for _, client := range cfg.Clients {
		id := strings.TrimSpace(client.ID)
		keyPath := strings.TrimSpace(client.PublicKey)
		if id == "" || keyPath == "" {
			return nil, fmt.Errorf("config %s contains empty id or public_key", path)
		}
		entries = append(entries, clientEntry{id: id, path: keyPath})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	return entries, nil
}

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
