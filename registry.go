package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/xtaci/hppk"
	qcrypto "github.com/xtaci/qsh/crypto"
)

// clientEntry binds a client identifier to a local path containing its public key.
type clientEntry struct {
	id   string
	path string
}

// clientRegistry maps client IDs onto their trusted public keys.
type clientRegistry map[string]*hppk.PublicKey

// registryLoader defines a function that loads a client registry.
type registryLoader func() (clientRegistry, error)

// clientRegistryStore provides atomic access to the client registry.
type clientRegistryStore struct {
	value atomic.Value
}

// newClientRegistryStore creates a new clientRegistryStore initialized with reg.
func newClientRegistryStore(reg clientRegistry) *clientRegistryStore {
	store := &clientRegistryStore{}
	store.value.Store(reg)
	return store
}

// Get retrieves the current client registry.
func (s *clientRegistryStore) Get() clientRegistry {
	reg, _ := s.value.Load().(clientRegistry)
	return reg
}

// Replace updates the client registry with reg.
func (s *clientRegistryStore) Replace(reg clientRegistry) {
	s.value.Store(reg)
}

// parseClientEntries parses client entries from command-line arguments.
func parseClientEntries(values []string) ([]clientEntry, error) {
	var entries []clientEntry
	for _, value := range values {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid client entry %q (expected id=/path/to/key)", value)
		}
		id := strings.TrimSpace(parts[0])
		path := strings.TrimSpace(parts[1])
		if id == "" || path == "" {
			return nil, fmt.Errorf("invalid client entry %q", value)
		}
		entries = append(entries, clientEntry{id: id, path: path})
	}
	return entries, nil
}

// loadClientRegistry loads each allowed client's public key once at startup.
func loadClientRegistry(entries []clientEntry) (clientRegistry, error) {
	reg := make(clientRegistry)
	for _, entry := range entries {
		pub, err := qcrypto.LoadPublicKey(entry.path)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", entry.path, err)
		}
		reg[entry.id] = pub
	}
	return reg, nil
}

// watchRegistryReload listens for SIGUSR1 and reloads the client registry.
func watchRegistryReload(store *clientRegistryStore, loader registryLoader) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1)
	defer signal.Stop(sigCh)
	for range sigCh {
		log.Printf("received SIGUSR1, reloading client registry")
		registry, err := loader()
		if err != nil {
			log.Printf("client registry reload failed: %v", err)
			continue
		}
		store.Replace(registry)
		log.Printf("client registry reloaded (%d clients)", len(registry))
	}
}
