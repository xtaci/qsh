package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xtaci/hppk"
	qcrypto "github.com/xtaci/qsh/crypto"
)

var (
	knownHostsDirOverride string
	promptHostApproval    = promptUserForHostKey
)

// ensureTrustedHost verifies the server's host key against known_hosts, prompting the user if needed.
func ensureTrustedHost(host string, pub *hppk.PublicKey) error {
	if pub == nil {
		return errors.New("nil host key")
	}
	fingerprint, err := qcrypto.FingerprintPublicKey(pub)
	if err != nil {
		return err
	}
	path, err := knownHostsPath()
	if err != nil {
		return err
	}
	existing, err := readKnownHosts(path)
	if err != nil {
		return err
	}
	if known, ok := existing[host]; ok {
		if known == fingerprint {
			return nil
		}
		return fmt.Errorf("host %s key mismatch (known %s, got %s)", host, known, fingerprint)
	}
	accepted, err := promptHostApproval(host, fingerprint)
	if err != nil {
		return err
	}
	if !accepted {
		return errors.New("host key rejected by user")
	}
	return appendKnownHost(path, host, fingerprint)
}

func knownHostsPath() (string, error) {
	if knownHostsDirOverride != "" {
		if err := os.MkdirAll(knownHostsDirOverride, 0o700); err != nil {
			return "", err
		}
		return filepath.Join(knownHostsDirOverride, "known_hosts"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".qsh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "known_hosts"), nil
}

func readKnownHosts(path string) (map[string]string, error) {
	entries := make(map[string]string)
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return entries, nil
		}
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		host := parts[0]
		fingerprint := parts[1]
		entries[host] = fingerprint
	}
	return entries, scanner.Err()
}

func appendKnownHost(path, host, fingerprint string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line := fmt.Sprintf("%s %s\n", host, fingerprint)
	_, err = f.WriteString(line)
	return err
}

func promptUserForHostKey(host, fingerprint string) (bool, error) {
	fmt.Fprintf(os.Stderr, "The authenticity of %s can't be established.\nFingerprint: %s\nTrust this host key? (yes/no) ", host, fingerprint)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
