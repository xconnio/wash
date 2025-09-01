package wampshell

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ReadPrivateKeyFromFile() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not get home directory: %w", err)
	}

	keyPath := filepath.Join(homeDir, ".wampshell/id_ed25519")
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("could not read private key from %s: %w", keyPath, err)
	}

	key := strings.TrimSpace(string(keyBytes))
	return key, nil
}
