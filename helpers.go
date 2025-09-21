package wampshell

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xconnio/wampproto-capnproto/go"
	"github.com/xconnio/xconn-go"
)

var CapnprotoSerializerSpec = xconn.NewSerializerSpec( //nolint:gochecknoglobals
	wampprotocapnp.CapnprotoSplitSubProtocol,
	&wampprotocapnp.CapnprotoSerializer{},
	xconn.SerializerID(wampprotocapnp.CapnprotoSplitSerializerID))

func ReadPrivateKeyFromFile() (string, error) {
	homeDir, err := RealHome()
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

func RealHome() (string, error) {
	if RunningInSnap() {
		return os.Getenv("SNAP_REAL_HOME"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not get home directory: %w", err)
	}

	return home, nil
}

func RunningInSnap() bool {
	snapPath := os.Getenv("SNAP")
	if snapPath == "" {
		return false
	}

	cmd := exec.Command("snapctl", "get", "none")
	err := cmd.Run()
	return err == nil
}
