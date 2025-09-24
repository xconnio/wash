package wampshell

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	berncrypt "github.com/xconnio/berncrypt/go"
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

func ExchangeKeys(session *xconn.Session) (*KeyPair, error) {
	publicKey, privateKey, err := berncrypt.CreateX25519KeyPair()
	if err != nil {
		return nil, err
	}

	response := session.Call("wampshell.key.exchange").Arg(publicKey).Do()
	if response.Err != nil {
		return nil, response.Err
	}

	publicKeyPeer, err := response.Args.Bytes(0)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := berncrypt.PerformKeyExchange(privateKey, publicKeyPeer)
	if err != nil {
		return nil, err
	}

	receiveKey, err := berncrypt.DeriveKeyHKDF(sharedSecret, []byte("backendToFrontend"))
	if err != nil {
		return nil, err
	}

	sendKey, err := berncrypt.DeriveKeyHKDF(sharedSecret, []byte("frontendToBackend"))
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Send:    sendKey,
		Receive: receiveKey,
	}, nil
}
