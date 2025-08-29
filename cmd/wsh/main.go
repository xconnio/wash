package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	berncrypt "github.com/xconnio/berncrypt/go"
	"github.com/xconnio/xconn-go"
)

type keyPair struct {
	send    []byte
	receive []byte
}

func exchangeKeys(session *xconn.Session) (*keyPair, error) {
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

	return &keyPair{
		send:    sendKey,
		receive: receiveKey,
	}, nil
}

func readPrivateKeyFromFile() (string, error) {
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

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: wsh user@host[:port] <command> [args...]\n")
		os.Exit(1)
	}

	target := os.Args[1]
	var host, port string

	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		_, host = parts[0], parts[1]
	} else {
		user := os.Getenv("USER")
		if user == "" {
			fmt.Println("Error: user not provided and $USER not set")
			os.Exit(1)
		}
		host = target
	}

	if strings.Contains(host, ":") {
		hp := strings.SplitN(host, ":", 2)
		host, port = hp[0], hp[1]
	} else {
		port = "8022"
	}

	args := os.Args[2:]
	anyArgs := make([]any, len(args))
	for i, a := range args {
		anyArgs[i] = a
	}

	privateKey, err := readPrivateKeyFromFile()
	if err != nil {
		fmt.Printf("Error reading private key: %v\n", err)
		os.Exit(1)
	}

	url := fmt.Sprintf("rs://%s:%s", host, port)
	session, err := xconn.ConnectCryptosign(context.Background(), url, "wampshell", "", privateKey)
	if err != nil {
		panic(err)
	}

	keys, err := exchangeKeys(session)
	if err != nil {
		panic(err)
	}

	ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305([]byte("send"), keys.send)
	if err != nil {
		panic(err)
	}

	payload := make([]byte, len(nonce)+len(ciphertext))
	copy(payload, nonce)
	copy(payload[len(nonce):], ciphertext)

	response := session.Call("wampshell.payload.echo").Arg(payload).Do()
	if response.Err != nil {
		panic(response.Err)
	}

	incomingCiphertext, err := response.Args.Bytes(0)
	if err != nil {
		panic(err)
	}

	_, err = berncrypt.DecryptChaCha20Poly1305(incomingCiphertext[12:], incomingCiphertext[:12], keys.receive)
	if err != nil {
		panic(err)
	}

	cmdResponse := session.Call("wampshell.shell.exec").Args(anyArgs...).Do()
	if cmdResponse.Err != nil {
		fmt.Printf("Command execution error: %v\n", cmdResponse.Err)
		os.Exit(1)
	}

	output, err := cmdResponse.Args.String(0)
	if err != nil {
		fmt.Printf("Output parsing error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(output)
}
