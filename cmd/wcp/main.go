package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jessevdk/go-flags"

	berncrypt "github.com/xconnio/berncrypt/go"
	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/wampshell"
	"github.com/xconnio/xconn-go"
)

const (
	maxSize = 1024 * 1024 * 15
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

func uploadFile(session *xconn.Session, keys *keyPair, localFile, remoteFile string) error {
	file, err := os.Stat(localFile)
	if err != nil {
		return fmt.Errorf("failed to stat local file: %w", err)
	}
	if file.Size() > maxSize {
		return fmt.Errorf("file too large: %d bytes (max %d bytes)", file.Size(), maxSize)
	}
	data, err := os.ReadFile(localFile)
	if err != nil {
		return fmt.Errorf("failed to read local file: %w", err)
	}
	ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305(data, keys.send)
	if err != nil {
		return err
	}
	encryptedPayload := append(nonce, ciphertext...)
	cmdResponse := session.Call("wampshell.shell.upload").Args(remoteFile, encryptedPayload).Do()
	if cmdResponse.Err != nil {
		return fmt.Errorf("file upload error: %w", cmdResponse.Err)
	}
	encResp, err := cmdResponse.Args.Bytes(0)
	if err != nil {
		return fmt.Errorf("output parsing error: %w", err)
	}
	resp, err := berncrypt.DecryptChaCha20Poly1305(encResp[12:], encResp[:12], keys.receive)
	if err != nil {
		return err
	}
	fmt.Printf("Server response: %s\n", string(resp))
	return nil
}

func downloadFile(session *xconn.Session, keys *keyPair, remoteFile, localFile string) error {
	cmdResponse := session.Call("wampshell.shell.download").Arg(remoteFile).Do()
	if cmdResponse.Err != nil {
		return fmt.Errorf("file download error: %w", cmdResponse.Err)
	}
	encResp, err := cmdResponse.Args.Bytes(0)
	if err != nil {
		return fmt.Errorf("output parsing error: %w", err)
	}
	data, err := berncrypt.DecryptChaCha20Poly1305(encResp[12:], encResp[:12], keys.receive)
	if err != nil {
		return err
	}
	if err := os.WriteFile(localFile, data, 0600); err != nil {
		return fmt.Errorf("failed to save file: %w", err)
	}
	fmt.Printf("Downloaded %s -> %s (%d bytes)\n", remoteFile, localFile, len(data))
	return nil
}

func splitRemote(s string) (user, host, port, path string, err error) {
	port = "8022"

	if strings.Contains(s, "@") {
		parts := strings.SplitN(s, "@", 2)
		user, s = parts[0], parts[1]
	}

	parts := strings.SplitN(s, ":", 3)
	switch len(parts) {
	case 2:
		host, path = parts[0], parts[1]
	case 3:
		host, port, path = parts[0], parts[1], parts[2]
	default:
		err = fmt.Errorf("invalid target: %s", s)
	}

	if user == "" {
		user = os.Getenv("USER")
	}
	return
}

type Options struct {
	Args struct {
		Source string `positional-arg-name:"source" required:"true"`
		Target string `positional-arg-name:"target" required:"true"`
	} `positional-args:"yes"`
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)

	_, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}

	src := opts.Args.Source
	dst := opts.Args.Target

	var mode string
	var localFile, remoteFile string
	var user, host, port string

	if strings.Contains(src, ":") && !strings.Contains(dst, ":") {
		mode = "download"
		user, host, port, remoteFile, _ = splitRemote(src)
		localFile = dst
	} else if !strings.Contains(src, ":") && strings.Contains(dst, ":") {
		mode = "upload"
		localFile = src
		user, host, port, remoteFile, _ = splitRemote(dst)
	} else {
		fmt.Println("Invalid usage: one of source/target must be remote (user@host:path)")
		os.Exit(1)
	}

	privateKey, err := wampshell.ReadPrivateKeyFromFile()
	if err != nil {
		fmt.Printf("Error reading private key: %v\n", err)
		os.Exit(1)
	}

	authExtra := map[string]any{}
	authExtra["user"] = user

	authenticator, err := auth.NewCryptoSignAuthenticator("", privateKey, authExtra)
	if err != nil {
		fmt.Printf("Error creating crypto sign authenticator: %v\n", err)
		os.Exit(1)
	}

	client := xconn.Client{
		SerializerSpec: xconn.CapnprotoSplitSerializerSpec,
		Authenticator:  authenticator,
	}

	url := fmt.Sprintf("rs://%s:%s", host, port)
	session, err := client.Connect(context.Background(), url, "wampshell")
	if err != nil {
		panic(err)
	}

	keys, err := exchangeKeys(session)
	if err != nil {
		panic(err)
	}

	switch mode {
	case "upload":
		if strings.HasSuffix(remoteFile, "/") {
			remoteFile += filepath.Base(localFile)
		} else if remoteFile == "" {
			remoteFile = filepath.Base(localFile)
		}
		if err := uploadFile(session, keys, localFile, remoteFile); err != nil {
			fmt.Printf("Upload failed: %v\n", err)
			os.Exit(1)
		}
	case "download":
		if fi, err := os.Stat(localFile); err == nil && fi.IsDir() {
			localFile = filepath.Join(localFile, filepath.Base(remoteFile))
		}
		if err := downloadFile(session, keys, remoteFile, localFile); err != nil {
			fmt.Printf("Download failed: %v\n", err)
			os.Exit(1)
		}
	}
}
