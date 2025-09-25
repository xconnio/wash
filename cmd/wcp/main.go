package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/jessevdk/go-flags"

	"github.com/xconnio/berncrypt/go"
	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/wampshell"
	"github.com/xconnio/xconn-go"
)

const (
	maxSize = 1024 * 1024 * 15
)

func uploadFile(session *xconn.Session, keys *wampshell.KeyPair, localPath, remotePath string) error {
	fileInfo, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("failed to stat local file: %w", err)
	}
	if fileInfo.Size() > maxSize {
		return fmt.Errorf("file too large: %d bytes (max %d bytes)", fileInfo.Size(), maxSize)
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read local file: %w", err)
	}

	ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305(data, keys.Send)
	if err != nil {
		return err
	}

	encryptedPayload := append(nonce, ciphertext...)
	callResponse := session.Call("wampshell.shell.upload").Args(remotePath, encryptedPayload).Do()
	if callResponse.Err != nil {
		return fmt.Errorf("file upload error: %w", callResponse.Err)
	}

	encResp, err := callResponse.Args.Bytes(0)
	if err != nil {
		return fmt.Errorf("parsing response failed: %w", err)
	}

	plainResp, err := berncrypt.DecryptChaCha20Poly1305(encResp[12:], encResp[:12], keys.Receive)
	if err != nil {
		return fmt.Errorf("response decryption failed: %w", err)
	}

	log.Printf("Upload response: %s", string(plainResp))
	return nil
}

func downloadFile(session *xconn.Session, keys *wampshell.KeyPair, remotePath, localPath string) error {
	callResponse := session.Call("wampshell.shell.download").Arg(remotePath).Do()
	if callResponse.Err != nil {
		return fmt.Errorf("file download error: %w", callResponse.Err)
	}

	encResp, err := callResponse.Args.Bytes(0)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	data, err := berncrypt.DecryptChaCha20Poly1305(encResp[12:], encResp[:12], keys.Receive)
	if err != nil {
		return err
	}

	if err := os.WriteFile(localPath, data, 0600); err != nil {
		return fmt.Errorf("failed to save file: %w", err)
	}

	log.Printf("Downloaded %s → %s (%d bytes)", remotePath, localPath, len(data))
	return nil
}

func parseRemoteTarget(target string) (user, host, port, path string, err error) {
	port = "8022"

	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		user, target = parts[0], parts[1]
	}

	parts := strings.SplitN(target, ":", 3)
	switch len(parts) {
	case 2:
		host, path = parts[0], parts[1]
	case 3:
		host, port, path = parts[0], parts[1], parts[2]
	default:
		err = fmt.Errorf("invalid target: %s", target)
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

	if _, err := parser.Parse(); err != nil {
		log.Fatal(err)
	}

	src := opts.Args.Source
	dst := opts.Args.Target

	var mode string
	var localPath, remotePath string
	var user, host, port string

	if strings.Contains(src, ":") && !strings.Contains(dst, ":") {
		mode = "download"
		user, host, port, remotePath, _ = parseRemoteTarget(src)
		localPath = dst
	} else if !strings.Contains(src, ":") && strings.Contains(dst, ":") {
		mode = "upload"
		localPath = src
		user, host, port, remotePath, _ = parseRemoteTarget(dst)
	} else {
		log.Fatal("Invalid usage: one of source/target must be remote (user@host:path)")
	}

	privateKey, err := wampshell.ReadPrivateKeyFromFile()
	if err != nil {
		log.Fatalf("Reading private key failed: %v", err)
	}

	authenticator, err := auth.NewCryptoSignAuthenticator("", privateKey, map[string]any{"user": user})
	if err != nil {
		log.Fatalf("Creating authenticator failed: %v", err)
	}

	client := xconn.Client{
		SerializerSpec: wampshell.CapnprotoSerializerSpec,
		Authenticator:  authenticator,
	}

	url := fmt.Sprintf("rs://%s:%s", host, port)
	session, err := client.Connect(context.Background(), url, "wampshell")
	if err != nil {
		log.Fatalf("Connection failed: %v", err)
	}

	keys, err := wampshell.ExchangeKeys(session)
	if err != nil {
		log.Fatalf("Key exchange failed: %v", err)
	}

	switch mode {
	case "upload":
		if strings.HasSuffix(remotePath, "/") {
			remotePath += filepath.Base(localPath)
		} else if remotePath == "" {
			remotePath = filepath.Base(localPath)
		}
		if err := uploadFile(session, keys, localPath, remotePath); err != nil {
			log.Fatalf("Upload failed: %v", err)
		}
	case "download":
		if fi, err := os.Stat(localPath); err == nil && fi.IsDir() {
			localPath = filepath.Join(localPath, filepath.Base(remotePath))
		}
		if err := downloadFile(session, keys, remotePath, localPath); err != nil {
			log.Fatalf("Download failed: %v", err)
		}
	}
}
