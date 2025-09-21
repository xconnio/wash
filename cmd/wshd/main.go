// wshd.go
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/jessevdk/go-flags"

	berncrypt "github.com/xconnio/berncrypt/go"
	"github.com/xconnio/wamp-webrtc-go"
	"github.com/xconnio/wampproto-go/serializers"
	"github.com/xconnio/wampshell"
	"github.com/xconnio/xconn-go"
)

const (
	defaultRealm             = "wampshell"
	defaultPort              = 8022
	defaultHost              = "0.0.0.0"
	procedureExec            = "wampshell.shell.exec"
	procedureFileUpload      = "wampshell.shell.upload"
	procedureFileDownload    = "wampshell.shell.download"
	procedureWebRTCOffer     = "wampshell.webrtc.offer"
	topicOffererOnCandidate  = "wampshell.webrtc.offerer.on_candidate"
	topicAnswererOnCandidate = "wampshell.webrtc.answerer.on_candidate"
)

func runCommand(cmd string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	command := exec.Command(cmd, args...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		return stderr.Bytes(), err
	}
	return stdout.Bytes(), nil
}

func handleRunCommand(e *wampshell.EncryptionManager) func(_ context.Context,
	inv *xconn.Invocation) *xconn.InvocationResult {
	return func(_ context.Context, inv *xconn.Invocation) *xconn.InvocationResult {

		payload, err := inv.ArgBytes(0)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
		}

		e.Lock()
		key, ok := e.Keys()[inv.Caller()]
		e.Unlock()

		if !ok {
			return xconn.NewInvocationError("wamp.error.unavailable", "unavailable")
		}

		decryptedPayload, err := berncrypt.DecryptChaCha20Poly1305(payload[12:], payload[:12], key.Receive)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
		}

		s := string(decryptedPayload)
		newStrs := strings.Split(s, " ")

		cmd := newStrs[0]

		rawArgs := newStrs[1:]

		output, err := runCommand(cmd, rawArgs...)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
		}

		ciphertext1, nonce1, err1 := berncrypt.EncryptChaCha20Poly1305(output, key.Send)
		if err1 != nil {
			panic(err)
		}

		payload1 := make([]byte, len(nonce1)+len(ciphertext1))
		copy(payload1, nonce1)
		copy(payload1[len(nonce1):], ciphertext1)

		return xconn.NewInvocationResult(payload1)
	}
}

func handleFileUpload(e *wampshell.EncryptionManager) func(_ context.Context,
	inv *xconn.Invocation) *xconn.InvocationResult {
	return func(_ context.Context, inv *xconn.Invocation) *xconn.InvocationResult {
		if len(inv.Args()) < 2 {
			return xconn.NewInvocationError("wamp.error.invalid_argument", "expected filename + encrypted data")
		}

		filename, err := inv.ArgString(0)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
		}

		payload, err := inv.ArgBytes(1)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.invalid_argument",
				fmt.Sprintf("file content must be []byte, got %s", err.Error()))
		}

		e.Lock()
		key, ok := e.Keys()[inv.Caller()]
		e.Unlock()
		if !ok {
			return xconn.NewInvocationError("wamp.error.unavailable", "no encryption key for caller")
		}

		decryptedData, err := berncrypt.DecryptChaCha20Poly1305(payload[12:], payload[:12], key.Receive)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
		}

		if err := os.WriteFile(filepath.Clean(filename), decryptedData, 0600); err != nil {
			return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
		}

		msg := fmt.Sprintf("file uploaded: %s (%d bytes)", filename, len(decryptedData))
		ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305([]byte(msg), key.Send)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
		}

		return xconn.NewInvocationResult(append(nonce, ciphertext...))
	}
}

func handleFileDownload(e *wampshell.EncryptionManager) func(_ context.Context,
	inv *xconn.Invocation) *xconn.InvocationResult {
	return func(_ context.Context, inv *xconn.Invocation) *xconn.InvocationResult {
		filename, err := inv.ArgString(0)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
		}

		e.Lock()
		key, ok := e.Keys()[inv.Caller()]
		e.Unlock()
		if !ok {
			return xconn.NewInvocationError("wamp.error.unavailable", "no encryption key for caller")
		}

		decryptedData, err := os.ReadFile(filepath.Clean(filename))
		if err != nil {
			return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
		}

		ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305(decryptedData, key.Send)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
		}

		return xconn.NewInvocationResult(append(nonce, ciphertext...))
	}
}

func registerProcedure(session *xconn.Session, procedure string, handler xconn.InvocationHandler) error {
	response := session.Register(procedure, handler).Do()
	if response.Err != nil {
		return fmt.Errorf("failed to register procedure %q: %w", procedure, response.Err)
	}
	log.Printf("Procedure registered: %s", procedure)
	return nil
}

type Options struct {
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)

	_, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}

	address := fmt.Sprintf("%s:%d", defaultHost, defaultPort)
	path := os.ExpandEnv("$HOME/.wampshell/authorized_keys")

	keyStore := wampshell.NewKeyStore()
	keyWatcher, err := keyStore.Watch(path)
	if err != nil {
		log.Fatalf("failed to initialize key watcher: %v", err)
	}
	defer func() { _ = keyWatcher.Close() }()

	authenticator := wampshell.NewAuthenticator(keyStore)

	router := xconn.NewRouter()
	if err = router.AddRealm(defaultRealm); err != nil {
		log.Fatal(err)
	}
	if err = router.AutoDiscloseCaller(defaultRealm, true); err != nil {
		log.Fatal(err)
	}

	encryption := wampshell.NewEncryptionManager(router)
	if err = encryption.Setup(); err != nil {
		log.Fatal(err)
	}

	procedures := []struct {
		name    string
		handler xconn.InvocationHandler
	}{
		{procedureExec, handleRunCommand(encryption)},
		{procedureFileUpload, handleFileUpload(encryption)},
		{procedureFileDownload, handleFileDownload(encryption)},
	}

	server := xconn.NewServer(router, authenticator, nil)
	if server == nil {
		log.Fatal("failed to create server")
	}

	closer, err := server.ListenAndServeRawSocket(xconn.NetworkTCP, address)
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = closer.Close() }()

	session, err := xconn.ConnectInMemory(router, defaultRealm)
	if err != nil {
		log.Fatalf("failed to connect to server: %v", err)
	}

	webRtcManager := wamp_webrtc_go.NewWebRTCHandler()
	cfg := &wamp_webrtc_go.ProviderConfig{
		Session:                     session,
		ProcedureHandleOffer:        procedureWebRTCOffer,
		TopicHandleRemoteCandidates: topicAnswererOnCandidate,
		TopicPublishLocalCandidate:  topicOffererOnCandidate,
		Serializer:                  &serializers.CBORSerializer{},
		Authenticator:               authenticator,
		Router:                      router,
	}
	err = webRtcManager.Setup(cfg)
	if err != nil {
		return
	}

	for _, proc := range procedures {
		if err = registerProcedure(session, proc.name, proc.handler); err != nil {
			log.Fatal(err)
		}
	}

	log.Printf("listening on rs://%s", address)

	closeChan := make(chan os.Signal, 1)
	signal.Notify(closeChan, os.Interrupt)
	<-closeChan
}
