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
	"sync"

	"github.com/creack/pty"

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
	procedureInteractive     = "wampshell.shell.interactive"
	procedureExec            = "wampshell.shell.exec"
	procedureFileUpload      = "wampshell.shell.upload"
	procedureFileDownload    = "wampshell.shell.download"
	procedureSyncKeys        = "wampshell.shell.keys.sync"
	procedureWebRTCOffer     = "wampshell.webrtc.offer"
	topicOffererOnCandidate  = "wampshell.webrtc.offerer.on_candidate"
	topicAnswererOnCandidate = "wampshell.webrtc.answerer.on_candidate"
)

type interactiveShellSession struct {
	ptmx map[uint64]*os.File
	sync.Mutex
}

func newInteractiveShellSession() *interactiveShellSession {
	return &interactiveShellSession{
		ptmx: make(map[uint64]*os.File),
	}
}

func (p *interactiveShellSession) startPtySession(inv *xconn.Invocation, sendKey []byte) (*os.File, error) {
	cmd := exec.Command("bash")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to start PTY: %w", err)
	}
	p.Lock()
	p.ptmx[inv.Caller()] = ptmx
	p.Unlock()

	go p.startOutputReader(inv, ptmx, sendKey)

	return ptmx, nil
}

func (p *interactiveShellSession) startOutputReader(inv *xconn.Invocation, ptmx *os.File, sendKey []byte) {
	caller := inv.Caller()
	defer func() {
		p.Lock()
		delete(p.ptmx, caller)
		p.Unlock()
		if err := ptmx.Close(); err != nil {
			log.Printf("Error closing PTY for caller %d: %v", caller, err)
		}
	}()
	buf := make([]byte, 4096)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			ciphertext, nonce, errEnc := berncrypt.EncryptChaCha20Poly1305(buf[:n], sendKey)
			if errEnc != nil {
				log.Printf("Encryption failed in shell output for caller %d: %v", caller, errEnc)
				return
			}
			payload := append(nonce, ciphertext...)
			_ = inv.SendProgress([]any{payload}, nil)
		}
		if err != nil {
			_ = inv.SendProgress(nil, nil)
			return
		}
	}
}

func (p *interactiveShellSession) handleShell(e *wampshell.EncryptionManager) func(_ context.Context,
	inv *xconn.Invocation) *xconn.InvocationResult {
	return func(_ context.Context, inv *xconn.Invocation) *xconn.InvocationResult {
		caller := inv.Caller()
		key, ok := e.Key(inv.Caller())
		if !ok {
			return xconn.NewInvocationError("wamp.error.unavailable", "unavailable")
		}

		p.Lock()
		ptmx, ok := p.ptmx[caller]
		p.Unlock()

		if !ok {
			_, err := p.startPtySession(inv, key.Send)
			if err != nil {
				return xconn.NewInvocationError("io.xconn.error", err.Error())
			}
			return xconn.NewInvocationError(xconn.ErrNoResult)
		}

		if inv.Progress() {
			payload, err := inv.ArgBytes(0)
			if err != nil {
				return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
			}
			if len(payload) < 12 {
				return xconn.NewInvocationError("wamp.error.invalid_argument", "payload too short")
			}

			decrypted, err := berncrypt.DecryptChaCha20Poly1305(payload[12:], payload[:12], key.Receive)
			if err != nil {
				p.Lock()
				if storedPtmx, exists := p.ptmx[caller]; exists {
					storedPtmx.Close()
					delete(p.ptmx, caller)
				}
				p.Unlock()
				return xconn.NewInvocationError("io.xconn.error", err.Error())
			}

			_, err = ptmx.Write(decrypted)
			if err != nil {
				log.Printf("Failed to write to PTY for caller %d: %v", caller, err)
				return xconn.NewInvocationError("io.xconn.error", err.Error())
			}
			return xconn.NewInvocationError(xconn.ErrNoResult)
		}

		p.Lock()
		delete(p.ptmx, caller)
		p.Unlock()
		if ok {
			ptmx.Close()
		}

		return xconn.NewInvocationResult()
	}
}

func runCommand(cmd string, args ...string) ([]byte, error) {
	fullCmd := cmd
	if len(args) > 0 {
		fullCmd += " " + strings.Join(args, " ")
	}
	c := exec.Command("bash", "-ic", fullCmd)
	ptmx, err := pty.Start(c)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ptmx.Close() }()

	var stdout bytes.Buffer
	_, _ = stdout.ReadFrom(ptmx)

	return stdout.Bytes(), nil
}

func handleRunCommand(e *wampshell.EncryptionManager) func(_ context.Context,
	inv *xconn.Invocation) *xconn.InvocationResult {
	return func(_ context.Context, inv *xconn.Invocation) *xconn.InvocationResult {
		encryptedPayload, err := inv.ArgBytes(0)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
		}

		key, ok := e.Key(inv.Caller())
		if !ok {
			return xconn.NewInvocationError("wamp.error.unavailable", "unavailable")
		}

		decryptedPayload, err := berncrypt.DecryptChaCha20Poly1305(encryptedPayload[12:], encryptedPayload[:12], key.Receive)
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

		ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305(output, key.Send)
		if err != nil {
			log.Printf("Encryption failed in runCommand: %v", err)
			return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
		}

		return xconn.NewInvocationResult(append(nonce, ciphertext...))
	}
}

func handleFileUpload(e *wampshell.EncryptionManager) func(_ context.Context,
	inv *xconn.Invocation) *xconn.InvocationResult {
	return func(_ context.Context, inv *xconn.Invocation) *xconn.InvocationResult {
		log.Printf("handleFileUpload called for caller: %d", inv.Caller())

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

		key, ok := e.Key(inv.Caller())
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
		log.Printf("handleFileDownload called for caller: %d", inv.Caller())

		filename, err := inv.ArgString(0)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
		}

		key, ok := e.Key(inv.Caller())
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

func addRealm(router *xconn.Router, realm string) {
	if router.HasRealm(realm) {
		return
	}
	if err := router.AddRealm(realm); err != nil {
		log.Printf("failed to add realm %q: %v", realm, err)
		return
	}
	if err := router.AutoDiscloseCaller(realm, true); err != nil {
		log.Printf("failed to enable auto-disclose for %q: %v", realm, err)
		return
	}
	log.Printf("Adding realm: %s", realm)
}

func SyncAuthorizedKeys(session *xconn.Session, keys *wampshell.KeyPair, keyStore *wampshell.KeyStore) error {
	lines, err := keyStore.AuthorizedKeys()
	if err != nil {
		return fmt.Errorf("failed to get authorized keys: %w", err)
	}

	plaintext := strings.Join(lines, "\n")
	if plaintext == "" {
		return fmt.Errorf("no keys to sync")
	}

	ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305([]byte(plaintext), keys.Send)
	if err != nil {
		return fmt.Errorf("failed to encrypt keys: %w", err)
	}
	payload := append(nonce, ciphertext...)

	callResponse := session.Call(procedureSyncKeys).Args(payload).Do()
	if callResponse.Err != nil {
		return fmt.Errorf("sync keys call failed: %w", callResponse.Err)
	}

	return nil
}

func handleSyncKeys(realm string, keyStore *wampshell.KeyStore,
	e *wampshell.EncryptionManager) xconn.InvocationHandler {
	return func(_ context.Context, inv *xconn.Invocation) *xconn.InvocationResult {
		encryptedPayload, err := inv.ArgBytes(0)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
		}

		key, ok := e.Key(inv.Caller())
		if !ok {
			return xconn.NewInvocationError("wamp.error.unavailable", "no encryption key for caller")
		}

		if len(encryptedPayload) < 12 {
			return xconn.NewInvocationError("wamp.error.invalid_argument", "payload too short")
		}
		plaintext, err := berncrypt.DecryptChaCha20Poly1305(encryptedPayload[12:], encryptedPayload[:12], key.Receive)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
		}

		allKeys := strings.Split(string(plaintext), "\n")
		newKeys := make(map[string][]string)
		for _, line := range allKeys {
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) == 0 {
				continue
			}
			k := parts[0]
			newKeys[realm] = append(newKeys[realm], k)
		}
		keyStore.Update(newKeys)

		log.Printf("Synced %d keys from caller %d", len(allKeys), inv.Caller())
		return xconn.NewInvocationResult("ok")
	}
}

func main() {
	loadConfig, err := wampshell.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
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

	privateKey, err := wampshell.ReadPrivateKeyFromFile()
	if err != nil {
		log.Fatalf("Error reading private key: %s", err)
	}

	router := xconn.NewRouter()
	addRealm(router, defaultRealm)
	for realm := range authenticator.Realms() {
		addRealm(router, realm)
	}

	keyStore.OnUpdate(func(keys map[string][]string) {
		for realm := range keys {
			addRealm(router, realm)
		}
	})

	server := xconn.NewServer(router, authenticator, nil)
	if server == nil {
		log.Fatal("failed to create server")
	}

	if err = server.RegisterSpec(wampshell.CapnprotoSerializerSpec); err != nil {
		log.Fatal(err)
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

	var sessions []*xconn.Session
	sessions = append(sessions, session)

	for _, p := range loadConfig.Principals {
		sess, err := xconn.ConnectCryptosign(context.Background(), p.URL, p.Realm, "", privateKey)
		if err != nil {
			continue
		}

		sessions = append(sessions, sess)

		keys, err := wampshell.ExchangeKeys(sess)
		if err != nil {
			log.Fatalf("Failed to exchange keys: %v", err)
		}

		if err := SyncAuthorizedKeys(sess, keys, keyStore); err != nil {
			log.Printf("failed to sync authorized keys with %s: %v", p.URL, err)
		}
	}

	for _, sess := range sessions {
		webRtcManager := wamp_webrtc_go.NewWebRTCHandler()
		cfg := &wamp_webrtc_go.ProviderConfig{
			Session:                     sess,
			ProcedureHandleOffer:        procedureWebRTCOffer,
			TopicHandleRemoteCandidates: topicAnswererOnCandidate,
			TopicPublishLocalCandidate:  topicOffererOnCandidate,
			Serializer:                  &serializers.CBORSerializer{},
			Authenticator:               authenticator,
			Router:                      router,
		}
		err = webRtcManager.Setup(cfg)
		if err != nil {
			log.Printf("Failed to setup WebRTC: %v", err)
			return
		}

		encryption := wampshell.NewEncryptionManager(sess)
		if err = encryption.Setup(); err != nil {
			log.Fatal(err)
		}

		procedures := []struct {
			name    string
			handler xconn.InvocationHandler
		}{
			{procedureInteractive, newInteractiveShellSession().handleShell(encryption)},
			{procedureExec, handleRunCommand(encryption)},
			{procedureFileUpload, handleFileUpload(encryption)},
			{procedureFileDownload, handleFileDownload(encryption)},
		}

		for _, proc := range procedures {
			registerResponse := sess.Register(proc.name, proc.handler).Do()
			if registerResponse.Err != nil {
				log.Fatalln(registerResponse.Err)
			}
			log.Printf("Procedure registered: %s", proc.name)
		}

		if sess.Details().Realm() != defaultRealm {
			c, err := xconn.ConnectInMemory(router, sess.Details().Realm())
			if err != nil {
				log.Fatalf("Error connecting to realm %s: %v", sess.Details().Realm(), err)
			}

			r := c.Register(procedureSyncKeys, handleSyncKeys(sess.Details().Realm(), keyStore, encryption)).Do()
			if r.Err != nil {
				log.Fatalf("Error registering realm %s: %v", sess.Details().Realm(), r.Err)
			}

			fmt.Printf("registered %s\n", procedureSyncKeys)
		}
	}

	log.Printf("listening on rs://%s", address)

	closeChan := make(chan os.Signal, 1)
	signal.Notify(closeChan, os.Interrupt)
	<-closeChan
}
