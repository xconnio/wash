package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jessevdk/go-flags"
	"golang.org/x/term"

	"github.com/xconnio/berncrypt/go"
	"github.com/xconnio/wamp-webrtc-go"
	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/wampshell"
	"github.com/xconnio/xconn-go"
)

const (
	defaultRealm             = "wampshell"
	procedureInteractive     = "wampshell.shell.interactive"
	procedureExec            = "wampshell.shell.exec"
	procedureWebRTCOffer     = "wampshell.webrtc.offer"
	topicOffererOnCandidate  = "wampshell.webrtc.offerer.on_candidate"
	topicAnswererOnCandidate = "wampshell.webrtc.answerer.on_candidate"
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

func startInteractiveShell(session *xconn.Session, keys *keyPair) {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		log.Fatalf("Failed to set raw mode: %s", err)
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	firstProgress := true

	call := session.Call(procedureInteractive).
		ProgressSender(func(ctx context.Context) *xconn.Progress {
			if firstProgress {
				firstProgress = false
				return xconn.NewProgress()
			}

			buf := make([]byte, 1024)
			n, err := os.Stdin.Read(buf)
			if err != nil {
				return xconn.NewFinalProgress()
			}

			ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305(buf[:n], keys.send)
			if err != nil {
				panic(err)
			}
			payload := append(nonce, ciphertext...)

			return xconn.NewProgress(payload)
		}).
		ProgressReceiver(func(result *xconn.InvocationResult) {
			if len(result.Args) > 0 {
				encData := result.Args[0].([]byte)

				if len(encData) < 12 {
					fmt.Fprintln(os.Stderr, "invalid payload from server")
					os.Exit(1)
				}

				plain, err := berncrypt.DecryptChaCha20Poly1305(encData[12:], encData[:12], keys.receive)
				if err != nil {
					_ = fmt.Errorf("decryption error: %w", err)
				}

				os.Stdout.Write(plain)
			} else {
				err = term.Restore(fd, oldState)
				if err != nil {
					return
				}
				os.Exit(0)
			}
		}).Do()

	if call.Err != nil {
		log.Fatalf("Shell error: %s", call.Err)
	}
}

func runCommand(session *xconn.Session, keys *keyPair, args []string) {
	b := []byte(strings.Join(args, " "))

	ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305(b, keys.send)
	if err != nil {
		panic(err)
	}

	payload := append(nonce, ciphertext...)

	cmdResponse := session.Call(procedureExec).Args(payload).Do()
	if cmdResponse.Err != nil {
		fmt.Printf("Command execution error: %v\n", cmdResponse.Err)
		os.Exit(1)
	}

	output, err := cmdResponse.Args.Bytes(0)
	if err != nil {
		fmt.Printf("Output parsing error: %v\n", err)
		os.Exit(1)
	}

	plain, err := berncrypt.DecryptChaCha20Poly1305(output[12:], output[:12], keys.receive)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(plain))
}

type Options struct {
	Interactive bool `short:"i" long:"interactive" description:"Force interactive shell"`
	PeerToPeer  bool `long:"p2p" description:"Use WebRTC for peer-to-peer connection"`
	Args        struct {
		Target string   `positional-arg-name:"host" required:"true"`
		Cmd    []string `positional-arg-name:"command"`
	} `positional-args:"yes"`
}

func main() {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)

	_, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}

	target := opts.Args.Target
	args := opts.Args.Cmd

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

	privateKey, err := wampshell.ReadPrivateKeyFromFile()
	if err != nil {
		fmt.Printf("Error reading private key: %v\n", err)
		os.Exit(1)
	}

	authenticator, err := auth.NewCryptoSignAuthenticator("", privateKey, nil)
	if err != nil {
		log.Fatal("Error creating crypto sign authenticator:", err)
	}

	client := xconn.Client{
		SerializerSpec: wampshell.CapnprotoSerializerSpec,
		Authenticator:  authenticator,
	}

	url := fmt.Sprintf("rs://%s:%s", host, port)

	session, err := client.Connect(context.Background(), url, defaultRealm)
	if err != nil {
		log.Fatalf("Failed to connect via TCP: %v", err)
	}

	if opts.PeerToPeer {
		config := &wamp_webrtc_go.ClientConfig{
			Realm:                    defaultRealm,
			ProcedureWebRTCOffer:     procedureWebRTCOffer,
			TopicAnswererOnCandidate: topicAnswererOnCandidate,
			TopicOffererOnCandidate:  topicOffererOnCandidate,
			Serializer:               xconn.CBORSerializerSpec,
			Authenticator:            authenticator,
			Session:                  session,
		}

		session, err = wamp_webrtc_go.ConnectWAMP(config)
		if err != nil {
			log.Fatalf("Failed to connect via WebRTC: %v", err)
		}
	}

	keys, err := exchangeKeys(session)
	if err != nil {
		panic(err)
	}

	if opts.Interactive || len(args) == 0 {
		startInteractiveShell(session, keys)
	}

	runCommand(session, keys, args)
}
