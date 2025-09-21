package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jessevdk/go-flags"

	"github.com/xconnio/berncrypt/go"
	"github.com/xconnio/wamp-webrtc-go"
	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/wampshell"
	"github.com/xconnio/xconn-go"
)

const (
	defaultRealm             = "wampshell"
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

type Options struct {
	PeerToPeer bool `long:"p2p" description:"Use WebRTC for peer-to-peer connection"`
	Args       struct {
		Target string   `positional-arg-name:"host" required:"true"`
		Cmd    []string `positional-arg-name:"command" required:"true"`
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

	anyArgs := make([]any, len(args))
	for i, a := range args {
		anyArgs[i] = a
	}

	privateKey, err := wampshell.ReadPrivateKeyFromFile()
	if err != nil {
		fmt.Printf("Error reading private key: %v\n", err)
		os.Exit(1)
	}

	authenticator, err := auth.NewCryptoSignAuthenticator("", privateKey, nil)
	if err != nil {
		fmt.Printf("Error creating crypto sign authenticator: %v\n", err)
		os.Exit(1)
	}

	client := xconn.Client{
		SerializerSpec: xconn.CBORSerializerSpec,
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

	b := []byte(strings.Join(args, " "))

	ciphertext, nonce, err := berncrypt.EncryptChaCha20Poly1305(b, keys.send)
	if err != nil {
		panic(err)
	}

	payload := make([]byte, len(nonce)+len(ciphertext))
	copy(payload, nonce)
	copy(payload[len(nonce):], ciphertext)

	cmdResponse := session.Call("wampshell.shell.exec").Args(payload).Do()
	if cmdResponse.Err != nil {
		fmt.Printf("Command execution error: %v\n", cmdResponse.Err)
		os.Exit(1)
	}

	output, err := cmdResponse.Args.Bytes(0)
	if err != nil {
		fmt.Printf("Output parsing error: %v\n", err)
		os.Exit(1)
	}

	a, err := berncrypt.DecryptChaCha20Poly1305(output[12:], output[:12], keys.receive)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(a))

}
