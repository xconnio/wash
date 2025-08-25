package main

import (
	"context"
	"fmt"

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

func main() {
	session, err := xconn.ConnectAnonymous(context.Background(), "rs://localhost:8022", "wampshell")
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

	decoded, err := berncrypt.DecryptChaCha20Poly1305(incomingCiphertext[12:], incomingCiphertext[:12], keys.receive)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(decoded))
}
