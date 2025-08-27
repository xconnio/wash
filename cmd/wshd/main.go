package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/xconnio/wampshell"
	"github.com/xconnio/xconn-go"
)

const (
	defaultRealm = "wampshell"
	defaultPort  = 8022
	defaultHost  = "0.0.0.0"
)

func main() {
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
	if err := router.AddRealm(defaultRealm); err != nil {
		log.Fatal(err)
	}

	if err := router.AutoDiscloseCaller(defaultRealm, true); err != nil {
		log.Fatal(err)
	}

	encryption := wampshell.NewEncryptionManager(router)
	if err := encryption.Setup(); err != nil {
		log.Fatal(err)
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

	fmt.Printf("listening on rs://%s\n", address)

	closeChan := make(chan os.Signal, 1)
	signal.Notify(closeChan, os.Interrupt)
	<-closeChan
}
