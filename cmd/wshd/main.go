package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/xconnio/wampshell/server"
)

const (
	defaultRealm = "wampshell"
	defaultPort  = 8022
)

func main() {
	address := fmt.Sprintf("0.0.0.0:%d", defaultPort)

	newServer, err := server.NewServer(defaultRealm, address)
	if err != nil {
		log.Fatalf("Failed to create Server: %v", err)
	}

	if err := newServer.Start(); err != nil {
		log.Fatalf("Failed to start Server: %v", err)
	}
	defer func(newServer *server.Server) {
		err := newServer.Stop()
		if err != nil {
			log.Fatalf("Failed to stop Server: %v", err)
		}
	}(newServer)

	log.Printf("wshd running. Realm=%s, Listening on %s", newServer.Realm(), newServer.Address())

	closeChan := make(chan os.Signal, 1)
	signal.Notify(closeChan, os.Interrupt)
	<-closeChan

	log.Println("Shutting down wshd...")
}
