package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/xconnio/xconn-go"
)

func main() {
	const (
		defaultRealm = "wampshell"
		defaultPort  = 8022
	)

	router := xconn.NewRouter()
	router.AddRealm(defaultRealm)
	defer router.Close()

	server := xconn.NewServer(router, nil, nil)

	address := fmt.Sprintf("0.0.0.0:%d", defaultPort)
	closer, err := server.ListenAndServeRawSocket(xconn.NetworkTCP, address)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer func(closer io.Closer) {
		err := closer.Close()
		if err != nil {

		}
	}(closer)

	log.Printf("wshd running. Realm=%s, Listening on %s", defaultRealm, address)

	closeChan := make(chan os.Signal, 1)
	signal.Notify(closeChan, os.Interrupt)
	<-closeChan

	log.Println("Shutting down wshd...")
}
