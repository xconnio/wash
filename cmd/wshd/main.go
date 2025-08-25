package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/xconnio/xconn-go"
)

const (
	defaultRealm = "wampshell"
	defaultPort  = 8022
	defaultHost  = "0.0.0.0"
)

func main() {
	address := fmt.Sprintf("%s:%d", defaultHost, defaultPort)

	router := xconn.NewRouter()
	if err := router.AddRealm(defaultRealm); err != nil {
		log.Fatal(err)
	}

	server := xconn.NewServer(router, nil, nil)
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
