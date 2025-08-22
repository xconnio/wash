package main

import (
	"context"

	"github.com/xconnio/xconn-go"
)

func main() {
	session, err := xconn.ConnectAnonymous(context.Background(), "ws://localhost:8080/ws", "realm1")
	if err != nil {
		panic(err)
	}

	println(session)
}
