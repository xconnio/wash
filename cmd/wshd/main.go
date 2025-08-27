package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"

	"github.com/xconnio/wampshell"
	"github.com/xconnio/xconn-go"
)

const (
	defaultRealm  = "wampshell"
	defaultPort   = 8022
	defaultHost   = "0.0.0.0"
	procedureExec = "wampshell.shell.exec"
)

func runCommand(cmd string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	command := exec.Command(cmd, args...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}

func handleRunCommand(_ context.Context, inv *xconn.Invocation) *xconn.InvocationResult {
	log.Printf("Received invocation: args=%v, kwargs=%v", inv.Args(), inv.Kwargs())

	cmd, err := inv.ArgString(0)
	if err != nil {
		return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
	}
	rawArgs := inv.Args()[1:]
	args := make([]string, 0, len(rawArgs))
	for idx := range rawArgs {
		str, err := inv.ArgString(idx + 1)
		if err != nil {
			return xconn.NewInvocationError("wamp.error.invalid_argument", err.Error())
		}
		args = append(args, str)
	}
	output, err := runCommand(cmd, args...)
	if err != nil {
		return xconn.NewInvocationError("wamp.error.internal_error", err.Error())
	}

	return xconn.NewInvocationResult(output)
}

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

	server := xconn.NewServer(router, authenticator, nil)
	if server == nil {
		log.Fatal("failed to create server")
	}

	closer, err := server.ListenAndServeRawSocket(xconn.NetworkTCP, address)
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = closer.Close() }()

	log.Printf("listening on rs://%s", address)

	session, err := xconn.ConnectInMemory(router, defaultRealm)
	if err != nil {
		log.Fatalf("failed to connect to server: %v", err)
	}

	registerResponse := session.Register(procedureExec, handleRunCommand).Do()
	if registerResponse.Err != nil {
		log.Fatalf("failed to register procedure %q: %v", procedureExec, registerResponse.Err)
	}

	log.Printf("Procedure registered: %s", procedureExec)

	closeChan := make(chan os.Signal, 1)
	signal.Notify(closeChan, os.Interrupt)
	<-closeChan
}
