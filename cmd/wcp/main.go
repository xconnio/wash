package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/wampshell"
	"github.com/xconnio/xconn-go"
)

const (
	maxSize = 1024 * 1024 * 15
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: wcp user@host[:port] <localfile> [remotefile]\n")
		os.Exit(1)
	}

	target := os.Args[1]
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

	localFile := os.Args[2]
	var remoteFile string
	if len(os.Args) >= 4 {
		remoteFile = os.Args[3]
	} else {
		remoteFile = filepath.Base(localFile)
	}

	fileInfo, err := os.Stat(localFile)
	if err != nil {
		fmt.Printf("Failed to stat local file: %v\n", err)
		os.Exit(1)
	}
	if fileInfo.Size() > maxSize {
		fmt.Printf("File too large: %d bytes (max %d bytes)\n", fileInfo.Size(), maxSize)
		os.Exit(1)
	}

	data, err := os.ReadFile(localFile)
	if err != nil {
		fmt.Printf("Failed to read local file: %v\n", err)
		os.Exit(1)
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
		SerializerSpec: xconn.CapnprotoSplitSerializerSpec,
		Authenticator:  authenticator,
	}

	url := fmt.Sprintf("rs://%s:%s", host, port)
	session, err := client.Connect(context.Background(), url, "wampshell")
	if err != nil {
		panic(err)
	}

	cmdResponse := session.Call("wampshell.shell.upload").Args(remoteFile, data).Do()
	if cmdResponse.Err != nil {
		fmt.Printf("File upload error: %v\n", cmdResponse.Err)
		os.Exit(1)
	}

	output, err := cmdResponse.Args.String(0)
	if err != nil {
		fmt.Printf("Output parsing error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Server response: %s\n", output)
}
