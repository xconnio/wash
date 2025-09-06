package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/wampshell"
)

func main() {
	home, err := wampshell.RealHome()
	if err != nil {
		log.Fatal(err)
	}

	dir := filepath.Join(home, ".wampshell")
	if err = os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("failed to create dir: %v", err)
	}

	privPath := filepath.Join(dir, "id_ed25519")
	pubPath := filepath.Join(dir, "id_ed25519.pub")

	if fileExists(privPath) || fileExists(pubPath) {
		fmt.Print("Key files already exist.Do you want to overwrite them? (y/N):")

		var answer string
		_, err := fmt.Scanln(&answer)
		if err != nil {
			return
		}
		answer = strings.TrimSpace(strings.ToLower(answer))

		if answer != "y" && answer != "yes" {
			fmt.Println("Cancelled.")
			return
		}
	}

	pub, priv, err := auth.GenerateCryptoSignKeyPair()
	if err != nil {
		log.Fatalf("failed to generate keypair: %v", err)
	}

	if err = os.WriteFile(privPath, []byte(priv+"\n"), 0600); err != nil {
		log.Fatalf("failed to write file: %v", err)
	}

	if err = os.WriteFile(pubPath, []byte(pub+"\n"), 0600); err != nil {
		log.Fatalf("failed to write file: %v", err)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
