package wampshell

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

type KeyStore struct {
	keys map[string]struct{}

	sync.RWMutex
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys: make(map[string]struct{}),
	}
}

func (k *KeyStore) HasKey(key string) bool {
	k.RLock()
	defer k.RUnlock()

	_, ok := k.keys[key]
	return ok
}

func (k *KeyStore) Update(keys []string) {
	k.Lock()
	defer k.Unlock()

	k.keys = make(map[string]struct{})
	for _, key := range keys {
		k.keys[key] = struct{}{}
	}
}

func readKeys(filePath string) ([]string, error) {
	var keys []string

	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if err := os.WriteFile(filePath, []byte(""), 0600); err != nil {
			return nil, fmt.Errorf("failed to create file %s: %w", filePath, err)
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	for _, key := range strings.Split(string(data), "\n") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		keyBytes, err := hex.DecodeString(key)
		if err != nil {
			continue
		}

		if len(keyBytes) != 32 {
			continue
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func (k *KeyStore) Watch(filePath string) (*fsnotify.Watcher, error) {
	keys, err := readKeys(filePath)
	if err != nil {
		return nil, err
	}
	k.Update(keys)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	dir := filepath.Dir(filePath)
	if err = watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("failed to watch %s: %w", dir, err)
	}

	go k.watch(filePath, watcher)

	return watcher, nil
}

func (k *KeyStore) watch(filePath string, watcher *fsnotify.Watcher) {
	fileName := filepath.Base(filePath)

	for event := range watcher.Events {
		if filepath.Base(event.Name) != fileName {
			continue
		}

		switch {
		case event.Has(fsnotify.Write), event.Has(fsnotify.Create):
			keys, err := readKeys(filePath)
			if err != nil {
				continue
			}
			k.Update(keys)

		case event.Has(fsnotify.Remove), event.Has(fsnotify.Rename):
			k.Update(nil)
		}
	}
}
