package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var secretRefPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*:[0-9]+:[0-9]+$`)

type Store struct {
	durableDir string
	runtimeDir string
	aead       cipher.AEAD
}

func Open(configDir, runtimeDir string) (*Store, error) {
	if configDir == "" || runtimeDir == "" {
		return nil, errors.New("secret directories are required")
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(configDir, "state.key")
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := writeExclusive(keyPath, key, 0o600); err != nil {
			if existing, readErr := os.ReadFile(keyPath); readErr == nil {
				key = existing
			} else {
				return nil, err
			}
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("local secret master key is invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	durableDir := filepath.Join(configDir, "secrets")
	if err := os.MkdirAll(durableDir, 0o700); err != nil {
		return nil, err
	}
	return &Store{durableDir: durableDir, runtimeDir: runtimeDir, aead: aead}, nil
}

func (s *Store) Put(ref string, plaintext []byte) error {
	if s == nil || !secretRefPattern.MatchString(ref) || len(plaintext) == 0 || len(plaintext) > 1024*1024 {
		return errors.New("secret material is invalid")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := s.aead.Seal(nil, nonce, plaintext, []byte(ref))
	raw := append(nonce, sealed...)
	return atomicWrite(s.durablePath(ref), raw, 0o600)
}

func (s *Store) Resolve(ref string) ([]byte, error) {
	if s == nil || !secretRefPattern.MatchString(ref) {
		return nil, errors.New("secret reference is invalid")
	}
	raw, err := os.ReadFile(s.durablePath(ref))
	if err != nil {
		return nil, err
	}
	nonceSize := s.aead.NonceSize()
	if len(raw) <= nonceSize {
		return nil, errors.New("encrypted secret is invalid")
	}
	plaintext, err := s.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], []byte(ref))
	if err != nil {
		return nil, errors.New("encrypted secret authentication failed")
	}
	return plaintext, nil
}

func (s *Store) Materialize(ref, extension string, mode os.FileMode) (string, error) {
	plaintext, err := s.Resolve(ref)
	if err != nil {
		return "", err
	}
	if extension != ".crt" && extension != ".key" {
		return "", errors.New("secret material extension is invalid")
	}
	path := filepath.Join(s.runtimeDir, secretName(ref)+extension)
	if err := atomicWrite(path, plaintext, mode); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Store) RemoveMaterialized() error {
	entries, err := os.ReadDir(s.runtimeDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(s.runtimeDir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s *Store) durablePath(ref string) string {
	return filepath.Join(s.durableDir, secretName(ref)+".enc")
}

func secretName(ref string) string {
	digest := sha256.Sum256([]byte(ref))
	return hex.EncodeToString(digest[:])
}

func writeExclusive(path string, raw []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func atomicWrite(path string, raw []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".secret-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace secret material: %w", err)
	}
	return nil
}
