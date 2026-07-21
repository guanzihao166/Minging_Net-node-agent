package secretstore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretStoreEncryptsDurableMaterialAndMaterializesRuntimeCopy(t *testing.T) {
	root := t.TempDir()
	store, err := Open(filepath.Join(root, "config"), filepath.Join(root, "run"))
	if err != nil {
		t.Fatal(err)
	}
	ref := "agent-secret:tls-key:21:4"
	plaintext := []byte("private-key-plaintext-that-must-not-appear-at-rest")
	if err := store.Put(ref, plaintext); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.durablePath(ref))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, plaintext) {
		t.Fatal("durable secret file contains plaintext")
	}
	resolved, err := store.Resolve(ref)
	if err != nil || !bytes.Equal(resolved, plaintext) {
		t.Fatalf("Resolve = %q, %v", resolved, err)
	}
	path, err := store.Materialize(ref, ".key", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(materialized, plaintext) {
		t.Fatalf("materialized = %q, %v", materialized, err)
	}
	if err := store.RemoveMaterialized(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("runtime copy still exists: %v", err)
	}
}
