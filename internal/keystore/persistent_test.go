package keystore

import (
	"crypto/elliptic"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glinharesb/vault-go/internal/crypto"
)

func makePersistentEntry(t *testing.T, id string) *KeyEntry {
	t.Helper()
	key, err := crypto.GenerateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &KeyEntry{
		ID:         id,
		Algorithm:  AlgorithmECDSAP256,
		Status:     StatusActive,
		PrivateKey: key,
		CreatedAt:  time.Now(),
		Labels:     map[string]string{"env": "test"},
	}
}

func TestPersistentStorePutAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	// Create store, add keys
	store, err := NewPersistentStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	entry := makePersistentEntry(t, "key-1")
	if err := store.Put(entry); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("data file should exist: %v", err)
	}

	// Simulate crash: create new store from same file
	store2, err := NewPersistentStore(path)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}

	got, err := store2.Get("key-1")
	if err != nil {
		t.Fatalf("get after reload: %v", err)
	}
	if got.ID != "key-1" {
		t.Fatalf("id mismatch: %s", got.ID)
	}
	if got.Algorithm != AlgorithmECDSAP256 {
		t.Fatalf("algorithm mismatch: %v", got.Algorithm)
	}

	// Verify the reloaded key can sign
	data := []byte("test signing after reload")
	sig, err := crypto.SignECDSA(got.PrivateKey, data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !crypto.VerifyECDSA(&entry.PrivateKey.PublicKey, data, sig) {
		t.Fatal("signature from reloaded key should verify against original")
	}
}

func TestPersistentStoreStatusPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	store, _ := NewPersistentStore(path)
	store.Put(makePersistentEntry(t, "key-1"))
	store.UpdateStatus("key-1", StatusRotated)

	store2, _ := NewPersistentStore(path)
	got, _ := store2.Get("key-1")
	if got.Status != StatusRotated {
		t.Fatalf("expected StatusRotated, got %v", got.Status)
	}
}

func TestPersistentStoreDeletePersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	store, _ := NewPersistentStore(path)
	store.Put(makePersistentEntry(t, "key-1"))
	store.Put(makePersistentEntry(t, "key-2"))
	store.Delete("key-1")

	store2, _ := NewPersistentStore(path)
	_, err := store2.Get("key-1")
	if err != ErrKeyNotFound {
		t.Fatal("deleted key should not survive reload")
	}
	_, err = store2.Get("key-2")
	if err != nil {
		t.Fatal("key-2 should survive reload")
	}
}

func TestPersistentStoreAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	store, _ := NewPersistentStore(path)
	store.Put(makePersistentEntry(t, "key-1"))

	// Temp file should not exist after successful save
	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatal("temp file should not exist after atomic rename")
	}
}

func TestPersistentStoreEmptyReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	// No file exists - should start empty
	store, err := NewPersistentStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	keys, _ := store.List(0)
	if len(keys) != 0 {
		t.Fatal("new store should be empty")
	}
}
