package keystore

import (
	"crypto/elliptic"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/glinharesb/vault-go/internal/crypto"
)

func makeEntry(t *testing.T, id string) *KeyEntry {
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

func TestPutAndGet(t *testing.T) {
	store := NewMemoryStore()
	entry := makeEntry(t, "key-1")

	if err := store.Put(entry); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, err := store.Get("key-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != "key-1" {
		t.Fatalf("id mismatch: got %s", got.ID)
	}
}

func TestPutDuplicate(t *testing.T) {
	store := NewMemoryStore()
	entry := makeEntry(t, "key-1")
	store.Put(entry)

	err := store.Put(makeEntry(t, "key-1"))
	if err == nil {
		t.Fatal("duplicate put should fail")
	}
}

func TestGetNotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.Get("nonexistent")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestListAll(t *testing.T) {
	store := NewMemoryStore()
	for i := range 5 {
		store.Put(makeEntry(t, fmt.Sprintf("key-%d", i)))
	}

	keys, err := store.List(0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("expected 5 keys, got %d", len(keys))
	}
}

func TestListFiltered(t *testing.T) {
	store := NewMemoryStore()
	for i := range 5 {
		e := makeEntry(t, fmt.Sprintf("key-%d", i))
		if i%2 == 0 {
			e.Status = StatusDeactivated
		}
		store.Put(e)
	}

	active, _ := store.List(StatusActive)
	if len(active) != 2 {
		t.Fatalf("expected 2 active, got %d", len(active))
	}

	deactivated, _ := store.List(StatusDeactivated)
	if len(deactivated) != 3 {
		t.Fatalf("expected 3 deactivated, got %d", len(deactivated))
	}
}

func TestUpdateStatus(t *testing.T) {
	store := NewMemoryStore()
	store.Put(makeEntry(t, "key-1"))

	if err := store.UpdateStatus("key-1", StatusRotated); err != nil {
		t.Fatalf("update status: %v", err)
	}

	got, _ := store.Get("key-1")
	if got.Status != StatusRotated {
		t.Fatalf("expected StatusRotated, got %v", got.Status)
	}
}

func TestUpdateStatusNotFound(t *testing.T) {
	store := NewMemoryStore()
	if err := store.UpdateStatus("nonexistent", StatusRotated); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	store := NewMemoryStore()
	store.Put(makeEntry(t, "key-1"))

	if err := store.Delete("key-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := store.Get("key-1")
	if err != ErrKeyNotFound {
		t.Fatal("deleted key should not be found")
	}
}

func TestDeleteNotFound(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Delete("nonexistent"); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	store := NewMemoryStore()
	const numKeys = 50
	const numReaders = 100

	// Pre-populate half the keys
	for i := range numKeys / 2 {
		store.Put(makeEntry(t, fmt.Sprintf("pre-%d", i)))
	}

	var wg sync.WaitGroup

	// Concurrent writers
	for i := range numKeys {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.Put(makeEntry(t, fmt.Sprintf("w-%d", i)))
		}(i)
	}

	// Concurrent readers
	for range numReaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.List(0)
		}()
	}

	// Concurrent get operations
	for i := range numKeys / 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.Get(fmt.Sprintf("pre-%d", i))
		}(i)
	}

	// Concurrent status updates
	for i := range numKeys / 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.UpdateStatus(fmt.Sprintf("pre-%d", i), StatusRotated)
		}(i)
	}

	wg.Wait()

	// Verify all pre-populated keys exist and were updated
	for i := range numKeys / 2 {
		got, err := store.Get(fmt.Sprintf("pre-%d", i))
		if err != nil {
			t.Fatalf("pre-%d not found: %v", i, err)
		}
		if got.Status != StatusRotated {
			t.Fatalf("pre-%d: expected rotated, got %v", i, got.Status)
		}
	}
}
