package keystore

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/glinharesb/vault-go/internal/crypto"
)

// persistedKey is the JSON-serializable form of a KeyEntry.
type persistedKey struct {
	ID            string            `json:"id"`
	Algorithm     KeyAlgorithm      `json:"algorithm"`
	Status        KeyStatus         `json:"status"`
	PrivateKeyDER []byte            `json:"private_key_der"`
	CreatedAt     time.Time         `json:"created_at"`
	RotatedAt     time.Time         `json:"rotated_at,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// PersistentStore wraps MemoryStore and persists to a JSON file using atomic rename.
type PersistentStore struct {
	*MemoryStore
	path string
}

// NewPersistentStore creates a store that persists to the given file path.
// If the file exists, it loads keys from it on startup (crash recovery).
func NewPersistentStore(path string) (*PersistentStore, error) {
	ps := &PersistentStore{
		MemoryStore: NewMemoryStore(),
		path:        path,
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	if _, err := os.Stat(path); err == nil {
		if err := ps.load(); err != nil {
			return nil, fmt.Errorf("load existing data: %w", err)
		}
		slog.Info("persistent store loaded", "keys", len(ps.keys))
	}

	return ps, nil
}

func (ps *PersistentStore) Put(entry *KeyEntry) error {
	if err := ps.MemoryStore.Put(entry); err != nil {
		return err
	}
	return ps.save()
}

func (ps *PersistentStore) UpdateStatus(id string, status KeyStatus) error {
	if err := ps.MemoryStore.UpdateStatus(id, status); err != nil {
		return err
	}
	return ps.save()
}

func (ps *PersistentStore) Delete(id string) error {
	if err := ps.MemoryStore.Delete(id); err != nil {
		return err
	}
	return ps.save()
}

// save writes all keys to a temp file then atomically renames it.
func (ps *PersistentStore) save() error {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var keys []persistedKey
	for _, e := range ps.keys {
		der, err := crypto.MarshalPrivateKey(e.PrivateKey)
		if err != nil {
			return fmt.Errorf("marshal key %s: %w", e.ID, err)
		}
		keys = append(keys, persistedKey{
			ID:            e.ID,
			Algorithm:     e.Algorithm,
			Status:        e.Status,
			PrivateKeyDER: der,
			CreatedAt:     e.CreatedAt,
			RotatedAt:     e.RotatedAt,
			Labels:        e.Labels,
		})
	}

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	tmpPath := ps.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, ps.path); err != nil {
		return fmt.Errorf("atomic rename: %w", err)
	}

	return nil
}

// load reads keys from the persisted file.
func (ps *PersistentStore) load() error {
	data, err := os.ReadFile(ps.path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var keys []persistedKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("unmarshal json: %w", err)
	}

	for _, pk := range keys {
		privKey, err := crypto.UnmarshalPrivateKey(pk.PrivateKeyDER)
		if err != nil {
			return fmt.Errorf("unmarshal key %s: %w", pk.ID, err)
		}
		ps.keys[pk.ID] = &KeyEntry{
			ID:         pk.ID,
			Algorithm:  pk.Algorithm,
			Status:     pk.Status,
			PrivateKey: privKey,
			CreatedAt:  pk.CreatedAt,
			RotatedAt:  pk.RotatedAt,
			Labels:     pk.Labels,
		}
	}

	return nil
}
