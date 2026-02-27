package keystore

import (
	"fmt"
	"sync"
)

// MemoryStore is a thread-safe in-memory key store backed by sync.RWMutex.
type MemoryStore struct {
	mu   sync.RWMutex
	keys map[string]*KeyEntry
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		keys: make(map[string]*KeyEntry),
	}
}

func (m *MemoryStore) Put(entry *KeyEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[entry.ID]; exists {
		return fmt.Errorf("key %s already exists", entry.ID)
	}
	m.keys[entry.ID] = entry
	return nil
}

func (m *MemoryStore) Get(id string) (*KeyEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return entry, nil
}

func (m *MemoryStore) List(filter KeyStatus) ([]*KeyEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*KeyEntry
	for _, entry := range m.keys {
		if filter == 0 || entry.Status == filter {
			result = append(result, entry)
		}
	}
	return result, nil
}

func (m *MemoryStore) UpdateStatus(id string, status KeyStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.keys[id]
	if !ok {
		return ErrKeyNotFound
	}
	entry.Status = status
	return nil
}

func (m *MemoryStore) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.keys[id]; !ok {
		return ErrKeyNotFound
	}
	delete(m.keys, id)
	return nil
}
