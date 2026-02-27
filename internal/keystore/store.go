package keystore

import (
	"crypto/ecdsa"
	"errors"
	"time"
)

var (
	ErrKeyNotFound = errors.New("key not found")
	ErrKeyInactive = errors.New("key is not active")
)

// KeyAlgorithm represents the cryptographic algorithm for a key.
type KeyAlgorithm int

const (
	AlgorithmECDSAP256 KeyAlgorithm = iota + 1
	AlgorithmECDSAP384
)

func (a KeyAlgorithm) String() string {
	switch a {
	case AlgorithmECDSAP256:
		return "ECDSA_P256"
	case AlgorithmECDSAP384:
		return "ECDSA_P384"
	default:
		return "UNKNOWN"
	}
}

// KeyStatus represents the lifecycle state of a key.
type KeyStatus int

const (
	StatusActive KeyStatus = iota + 1
	StatusRotated
	StatusDeactivated
)

func (s KeyStatus) String() string {
	switch s {
	case StatusActive:
		return "ACTIVE"
	case StatusRotated:
		return "ROTATED"
	case StatusDeactivated:
		return "DEACTIVATED"
	default:
		return "UNKNOWN"
	}
}

// KeyEntry holds a key and its metadata.
type KeyEntry struct {
	ID         string
	Algorithm  KeyAlgorithm
	Status     KeyStatus
	PrivateKey *ecdsa.PrivateKey
	CreatedAt  time.Time
	RotatedAt  time.Time
	Labels     map[string]string
}

// Store defines the key storage interface.
type Store interface {
	Put(entry *KeyEntry) error
	Get(id string) (*KeyEntry, error)
	List(filter KeyStatus) ([]*KeyEntry, error)
	UpdateStatus(id string, status KeyStatus) error
	Delete(id string) error
}
