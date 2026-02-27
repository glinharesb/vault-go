package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a key from the root key material using HKDF-SHA256.
// context is used as the HKDF info parameter for domain separation.
// length specifies the output key size in bytes.
func DeriveKey(rootKey, context []byte, length int) ([]byte, error) {
	if length <= 0 || length > 64 {
		return nil, fmt.Errorf("invalid derived key length: %d (must be 1-64)", length)
	}

	r := hkdf.New(sha256.New, rootKey, nil, context)
	derived := make([]byte, length)
	if _, err := io.ReadFull(r, derived); err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return derived, nil
}
