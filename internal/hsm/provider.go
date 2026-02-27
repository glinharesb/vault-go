package hsm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
)

// Provider abstracts hardware security module operations.
// Real implementations would delegate to PKCS#11 or cloud KMS.
type Provider interface {
	GenerateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error)
	Sign(key *ecdsa.PrivateKey, data []byte) ([]byte, error)
	Verify(pub *ecdsa.PublicKey, data, signature []byte) bool
}
