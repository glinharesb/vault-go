package hsm

import (
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/glinharesb/vault-go/internal/crypto"
)

// SoftwareHSM is a software-only HSM implementation for development and testing.
// In production, this would be replaced by a hardware-backed provider.
type SoftwareHSM struct{}

func NewSoftwareHSM() *SoftwareHSM {
	return &SoftwareHSM{}
}

func (s *SoftwareHSM) GenerateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return crypto.GenerateECDSAKey(curve)
}

func (s *SoftwareHSM) Sign(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	return crypto.SignECDSA(key, data)
}

func (s *SoftwareHSM) Verify(pub *ecdsa.PublicKey, data, signature []byte) bool {
	return crypto.VerifyECDSA(pub, data, signature)
}
