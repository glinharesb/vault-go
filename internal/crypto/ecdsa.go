package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

// GenerateECDSAKey creates a new ECDSA key pair for the given curve.
func GenerateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}
	return key, nil
}

// SignECDSA signs data with the given private key using SHA-256 digest.
// Returns the ASN.1 DER-encoded signature.
func SignECDSA(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	return sig, nil
}

// VerifyECDSA verifies an ASN.1 DER-encoded ECDSA signature against data.
func VerifyECDSA(pub *ecdsa.PublicKey, data, signature []byte) bool {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(pub, hash[:], signature)
}

// MarshalPublicKey encodes an ECDSA public key in PKIX DER format.
func MarshalPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return der, nil
}

// MarshalPrivateKey encodes an ECDSA private key in PKCS8 DER format.
func MarshalPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return der, nil
}

// UnmarshalPrivateKey decodes a PKCS8 DER-encoded ECDSA private key.
func UnmarshalPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA private key")
	}
	return key, nil
}
