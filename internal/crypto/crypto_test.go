package crypto

import (
	"bytes"
	"crypto/elliptic"
	"testing"
)

func TestECDSAP256SignVerify(t *testing.T) {
	key, err := GenerateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	data := []byte("test message for signing")
	sig, err := SignECDSA(key, data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !VerifyECDSA(&key.PublicKey, data, sig) {
		t.Fatal("valid signature rejected")
	}
}

func TestECDSAP384SignVerify(t *testing.T) {
	key, err := GenerateECDSAKey(elliptic.P384())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	data := []byte("test message P384")
	sig, err := SignECDSA(key, data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !VerifyECDSA(&key.PublicKey, data, sig) {
		t.Fatal("valid signature rejected")
	}
}

func TestECDSAVerifyWrongData(t *testing.T) {
	key, err := GenerateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	sig, err := SignECDSA(key, []byte("original"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if VerifyECDSA(&key.PublicKey, []byte("tampered"), sig) {
		t.Fatal("tampered data should not verify")
	}
}

func TestECDSAVerifyWrongKey(t *testing.T) {
	key1, _ := GenerateECDSAKey(elliptic.P256())
	key2, _ := GenerateECDSAKey(elliptic.P256())

	sig, _ := SignECDSA(key1, []byte("data"))
	if VerifyECDSA(&key2.PublicKey, []byte("data"), sig) {
		t.Fatal("wrong key should not verify")
	}
}

func TestECDSAMarshalRoundTrip(t *testing.T) {
	key, err := GenerateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	der, err := MarshalPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	recovered, err := UnmarshalPrivateKey(der)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Sign with original, verify with recovered
	data := []byte("roundtrip test")
	sig, err := SignECDSA(key, data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !VerifyECDSA(&recovered.PublicKey, data, sig) {
		t.Fatal("roundtrip key should verify signature")
	}
}

func TestMarshalPublicKey(t *testing.T) {
	key, _ := GenerateECDSAKey(elliptic.P256())
	der, err := MarshalPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("empty public key DER")
	}
}

func TestAESGCMEncryptDecrypt(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plaintext := []byte("secret data for encryption")
	aad := []byte("additional authenticated data")

	ct, err := EncryptAESGCM(key, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	pt, err := DecryptAESGCM(key, ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, pt) {
		t.Fatalf("plaintext mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestAESGCMNoAAD(t *testing.T) {
	key, _ := GenerateAESKey()
	plaintext := []byte("no aad test")

	ct, err := EncryptAESGCM(key, plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	pt, err := DecryptAESGCM(key, ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, pt) {
		t.Fatal("plaintext mismatch")
	}
}

func TestAESGCMWrongKey(t *testing.T) {
	key1, _ := GenerateAESKey()
	key2, _ := GenerateAESKey()

	ct, _ := EncryptAESGCM(key1, []byte("secret"), nil)
	_, err := DecryptAESGCM(key2, ct, nil)
	if err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestAESGCMWrongAAD(t *testing.T) {
	key, _ := GenerateAESKey()

	ct, _ := EncryptAESGCM(key, []byte("secret"), []byte("correct aad"))
	_, err := DecryptAESGCM(key, ct, []byte("wrong aad"))
	if err == nil {
		t.Fatal("decrypt with wrong AAD should fail")
	}
}

func TestAESGCMCiphertextTooShort(t *testing.T) {
	key, _ := GenerateAESKey()
	_, err := DecryptAESGCM(key, []byte("short"), nil)
	if err == nil {
		t.Fatal("short ciphertext should fail")
	}
}

func TestAESGCMUniqueNonce(t *testing.T) {
	key, _ := GenerateAESKey()
	plaintext := []byte("same data")

	ct1, _ := EncryptAESGCM(key, plaintext, nil)
	ct2, _ := EncryptAESGCM(key, plaintext, nil)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of same data should produce different ciphertext (unique nonce)")
	}
}

func TestHKDFDeriveKey(t *testing.T) {
	rootKey, _ := GenerateAESKey()
	ctx := []byte("transaction-signing-key")

	derived, err := DeriveKey(rootKey, ctx, 32)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}

	if len(derived) != 32 {
		t.Fatalf("derived key length: got %d, want 32", len(derived))
	}
}

func TestHKDFDeterministic(t *testing.T) {
	rootKey, _ := GenerateAESKey()
	ctx := []byte("same context")

	d1, _ := DeriveKey(rootKey, ctx, 32)
	d2, _ := DeriveKey(rootKey, ctx, 32)

	if !bytes.Equal(d1, d2) {
		t.Fatal("same inputs should produce same derived key")
	}
}

func TestHKDFDifferentContext(t *testing.T) {
	rootKey, _ := GenerateAESKey()

	d1, _ := DeriveKey(rootKey, []byte("context-a"), 32)
	d2, _ := DeriveKey(rootKey, []byte("context-b"), 32)

	if bytes.Equal(d1, d2) {
		t.Fatal("different contexts should produce different keys")
	}
}

func TestHKDFInvalidLength(t *testing.T) {
	rootKey, _ := GenerateAESKey()

	if _, err := DeriveKey(rootKey, []byte("ctx"), 0); err == nil {
		t.Fatal("length 0 should fail")
	}
	if _, err := DeriveKey(rootKey, []byte("ctx"), 65); err == nil {
		t.Fatal("length 65 should fail")
	}
}

// Benchmarks

func BenchmarkECDSAP256Sign(b *testing.B) {
	key, _ := GenerateECDSAKey(elliptic.P256())
	data := []byte("benchmark data for signing")
	b.ResetTimer()
	for b.Loop() {
		SignECDSA(key, data)
	}
}

func BenchmarkECDSAP256Verify(b *testing.B) {
	key, _ := GenerateECDSAKey(elliptic.P256())
	data := []byte("benchmark data for signing")
	sig, _ := SignECDSA(key, data)
	b.ResetTimer()
	for b.Loop() {
		VerifyECDSA(&key.PublicKey, data, sig)
	}
}

func BenchmarkAESGCMEncrypt(b *testing.B) {
	key, _ := GenerateAESKey()
	data := make([]byte, 1024)
	b.ResetTimer()
	for b.Loop() {
		EncryptAESGCM(key, data, nil)
	}
}

func BenchmarkAESGCMDecrypt(b *testing.B) {
	key, _ := GenerateAESKey()
	data := make([]byte, 1024)
	ct, _ := EncryptAESGCM(key, data, nil)
	b.ResetTimer()
	for b.Loop() {
		DecryptAESGCM(key, ct, nil)
	}
}

func BenchmarkHKDFDerive(b *testing.B) {
	rootKey, _ := GenerateAESKey()
	ctx := []byte("bench-context")
	b.ResetTimer()
	for b.Loop() {
		DeriveKey(rootKey, ctx, 32)
	}
}
