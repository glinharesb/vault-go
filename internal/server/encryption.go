package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/glinharesb/vault-go/gen/vault/v1"
	"github.com/glinharesb/vault-go/internal/audit"
	"github.com/glinharesb/vault-go/internal/crypto"
	"github.com/glinharesb/vault-go/internal/keystore"
)

type EncryptionServer struct {
	pb.UnimplementedEncryptionServiceServer
	store keystore.Store
	audit *audit.Logger
}

func NewEncryptionServer(store keystore.Store, a *audit.Logger) *EncryptionServer {
	return &EncryptionServer{
		store: store,
		audit: a,
	}
}

func (s *EncryptionServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	entry, err := s.store.Get(req.KeyId)
	if err != nil {
		return nil, keyError(err)
	}
	if entry.Status != keystore.StatusActive {
		return nil, status.Error(codes.FailedPrecondition, "key is not active")
	}

	// Derive a symmetric key from the ECDSA private key bytes for AES-GCM.
	symKey, err := deriveSymmetricKey(entry)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive symmetric key: %v", err)
	}

	ct, err := crypto.EncryptAESGCM(symKey, req.Plaintext, req.Aad)
	if err != nil {
		s.audit.Log("Encrypt", req.KeyId, "ERROR", "", nil)
		return nil, status.Errorf(codes.Internal, "encrypt: %v", err)
	}

	s.audit.Log("Encrypt", req.KeyId, "OK", "", nil)
	return &pb.EncryptResponse{Ciphertext: ct, KeyId: req.KeyId}, nil
}

func (s *EncryptionServer) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	entry, err := s.store.Get(req.KeyId)
	if err != nil {
		return nil, keyError(err)
	}

	symKey, err := deriveSymmetricKey(entry)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive symmetric key: %v", err)
	}

	pt, err := crypto.DecryptAESGCM(symKey, req.Ciphertext, req.Aad)
	if err != nil {
		s.audit.Log("Decrypt", req.KeyId, "ERROR", "", nil)
		return nil, status.Errorf(codes.InvalidArgument, "decrypt: %v", err)
	}

	s.audit.Log("Decrypt", req.KeyId, "OK", "", nil)
	return &pb.DecryptResponse{Plaintext: pt}, nil
}

func (s *EncryptionServer) DeriveKey(ctx context.Context, req *pb.DeriveKeyRequest) (*pb.DeriveKeyResponse, error) {
	entry, err := s.store.Get(req.RootKeyId)
	if err != nil {
		return nil, keyError(err)
	}
	if entry.Status != keystore.StatusActive {
		return nil, status.Error(codes.FailedPrecondition, "root key is not active")
	}

	length := int(req.Length)
	if length <= 0 || length > 64 {
		return nil, status.Error(codes.InvalidArgument, "length must be 1-64 bytes")
	}

	rootBytes, err := crypto.MarshalPrivateKey(entry.PrivateKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal root key: %v", err)
	}

	derived, err := crypto.DeriveKey(rootBytes, req.Context, length)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive key: %v", err)
	}

	s.audit.Log("DeriveKey", req.RootKeyId, "OK", "", nil)
	return &pb.DeriveKeyResponse{DerivedKey: derived}, nil
}

// deriveSymmetricKey produces a 32-byte AES key from an ECDSA key via HKDF.
func deriveSymmetricKey(entry *keystore.KeyEntry) ([]byte, error) {
	privBytes, err := crypto.MarshalPrivateKey(entry.PrivateKey)
	if err != nil {
		return nil, err
	}
	return crypto.DeriveKey(privBytes, []byte("vault-aes-gcm"), 32)
}
