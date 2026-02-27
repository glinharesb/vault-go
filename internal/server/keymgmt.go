package server

import (
	"context"
	"crypto/elliptic"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/glinharesb/vault-go/gen/vault/v1"
	"github.com/glinharesb/vault-go/internal/audit"
	"github.com/glinharesb/vault-go/internal/crypto"
	"github.com/glinharesb/vault-go/internal/hsm"
	"github.com/glinharesb/vault-go/internal/keystore"
)

type KeyManagementServer struct {
	pb.UnimplementedKeyManagementServiceServer
	store keystore.Store
	hsm   hsm.Provider
	audit *audit.Logger

	mu          sync.RWMutex
	subscribers []chan *pb.KeyEvent
}

func NewKeyManagementServer(store keystore.Store, h hsm.Provider, a *audit.Logger) *KeyManagementServer {
	return &KeyManagementServer{
		store: store,
		hsm:   h,
		audit: a,
	}
}

func (s *KeyManagementServer) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	curve, algo, err := resolveCurve(req.Algorithm)
	if err != nil {
		return nil, err
	}

	key, err := s.hsm.GenerateKey(curve)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate key: %v", err)
	}

	entry := &keystore.KeyEntry{
		ID:         uuid.NewString(),
		Algorithm:  algo,
		Status:     keystore.StatusActive,
		PrivateKey: key,
		CreatedAt:  time.Now(),
		Labels:     req.Labels,
	}

	if err := s.store.Put(entry); err != nil {
		return nil, status.Errorf(codes.Internal, "store key: %v", err)
	}

	meta := entryToProto(entry)
	s.broadcastEvent(pb.KeyEventType_KEY_EVENT_TYPE_CREATED, meta)
	s.audit.Log("GenerateKey", entry.ID, "OK", "", nil)

	return &pb.GenerateKeyResponse{Metadata: meta}, nil
}

func (s *KeyManagementServer) GetPublicKey(ctx context.Context, req *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	entry, err := s.store.Get(req.KeyId)
	if err != nil {
		return nil, keyError(err)
	}

	der, err := crypto.MarshalPublicKey(&entry.PrivateKey.PublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal public key: %v", err)
	}

	return &pb.GetPublicKeyResponse{
		KeyId:        entry.ID,
		PublicKeyDer: der,
		Algorithm:    algoToProto(entry.Algorithm),
	}, nil
}

func (s *KeyManagementServer) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	filter := statusFromProto(req.StatusFilter)
	entries, err := s.store.List(filter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list keys: %v", err)
	}

	var keys []*pb.KeyMetadata
	for _, e := range entries {
		keys = append(keys, entryToProto(e))
	}
	return &pb.ListKeysResponse{Keys: keys}, nil
}

func (s *KeyManagementServer) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	old, err := s.store.Get(req.KeyId)
	if err != nil {
		return nil, keyError(err)
	}
	if old.Status != keystore.StatusActive {
		return nil, status.Error(codes.FailedPrecondition, "can only rotate active keys")
	}

	// Generate new key with same algorithm
	curve, _, err := resolveCurve(algoToProto(old.Algorithm))
	if err != nil {
		return nil, err
	}

	newKey, err := s.hsm.GenerateKey(curve)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate key: %v", err)
	}

	newEntry := &keystore.KeyEntry{
		ID:         uuid.NewString(),
		Algorithm:  old.Algorithm,
		Status:     keystore.StatusActive,
		PrivateKey: newKey,
		CreatedAt:  time.Now(),
		Labels:     old.Labels,
	}

	if err := s.store.UpdateStatus(req.KeyId, keystore.StatusRotated); err != nil {
		return nil, status.Errorf(codes.Internal, "update old key: %v", err)
	}
	old.Status = keystore.StatusRotated
	old.RotatedAt = time.Now()

	if err := s.store.Put(newEntry); err != nil {
		return nil, status.Errorf(codes.Internal, "store new key: %v", err)
	}

	oldMeta := entryToProto(old)
	newMeta := entryToProto(newEntry)
	s.broadcastEvent(pb.KeyEventType_KEY_EVENT_TYPE_ROTATED, newMeta)
	s.audit.Log("RotateKey", req.KeyId, "OK", "", map[string]string{"new_key_id": newEntry.ID})

	return &pb.RotateKeyResponse{OldKey: oldMeta, NewKey: newMeta}, nil
}

func (s *KeyManagementServer) DeactivateKey(ctx context.Context, req *pb.DeactivateKeyRequest) (*pb.DeactivateKeyResponse, error) {
	if err := s.store.UpdateStatus(req.KeyId, keystore.StatusDeactivated); err != nil {
		return nil, keyError(err)
	}

	entry, _ := s.store.Get(req.KeyId)
	meta := entryToProto(entry)
	s.broadcastEvent(pb.KeyEventType_KEY_EVENT_TYPE_DEACTIVATED, meta)
	s.audit.Log("DeactivateKey", req.KeyId, "OK", "", nil)

	return &pb.DeactivateKeyResponse{Metadata: meta}, nil
}

func (s *KeyManagementServer) WatchKeyEvents(_ *pb.WatchKeyEventsRequest, stream grpc.ServerStreamingServer[pb.KeyEvent]) error {
	ch := make(chan *pb.KeyEvent, 32)

	s.mu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		for i, sub := range s.subscribers {
			if sub == ch {
				s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case event := <-ch:
			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}

func (s *KeyManagementServer) broadcastEvent(eventType pb.KeyEventType, meta *pb.KeyMetadata) {
	event := &pb.KeyEvent{
		Type:      eventType,
		Metadata:  meta,
		Timestamp: timestamppb.Now(),
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, ch := range s.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

// helpers

func resolveCurve(algo pb.KeyAlgorithm) (elliptic.Curve, keystore.KeyAlgorithm, error) {
	switch algo {
	case pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, pb.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED:
		return elliptic.P256(), keystore.AlgorithmECDSAP256, nil
	case pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:
		return elliptic.P384(), keystore.AlgorithmECDSAP384, nil
	default:
		return nil, 0, status.Errorf(codes.InvalidArgument, "unsupported algorithm: %v", algo)
	}
}

func entryToProto(e *keystore.KeyEntry) *pb.KeyMetadata {
	meta := &pb.KeyMetadata{
		KeyId:     e.ID,
		Algorithm: algoToProto(e.Algorithm),
		Status:    statusToProto(e.Status),
		CreatedAt: timestamppb.New(e.CreatedAt),
		Labels:    e.Labels,
	}
	if !e.RotatedAt.IsZero() {
		meta.RotatedAt = timestamppb.New(e.RotatedAt)
	}
	return meta
}

func algoToProto(a keystore.KeyAlgorithm) pb.KeyAlgorithm {
	switch a {
	case keystore.AlgorithmECDSAP256:
		return pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	case keystore.AlgorithmECDSAP384:
		return pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384
	default:
		return pb.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	}
}

func statusToProto(s keystore.KeyStatus) pb.KeyStatus {
	switch s {
	case keystore.StatusActive:
		return pb.KeyStatus_KEY_STATUS_ACTIVE
	case keystore.StatusRotated:
		return pb.KeyStatus_KEY_STATUS_ROTATED
	case keystore.StatusDeactivated:
		return pb.KeyStatus_KEY_STATUS_DEACTIVATED
	default:
		return pb.KeyStatus_KEY_STATUS_UNSPECIFIED
	}
}

func statusFromProto(s pb.KeyStatus) keystore.KeyStatus {
	switch s {
	case pb.KeyStatus_KEY_STATUS_ACTIVE:
		return keystore.StatusActive
	case pb.KeyStatus_KEY_STATUS_ROTATED:
		return keystore.StatusRotated
	case pb.KeyStatus_KEY_STATUS_DEACTIVATED:
		return keystore.StatusDeactivated
	default:
		return 0
	}
}

func keyError(err error) error {
	if err == keystore.ErrKeyNotFound {
		return status.Error(codes.NotFound, "key not found")
	}
	return status.Errorf(codes.Internal, "%v", err)
}
