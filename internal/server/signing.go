package server

import (
	"context"
	"io"
	"runtime"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/glinharesb/vault-go/gen/vault/v1"
	"github.com/glinharesb/vault-go/internal/audit"
	"github.com/glinharesb/vault-go/internal/hsm"
	"github.com/glinharesb/vault-go/internal/keystore"
)

type SigningServer struct {
	pb.UnimplementedSigningServiceServer
	store keystore.Store
	hsm   hsm.Provider
	audit *audit.Logger
}

func NewSigningServer(store keystore.Store, h hsm.Provider, a *audit.Logger) *SigningServer {
	return &SigningServer{
		store: store,
		hsm:   h,
		audit: a,
	}
}

func (s *SigningServer) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	entry, err := s.store.Get(req.KeyId)
	if err != nil {
		return nil, keyError(err)
	}
	if entry.Status != keystore.StatusActive {
		return nil, status.Error(codes.FailedPrecondition, "key is not active")
	}

	sig, err := s.hsm.Sign(entry.PrivateKey, req.Data)
	if err != nil {
		s.audit.Log("Sign", req.KeyId, "ERROR", "", nil)
		return nil, status.Errorf(codes.Internal, "sign: %v", err)
	}

	s.audit.Log("Sign", req.KeyId, "OK", "", nil)
	return &pb.SignResponse{Signature: sig, KeyId: req.KeyId}, nil
}

func (s *SigningServer) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	entry, err := s.store.Get(req.KeyId)
	if err != nil {
		return nil, keyError(err)
	}

	valid := s.hsm.Verify(&entry.PrivateKey.PublicKey, req.Data, req.Signature)
	s.audit.Log("Verify", req.KeyId, "OK", "", nil)

	return &pb.VerifyResponse{Valid: valid}, nil
}

func (s *SigningServer) BatchSign(ctx context.Context, req *pb.BatchSignRequest) (*pb.BatchSignResponse, error) {
	entry, err := s.store.Get(req.KeyId)
	if err != nil {
		return nil, keyError(err)
	}
	if entry.Status != keystore.StatusActive {
		return nil, status.Error(codes.FailedPrecondition, "key is not active")
	}

	results := make([]*pb.SignResult, len(req.Data))
	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup

	for i, data := range req.Data {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, data []byte) {
			defer wg.Done()
			defer func() { <-sem }()

			sig, err := s.hsm.Sign(entry.PrivateKey, data)
			if err != nil {
				results[i] = &pb.SignResult{Error: err.Error()}
				return
			}
			results[i] = &pb.SignResult{Signature: sig}
		}(i, data)
	}

	wg.Wait()
	s.audit.Log("BatchSign", req.KeyId, "OK", "", nil)

	return &pb.BatchSignResponse{Results: results}, nil
}

func (s *SigningServer) StreamSign(stream grpc.BidiStreamingServer[pb.StreamSignRequest, pb.StreamSignResponse]) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		entry, err := s.store.Get(req.KeyId)
		if err != nil {
			if sendErr := stream.Send(&pb.StreamSignResponse{Error: "key not found"}); sendErr != nil {
				return sendErr
			}
			continue
		}

		if entry.Status != keystore.StatusActive {
			if sendErr := stream.Send(&pb.StreamSignResponse{Error: "key is not active"}); sendErr != nil {
				return sendErr
			}
			continue
		}

		sig, err := s.hsm.Sign(entry.PrivateKey, req.Data)
		if err != nil {
			if sendErr := stream.Send(&pb.StreamSignResponse{Error: err.Error()}); sendErr != nil {
				return sendErr
			}
			continue
		}

		if err := stream.Send(&pb.StreamSignResponse{Signature: sig}); err != nil {
			return err
		}
	}
}
