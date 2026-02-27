package server

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/glinharesb/vault-go/gen/vault/v1"
	"github.com/glinharesb/vault-go/internal/audit"
)

type AuditServer struct {
	pb.UnimplementedAuditServiceServer
	logger *audit.Logger
}

func NewAuditServer(logger *audit.Logger) *AuditServer {
	return &AuditServer{logger: logger}
}

func (s *AuditServer) QueryAudit(ctx context.Context, req *pb.QueryAuditRequest) (*pb.QueryAuditResponse, error) {
	var startTime, endTime time.Time
	if req.StartTime != nil {
		startTime = req.StartTime.AsTime()
	}
	if req.EndTime != nil {
		endTime = req.EndTime.AsTime()
	}

	entries := s.logger.Query(
		req.KeyId,
		req.Operation,
		startTime,
		endTime,
		int(req.Limit),
	)

	var pbEntries []*pb.AuditEntry
	for _, e := range entries {
		pbEntries = append(pbEntries, auditEntryToProto(e))
	}

	return &pb.QueryAuditResponse{Entries: pbEntries}, nil
}

func (s *AuditServer) StreamAudit(_ *pb.StreamAuditRequest, stream grpc.ServerStreamingServer[pb.AuditEntry]) error {
	sub := s.logger.Subscribe()
	defer s.logger.Unsubscribe(sub)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case entry, ok := <-sub.C:
			if !ok {
				return nil
			}
			if err := stream.Send(auditEntryToProto(entry)); err != nil {
				return err
			}
		}
	}
}

func auditEntryToProto(e audit.Entry) *pb.AuditEntry {
	return &pb.AuditEntry{
		Id:          e.ID,
		Timestamp:   timestamppb.New(e.Timestamp),
		Operation:   e.Operation,
		KeyId:       e.KeyID,
		Status:      e.Status,
		PeerAddress: e.PeerAddress,
		Metadata:    e.Metadata,
	}
}
