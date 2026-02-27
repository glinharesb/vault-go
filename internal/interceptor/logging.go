package interceptor

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// LoggingUnary logs unary RPC calls with method, duration, and status code.
func LoggingUnary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := status.Code(err)

		slog.Info("unary",
			"method", info.FullMethod,
			"code", code.String(),
			"duration", time.Since(start),
		)
		return resp, err
	}
}

// LoggingStream logs stream RPC calls.
func LoggingStream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		err := handler(srv, ss)
		code := status.Code(err)

		slog.Info("stream",
			"method", info.FullMethod,
			"code", code.String(),
			"duration", time.Since(start),
		)
		return err
	}
}
