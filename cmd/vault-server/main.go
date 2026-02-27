package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/glinharesb/vault-go/gen/vault/v1"
	"github.com/glinharesb/vault-go/internal/audit"
	"github.com/glinharesb/vault-go/internal/config"
	"github.com/glinharesb/vault-go/internal/hsm"
	"github.com/glinharesb/vault-go/internal/interceptor"
	"github.com/glinharesb/vault-go/internal/keystore"
	"github.com/glinharesb/vault-go/internal/server"
)

func main() {
	cfg := config.Load()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	auditLogger := audit.NewLogger(cfg.AuditBuffer, os.Stdout)
	defer auditLogger.Close()

	var store keystore.Store
	if cfg.DataDir != "" {
		ps, err := keystore.NewPersistentStore(filepath.Join(cfg.DataDir, "keys.json"))
		if err != nil {
			slog.Error("persistent store", "error", err)
			os.Exit(1)
		}
		store = ps
		slog.Info("using persistent store", "path", cfg.DataDir)
	} else {
		store = keystore.NewMemoryStore()
		slog.Info("using in-memory store")
	}
	hsmProvider := hsm.NewSoftwareHSM()

	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interceptor.RecoveryUnary(),
			interceptor.LoggingUnary(),
			interceptor.RateLimitUnary(cfg.RateLimitRPS),
			interceptor.AuthUnary(cfg.AuthToken),
		),
		grpc.ChainStreamInterceptor(
			interceptor.RecoveryStream(),
			interceptor.LoggingStream(),
			interceptor.RateLimitStream(cfg.RateLimitRPS),
			interceptor.AuthStream(cfg.AuthToken),
		),
	)

	pb.RegisterKeyManagementServiceServer(srv, server.NewKeyManagementServer(store, hsmProvider, auditLogger))
	pb.RegisterSigningServiceServer(srv, server.NewSigningServer(store, hsmProvider, auditLogger))
	pb.RegisterEncryptionServiceServer(srv, server.NewEncryptionServer(store, auditLogger))
	pb.RegisterAuditServiceServer(srv, server.NewAuditServer(auditLogger))
	reflection.Register(srv)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		slog.Error("listen", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("server starting", "addr", cfg.GRPCAddr)
		if err := srv.Serve(lis); err != nil {
			slog.Error("serve", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	// Graceful shutdown with 10s timeout
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("shutdown complete")
	case <-time.After(10 * time.Second):
		slog.Warn("graceful shutdown timed out, forcing stop")
		srv.Stop()
	}
}
