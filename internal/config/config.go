package config

import (
	"os"
	"strconv"
)

type Config struct {
	GRPCAddr      string
	TLSCert       string
	TLSKey        string
	AuthToken     string
	AuditBuffer   int
	RateLimitRPS  int
	DataDir       string
}

func Load() Config {
	return Config{
		GRPCAddr:     envOr("VAULT_GRPC_ADDR", ":50051"),
		TLSCert:      os.Getenv("VAULT_TLS_CERT"),
		TLSKey:       os.Getenv("VAULT_TLS_KEY"),
		AuthToken:    envOr("VAULT_AUTH_TOKEN", "dev-token"),
		AuditBuffer:  envInt("VAULT_AUDIT_BUFFER", 1024),
		RateLimitRPS: envInt("VAULT_RATE_LIMIT_RPS", 100),
		DataDir:      envOr("VAULT_DATA_DIR", ""),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
