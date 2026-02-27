# vault-go

A gRPC service for cryptographic key management, digital signing, and authenticated encryption. Designed as a Root of Trust backend for card and POS payment systems.

Built with Go standard library crypto primitives. No external key management dependencies.

## Architecture

```
                   +-------------------+
                   |      Client       |
                   +--------+----------+
                            |
                            | gRPC (:50051)
                            v
                   +-------------------+
                   |   Interceptors    |
                   | Recovery > Log >  |
                   | RateLimit > Auth  |
                   +--------+----------+
                            |
            +-------+-------+-------+--------+
            |       |               |        |
            v       v               v        v
        KeyMgmt  Signing      Encryption   Audit
            |       |               |        |
            +---+---+-------+-------+        |
                |           |                |
                v           v                v
           +----------+ +--------+    +------------+
           | KeyStore | | HSM    |    | Audit Log  |
           | mem/disk | | SW/HW  |    | async chan  |
           +----------+ +--------+    +------------+
```

### Services

| Service | RPCs |
|---------|------|
| **KeyManagement** | GenerateKey, GetPublicKey, ListKeys, RotateKey, DeactivateKey, WatchKeyEvents (stream) |
| **Signing** | Sign, Verify, BatchSign (worker pool), StreamSign (bidirectional) |
| **Encryption** | Encrypt, Decrypt (AES-256-GCM + AAD), DeriveKey (HKDF) |
| **Audit** | QueryAudit, StreamAudit (stream) |

### Crypto

- **ECDSA** P-256/P-384 for key generation and signing
- **AES-256-GCM** with random nonce for authenticated encryption
- **HKDF-SHA256** for key derivation from root keys

### Concurrency

- `sync.RWMutex` on key store (concurrent reads, exclusive writes)
- Worker pool for BatchSign (bounded by `runtime.NumCPU()`)
- Fan-out to streaming subscribers via buffered channels
- Async audit logger decoupled from request path
- Graceful shutdown with `signal.NotifyContext` + timeout

## Getting Started

### Prerequisites

- Go 1.24+
- protoc with `protoc-gen-go` and `protoc-gen-go-grpc`
- grpcurl (for manual testing)

### Build and Run

```bash
make build
./bin/vault-server
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_GRPC_ADDR` | `:50051` | Listen address |
| `VAULT_AUTH_TOKEN` | `dev-token` | Bearer token for auth |
| `VAULT_DATA_DIR` | (empty) | Set to enable persistent key storage |
| `VAULT_RATE_LIMIT_RPS` | `100` | Requests per second limit |
| `VAULT_AUDIT_BUFFER` | `1024` | Audit log channel buffer size |
| `VAULT_TLS_CERT` | (empty) | TLS certificate path |
| `VAULT_TLS_KEY` | (empty) | TLS key path |

### Docker

```bash
make docker
docker compose up
```

## Usage

All RPCs require a bearer token in the `authorization` metadata header.

### Generate a key

```bash
grpcurl -plaintext \
  -H "authorization: Bearer dev-token" \
  -d '{"algorithm": 1}' \
  localhost:50051 vault.v1.KeyManagementService/GenerateKey
```

### Sign and verify

```bash
# Sign (data is base64-encoded)
grpcurl -plaintext \
  -H "authorization: Bearer dev-token" \
  -d '{"key_id": "<KEY_ID>", "data": "aGVsbG8gd29ybGQ="}' \
  localhost:50051 vault.v1.SigningService/Sign

# Verify
grpcurl -plaintext \
  -H "authorization: Bearer dev-token" \
  -d '{"key_id": "<KEY_ID>", "data": "aGVsbG8gd29ybGQ=", "signature": "<SIG>"}' \
  localhost:50051 vault.v1.SigningService/Verify
```

### Encrypt and decrypt

```bash
grpcurl -plaintext \
  -H "authorization: Bearer dev-token" \
  -d '{"key_id": "<KEY_ID>", "plaintext": "c2VjcmV0", "aad": "Y29udGV4dA=="}' \
  localhost:50051 vault.v1.EncryptionService/Encrypt
```

### Derive a key (HKDF)

```bash
grpcurl -plaintext \
  -H "authorization: Bearer dev-token" \
  -d '{"root_key_id": "<KEY_ID>", "context": "dHhuLWtleQ==", "length": 32}' \
  localhost:50051 vault.v1.EncryptionService/DeriveKey
```

### Rotate a key

```bash
grpcurl -plaintext \
  -H "authorization: Bearer dev-token" \
  -d '{"key_id": "<KEY_ID>"}' \
  localhost:50051 vault.v1.KeyManagementService/RotateKey
```

### List keys

```bash
grpcurl -plaintext \
  -H "authorization: Bearer dev-token" \
  localhost:50051 vault.v1.KeyManagementService/ListKeys
```

## Testing

```bash
make test          # all tests with race detector
make bench         # crypto benchmarks
make test-cover    # generate coverage report
```

## Project Structure

```
cmd/vault-server/    entrypoint and wiring
internal/crypto/     ECDSA, AES-GCM, HKDF primitives
internal/keystore/   key storage (memory + persistent)
internal/hsm/        HSM provider interface
internal/audit/      async structured audit logger
internal/interceptor/ gRPC interceptors
internal/server/     gRPC service implementations
proto/vault/v1/      protobuf definitions
gen/vault/v1/        generated Go code
```
