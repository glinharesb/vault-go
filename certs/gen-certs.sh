#!/usr/bin/env bash
set -euo pipefail

# Generate self-signed TLS certificates for development.
# Produces: ca.pem, server.pem, server-key.pem

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -days 365 -nodes -keyout ca-key.pem -out ca.pem \
  -subj "/CN=vault-go CA" 2>/dev/null

# Server key + CSR
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -keyout server-key.pem -out server.csr \
  -subj "/CN=localhost" 2>/dev/null

# Sign server cert with CA
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out server.pem -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null

rm -f server.csr ca.srl

echo "Generated: ca.pem, server.pem, server-key.pem"
