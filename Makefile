.PHONY: build test proto clean docker lint

BIN_DIR := bin
BINARY := $(BIN_DIR)/vault-server

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BINARY) ./cmd/vault-server

test:
	go test -race -v ./...

test-short:
	go test -race -short ./...

test-cover:
	go test -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html

bench:
	go test -bench=. -benchmem ./internal/crypto/...

proto:
	@find gen -name '*.go' -delete 2>/dev/null || true
	protoc \
		--go_out=. --go_opt=module=github.com/glinharesb/vault-go \
		--go-grpc_out=. --go-grpc_opt=module=github.com/glinharesb/vault-go \
		-I proto \
		proto/vault/v1/*.proto

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BIN_DIR) coverage.txt coverage.html

docker:
	docker build -f docker/Dockerfile -t vault-go:latest .

certs:
	cd certs && bash gen-certs.sh

run: build
	$(BINARY)
