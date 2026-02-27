FROM golang:1.24-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /vault-server ./cmd/vault-server

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /vault-server /vault-server

EXPOSE 50051
ENTRYPOINT ["/vault-server"]
