package interceptor

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tokenBucket implements a simple token bucket rate limiter.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	rate     float64 // tokens per second
	lastTime time.Time
}

func newTokenBucket(rps int) *tokenBucket {
	return &tokenBucket{
		tokens:   float64(rps),
		max:      float64(rps),
		rate:     float64(rps),
		lastTime: time.Now(),
	}
}

func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastTime).Seconds()
	tb.lastTime = now

	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.max {
		tb.tokens = tb.max
	}

	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// RateLimitUnary returns a unary interceptor that enforces requests per second.
func RateLimitUnary(rps int) grpc.UnaryServerInterceptor {
	bucket := newTokenBucket(rps)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !bucket.allow() {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}

// RateLimitStream returns a stream interceptor that enforces requests per second.
func RateLimitStream(rps int) grpc.StreamServerInterceptor {
	bucket := newTokenBucket(rps)
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !bucket.allow() {
			return status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(srv, ss)
	}
}
