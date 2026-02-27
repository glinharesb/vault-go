package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// Tests use logger.Close() to drain entries instead of time.Sleep,
// ensuring deterministic behavior with the race detector.

func TestLogAndQuery(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(100, &buf)

	logger.Log("GenerateKey", "key-1", "OK", "127.0.0.1:50051", nil)
	logger.Log("Sign", "key-1", "OK", "127.0.0.1:50051", nil)
	logger.Log("GenerateKey", "key-2", "OK", "127.0.0.1:50051", nil)

	// Close drains the channel and waits for the loop to finish.
	logger.Close()

	entries := logger.Query("key-1", "", time.Time{}, time.Time{}, 0)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries for key-1, got %d", len(entries))
	}

	entries = logger.Query("", "Sign", time.Time{}, time.Time{}, 0)
	if len(entries) != 1 {
		t.Fatalf("expected 1 Sign entry, got %d", len(entries))
	}

	// Safe to read buf now - processLoop has exited.
	if !strings.Contains(buf.String(), "GenerateKey") {
		t.Fatal("expected GenerateKey in output")
	}
}

func TestQueryLimit(t *testing.T) {
	logger := NewLogger(100, nil)

	for i := range 10 {
		logger.Log("Sign", "key-1", "OK", "", map[string]string{"i": string(rune('0' + i))})
	}
	logger.Close()

	entries := logger.Query("", "", time.Time{}, time.Time{}, 3)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
}

func TestSubscribeReceivesEntries(t *testing.T) {
	logger := NewLogger(100, nil)
	defer logger.Close()

	sub := logger.Subscribe()
	defer logger.Unsubscribe(sub)

	logger.Log("Sign", "key-1", "OK", "", nil)

	select {
	case entry := <-sub.C:
		if entry.Operation != "Sign" {
			t.Fatalf("expected Sign, got %s", entry.Operation)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive entry")
	}
}

func TestUnsubscribeClosesChannel(t *testing.T) {
	logger := NewLogger(100, nil)
	defer logger.Close()

	sub := logger.Subscribe()
	logger.Unsubscribe(sub)

	// Channel should be closed
	_, ok := <-sub.C
	if ok {
		t.Fatal("expected closed channel")
	}
}

func TestLogEntryHasID(t *testing.T) {
	logger := NewLogger(100, nil)

	logger.Log("Encrypt", "key-1", "OK", "", nil)
	logger.Close()

	entries := logger.Query("", "", time.Time{}, time.Time{}, 0)
	if len(entries) != 1 {
		t.Fatal("expected 1 entry")
	}
	if entries[0].ID == "" {
		t.Fatal("entry should have an ID")
	}
}
