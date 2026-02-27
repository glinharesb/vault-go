package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Entry represents an audit log entry.
type Entry struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	Operation   string            `json:"operation"`
	KeyID       string            `json:"key_id,omitempty"`
	Status      string            `json:"status"`
	PeerAddress string            `json:"peer_address,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Subscriber receives audit entries via a channel.
type Subscriber struct {
	C  chan Entry
	id string
}

// Logger is an async audit logger that decouples the critical path from log writes.
type Logger struct {
	entries chan Entry
	out     io.Writer

	mu          sync.RWMutex
	subscribers map[string]*Subscriber
	store       []Entry

	done chan struct{}
}

// NewLogger creates a logger with the given buffer size and output writer.
func NewLogger(bufferSize int, out io.Writer) *Logger {
	l := &Logger{
		entries:     make(chan Entry, bufferSize),
		out:         out,
		subscribers: make(map[string]*Subscriber),
		done:        make(chan struct{}),
	}
	go l.processLoop()
	return l
}

// Log sends an entry to the async processing pipeline. Non-blocking if buffer has capacity.
func (l *Logger) Log(operation, keyID, status, peerAddr string, metadata map[string]string) {
	entry := Entry{
		ID:          uuid.NewString(),
		Timestamp:   time.Now(),
		Operation:   operation,
		KeyID:       keyID,
		Status:      status,
		PeerAddress: peerAddr,
		Metadata:    metadata,
	}

	select {
	case l.entries <- entry:
	default:
		slog.Warn("audit log buffer full, dropping entry", "operation", operation)
	}
}

// Subscribe creates a new subscriber that receives entries via a buffered channel.
func (l *Logger) Subscribe() *Subscriber {
	l.mu.Lock()
	defer l.mu.Unlock()

	sub := &Subscriber{
		C:  make(chan Entry, 64),
		id: uuid.NewString(),
	}
	l.subscribers[sub.id] = sub
	return sub
}

// Unsubscribe removes a subscriber.
func (l *Logger) Unsubscribe(sub *Subscriber) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.subscribers, sub.id)
	close(sub.C)
}

// Query returns stored audit entries matching the filter criteria.
func (l *Logger) Query(keyID, operation string, start, end time.Time, limit int) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var results []Entry
	for i := len(l.store) - 1; i >= 0; i-- {
		e := l.store[i]
		if keyID != "" && e.KeyID != keyID {
			continue
		}
		if operation != "" && e.Operation != operation {
			continue
		}
		if !start.IsZero() && e.Timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && e.Timestamp.After(end) {
			continue
		}
		results = append(results, e)
		if limit > 0 && len(results) >= limit {
			break
		}
	}
	return results
}

// Close stops the processing loop and waits for it to finish.
func (l *Logger) Close() {
	close(l.entries)
	<-l.done
}

func (l *Logger) processLoop() {
	defer close(l.done)

	for entry := range l.entries {
		// Store entry
		l.mu.Lock()
		l.store = append(l.store, entry)
		l.mu.Unlock()

		// Write to output
		if l.out != nil {
			data, err := json.Marshal(entry)
			if err != nil {
				slog.Error("audit marshal", "error", err)
				continue
			}
			fmt.Fprintf(l.out, "%s\n", data)
		}

		// Fan-out to subscribers (non-blocking)
		l.mu.RLock()
		for _, sub := range l.subscribers {
			select {
			case sub.C <- entry:
			default:
				// subscriber too slow, drop
			}
		}
		l.mu.RUnlock()
	}
}
