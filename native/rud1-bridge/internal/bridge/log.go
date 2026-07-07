package bridge

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Logger sinks structured events the desktop manager scrapes from stderr.
type Logger interface {
	// Event must be goroutine-safe — pump goroutines call it without locking.
	Event(name string, fields map[string]any)
}

// JSONLogger writes one JSON object per line. Records carry `ts`,
// `event`, plus caller fields.
type JSONLogger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStderrLogger writes to stderr. Stdout is reserved for the "ready" line.
func NewStderrLogger() *JSONLogger {
	return &JSONLogger{w: os.Stderr}
}

func (l *JSONLogger) Event(name string, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any, 2)
	}
	fields["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["event"] = name
	buf, err := json.Marshal(fields)
	if err != nil {
		buf = []byte(`{"event":"log.marshal.error"}`)
	}
	buf = append(buf, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(buf)
}

// NoopLogger discards every event. Used when Config.Logger is nil.
type NoopLogger struct{}

func (NoopLogger) Event(_ string, _ map[string]any) {}
