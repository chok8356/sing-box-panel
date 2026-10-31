package singbox

import (
	"strings"
	"sync"
)

// MaxLogBytes is how much recent output TailLog keeps.
const MaxLogBytes = 64 << 10

// TailLog is an in-memory buffer that keeps the last MaxLogBytes written.
type TailLog struct {
	mu   sync.Mutex
	data []byte
}

func (l *TailLog) Write(value []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(value)
	if len(value) > MaxLogBytes {
		value = value[len(value)-MaxLogBytes:]
	}
	if excess := len(l.data) + len(value) - MaxLogBytes; excess > 0 {
		copy(l.data, l.data[excess:])
		l.data = l.data[:len(l.data)-excess]
	}
	l.data = append(l.data, value...)
	return n, nil
}

func (l *TailLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.ToValidUTF8(string(l.data), "�")
}
