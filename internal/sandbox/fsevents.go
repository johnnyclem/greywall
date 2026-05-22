package sandbox

import (
	"sync"
	"time"
)

// nowTs returns the current time as an RFC3339Nano-formatted UTC string.
func nowTs() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// FsEvent is a single filesystem operation observed inside the sandbox.
type FsEvent struct {
	Ts    string `json:"ts"`              // RFC3339Nano timestamp
	Op    string `json:"op"`              // open_read|open_write|create|unlink|rename|symlink|link|mkdir
	Path  string `json:"path"`            // absolute path of the primary target
	Path2 string `json:"path2,omitempty"` // destination path for rename/link ops
	PID   int    `json:"pid,omitempty"`
	Errno int    `json:"errno,omitempty"`
}

// FsEventBuffer is a bounded ring buffer of FsEvents. When full, Push
// overwrites the oldest entry and increments a dropped counter. Safe for
// concurrent use by a single producer and a single consumer.
type FsEventBuffer struct {
	mu      sync.Mutex
	buf     []FsEvent
	head    int    // index of the oldest live entry
	size    int    // number of live entries (0..cap)
	cap     int    // ring capacity (>0)
	dropped uint64 // events dropped since the last Drain
}

// NewFsEventBuffer constructs a buffer with the given capacity. A capacity
// of zero or negative is clamped to 1.
func NewFsEventBuffer(capacity int) *FsEventBuffer {
	if capacity <= 0 {
		capacity = 1
	}
	return &FsEventBuffer{
		buf: make([]FsEvent, capacity),
		cap: capacity,
	}
}

// Push appends an event. When the buffer is full, the oldest entry is
// overwritten and the dropped counter advances by one.
func (b *FsEventBuffer) Push(e FsEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.size < b.cap {
		b.buf[(b.head+b.size)%b.cap] = e
		b.size++
		return
	}
	b.buf[b.head] = e
	b.head = (b.head + 1) % b.cap
	b.dropped++
}

// Drain returns all queued events in FIFO order along with the number of
// events that were dropped since the previous Drain, then resets the
// buffer. Returns (nil, 0) when there is nothing to report.
func (b *FsEventBuffer) Drain() ([]FsEvent, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.size == 0 && b.dropped == 0 {
		return nil, 0
	}

	out := make([]FsEvent, b.size)
	for i := 0; i < b.size; i++ {
		out[i] = b.buf[(b.head+i)%b.cap]
	}
	dropped := b.dropped
	b.head = 0
	b.size = 0
	b.dropped = 0
	return out, dropped
}

// Len returns the current number of queued events.
func (b *FsEventBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.size
}

// Dropped returns the number of events dropped since the last Drain
// without consuming or resetting the counter.
func (b *FsEventBuffer) Dropped() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}
