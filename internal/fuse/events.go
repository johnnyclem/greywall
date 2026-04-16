// Package fuse implements an experimental FUSE passthrough layer for
// greywall. It is currently decoupled from the main sandbox pipeline and
// lives behind the `greywall fuse` subcommand.
package fuse

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Action describes the decision taken for a single filesystem operation.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionLog   Action = "log"
)

// Op is the short name used for each intercepted operation in events and rules.
type Op string

const (
	OpLookup  Op = "lookup"
	OpOpen    Op = "open"
	OpCreate  Op = "create"
	OpRead    Op = "read"
	OpWrite   Op = "write"
	OpUnlink  Op = "unlink"
	OpRmdir   Op = "rmdir"
	OpMkdir   Op = "mkdir"
	OpRename  Op = "rename"
	OpGetattr Op = "getattr"
)

// FsEvent is one observed filesystem operation. Events are emitted as
// newline-delimited JSON to the configured EventSink.
type FsEvent struct {
	Timestamp time.Time `json:"ts"`
	Op        Op        `json:"op"`
	Path      string    `json:"path"`
	Caller    string    `json:"caller,omitempty"`
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid,omitempty"`
	Comm      string    `json:"comm,omitempty"`
	Action    Action    `json:"action"`
	Rule      string    `json:"rule,omitempty"`
	Errno     string    `json:"errno,omitempty"`
}

// EventSink receives FsEvents from the FUSE hook layer. Implementations
// must be safe for concurrent use.
type EventSink interface {
	Emit(FsEvent)
}

// NoopSink discards all events. Useful for tests.
type NoopSink struct{}

func (NoopSink) Emit(FsEvent) {}

// ChannelSink buffers events on a channel. Useful for tests that assert
// a specific event was emitted.
type ChannelSink struct {
	Ch chan FsEvent
}

// NewChannelSink returns a ChannelSink with a buffered channel.
func NewChannelSink(buf int) *ChannelSink {
	return &ChannelSink{Ch: make(chan FsEvent, buf)}
}

// Emit sends to the channel, dropping if full.
func (s *ChannelSink) Emit(e FsEvent) {
	select {
	case s.Ch <- e:
	default:
	}
}

// StdoutSink writes one JSON object per line to an io.Writer.
type StdoutSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdoutSink wraps an io.Writer in a StdoutSink.
func NewStdoutSink(w io.Writer) *StdoutSink {
	return &StdoutSink{w: w}
}

// Emit writes the event as one JSON line. Write errors are silently
// ignored to keep the FUSE hook path simple; the sandboxed process
// should never be affected by logging failures.
func (s *StdoutSink) Emit(e FsEvent) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.w.Write(b)
	_, _ = s.w.Write([]byte{'\n'})
}
