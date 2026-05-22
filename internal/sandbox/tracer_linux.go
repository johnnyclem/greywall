//go:build linux

package sandbox

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// straceTailIdle is how long the tail loop waits at EOF before checking
// for new data.
const straceTailIdle = 100 * time.Millisecond

// StreamingTracer tails a strace log file as it is being written, classifies
// each line into an FsEvent, and pushes events into the supplied buffer. It
// runs until Stop is called or the context is canceled.
//
// The zero value is not usable; construct with NewStreamingTracer.
type StreamingTracer struct {
	buf   *FsEventBuffer
	debug bool

	cancel context.CancelFunc
	done   chan struct{}
	stop   sync.Once
}

// NewStreamingTracer constructs a tracer that will push events into buf.
// buf must be non-nil.
func NewStreamingTracer(buf *FsEventBuffer, debug bool) *StreamingTracer {
	return &StreamingTracer{buf: buf, debug: debug}
}

// Start begins tailing logPath in a background goroutine. It returns
// immediately; the tracer continues until Stop is called or ctx is
// canceled. rootPID is unused on Linux (strace already scopes itself to
// the traced process tree via -f).
//
// Calling Start more than once on the same tracer returns an error.
func (t *StreamingTracer) Start(ctx context.Context, logPath string, rootPID int) error {
	_ = rootPID
	if t.done != nil {
		return fmt.Errorf("tracer already started")
	}
	if t.buf == nil {
		return fmt.Errorf("tracer: nil event buffer")
	}

	f, err := os.Open(logPath) //nolint:gosec // log path supplied by sandbox manager (temp file)
	if err != nil {
		return fmt.Errorf("open strace log: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	t.cancel = cancel
	t.done = make(chan struct{})

	go t.tailLoop(ctx, f)
	return nil
}

// Stop signals the tracer to finish and blocks until it exits. Safe to
// call multiple times; safe to call before Start (no-op).
func (t *StreamingTracer) Stop() {
	if t.done == nil {
		return
	}
	t.stop.Do(func() {
		t.cancel()
		<-t.done
	})
}

func (t *StreamingTracer) tailLoop(ctx context.Context, f *os.File) {
	defer close(t.done)
	defer func() { _ = f.Close() }()

	// strace lines can occasionally be very long.
	reader := bufio.NewReaderSize(f, 1024*1024)
	var pending strings.Builder

	for {
		select {
		case <-ctx.Done():
			t.flushPending(reader, &pending)
			return
		default:
		}

		chunk, err := reader.ReadString('\n')
		if len(chunk) > 0 && !strings.HasSuffix(chunk, "\n") {
			// Partial line: strace hasn't finished writing it yet.
			pending.WriteString(chunk)
		} else if len(chunk) > 0 {
			pending.WriteString(chunk)
			line := strings.TrimRight(pending.String(), "\n")
			pending.Reset()
			t.classifyAndPush(line)
		}

		if err == nil {
			continue
		}
		if err != io.EOF {
			if t.debug {
				fmt.Fprintf(os.Stderr, "[greywall:tracer] read error: %v\n", err)
			}
			return
		}
		// EOF: wait for more data or cancellation.
		select {
		case <-ctx.Done():
			t.flushPending(reader, &pending)
			return
		case <-time.After(straceTailIdle):
		}
	}
}

// flushPending drains any remaining bytes from the reader on shutdown.
// strace may have written a final incomplete line that we still want to
// classify.
func (t *StreamingTracer) flushPending(r *bufio.Reader, pending *strings.Builder) {
	for {
		chunk, err := r.ReadString('\n')
		if len(chunk) > 0 {
			pending.WriteString(chunk)
		}
		if strings.HasSuffix(pending.String(), "\n") {
			line := strings.TrimRight(pending.String(), "\n")
			pending.Reset()
			t.classifyAndPush(line)
		}
		if err != nil {
			break
		}
	}
	if pending.Len() > 0 {
		line := strings.TrimRight(pending.String(), "\n")
		pending.Reset()
		t.classifyAndPush(line)
	}
}

func (t *StreamingTracer) classifyAndPush(line string) {
	if event, ok := classifyStraceLine(line); ok {
		t.buf.Push(event)
	}
}

// classifyStraceLine inspects a single strace line and returns an FsEvent
// describing the operation. Returns (FsEvent{}, false) when the line does
// not match a tracked syscall, is a failed call, or is a resumed/unfinished
// continuation that the next line will complete.
func classifyStraceLine(line string) (FsEvent, bool) {
	if !straceSyscallRegex.MatchString(line) {
		return FsEvent{}, false
	}
	if strings.Contains(line, "= -1 ") {
		return FsEvent{}, false
	}
	if strings.Contains(line, "<unfinished") || strings.Contains(line, "resumed>") {
		return FsEvent{}, false
	}

	pid := extractStracePID(line)

	switch {
	case strings.Contains(line, "openat("):
		path := extractATPath(line)
		if path == "" {
			return FsEvent{}, false
		}
		if openatWriteFlags.MatchString(line) {
			return FsEvent{Ts: nowTs(), Op: "open_write", Path: path, PID: pid}, true
		}
		if strings.Contains(line, "O_DIRECTORY") {
			return FsEvent{}, false
		}
		return FsEvent{Ts: nowTs(), Op: "open_read", Path: path, PID: pid}, true

	case strings.Contains(line, "mkdirat("):
		path := extractATPath(line)
		if path == "" {
			return FsEvent{}, false
		}
		return FsEvent{Ts: nowTs(), Op: "mkdir", Path: path, PID: pid}, true

	case strings.Contains(line, "unlinkat("):
		path := extractATPath(line)
		if path == "" {
			return FsEvent{}, false
		}
		return FsEvent{Ts: nowTs(), Op: "unlink", Path: path, PID: pid}, true

	case strings.Contains(line, "renameat2("):
		src, dst := extractRenamePaths(line)
		if src == "" && dst == "" {
			return FsEvent{}, false
		}
		return FsEvent{Ts: nowTs(), Op: "rename", Path: src, Path2: dst, PID: pid}, true

	case strings.Contains(line, "creat("):
		path := extractCreatPath(line)
		if path == "" {
			return FsEvent{}, false
		}
		return FsEvent{Ts: nowTs(), Op: "create", Path: path, PID: pid}, true

	case strings.Contains(line, "symlinkat("):
		path := extractATPath(line)
		if path == "" {
			return FsEvent{}, false
		}
		return FsEvent{Ts: nowTs(), Op: "symlink", Path: path, PID: pid}, true

	case strings.Contains(line, "linkat("):
		src, dst := extractRenamePaths(line)
		if src == "" && dst == "" {
			return FsEvent{}, false
		}
		return FsEvent{Ts: nowTs(), Op: "link", Path: src, Path2: dst, PID: pid}, true
	}

	return FsEvent{}, false
}

// extractRenamePaths returns both quoted paths from a renameat2/linkat line.
// Pattern: syscall(AT_FDCWD, "/src", AT_FDCWD, "/dst", flags). Returns ("","")
// if neither path can be located.
func extractRenamePaths(line string) (string, string) {
	first := strings.Index(line, "AT_FDCWD, \"")
	if first < 0 {
		return "", ""
	}
	rest := line[first+len("AT_FDCWD, \""):]
	endFirst := strings.Index(rest, "\"")
	if endFirst < 0 {
		return "", ""
	}
	src := rest[:endFirst]
	rest = rest[endFirst+1:]

	second := strings.Index(rest, "AT_FDCWD, \"")
	if second < 0 {
		return src, ""
	}
	rest = rest[second+len("AT_FDCWD, \""):]
	endSecond := strings.Index(rest, "\"")
	if endSecond < 0 {
		return src, ""
	}
	return src, rest[:endSecond]
}

// extractStracePID returns the PID prefix that strace prepends to each
// line when called with -f (follow forks). Returns 0 if no PID prefix is
// present, which can happen for the root process before any fork.
func extractStracePID(line string) int {
	// Strace -f prefixes lines with the PID followed by whitespace, e.g.
	// "12345 openat(...)". We only consider a leading run of digits.
	pid := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c < '0' || c > '9' {
			if i == 0 {
				return 0
			}
			return pid
		}
		pid = pid*10 + int(c-'0')
	}
	return pid
}

