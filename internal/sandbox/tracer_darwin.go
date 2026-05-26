//go:build darwin

package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// esloggerTailIdle is how long the tail loop waits at EOF before checking
// for new lines.
const esloggerTailIdle = 100 * time.Millisecond

// StreamingTracer tails an eslogger JSON log as it is written, classifies
// each event into an FsEvent, and pushes events into the supplied buffer.
// The PID set is tracked incrementally: it seeds with the root PID and
// adds child PIDs as fork events arrive. Events from PIDs that have not
// yet been observed as descendants are dropped.
//
// The zero value is not usable; construct with NewStreamingTracer.
type StreamingTracer struct {
	buf   *FsEventBuffer
	debug bool

	// onEvent is an optional sink invoked after each FsEvent is pushed
	// into the buffer. Used by --record-fs-verbose to surface live
	// activity on stderr without forcing extra plumbing through the
	// heartbeat path. May be nil.
	onEvent func(FsEvent)

	cancel context.CancelFunc
	done   chan struct{}
	stop   sync.Once

	pidMu  sync.Mutex
	pidSet map[int]bool
}

// NewStreamingTracer constructs a tracer that will push events into buf.
// buf must be non-nil.
func NewStreamingTracer(buf *FsEventBuffer, debug bool) *StreamingTracer {
	return &StreamingTracer{buf: buf, debug: debug}
}

// SetOnEvent installs a callback invoked once per FsEvent immediately
// after it is pushed into the buffer. Must be called before Start; the
// tracer reads the field under no lock during the tail loop. Passing nil
// disables the callback.
func (t *StreamingTracer) SetOnEvent(fn func(FsEvent)) {
	t.onEvent = fn
}

// Start begins tailing logPath in a background goroutine. rootPID seeds
// the PID set; only events from rootPID or one of its observed
// descendants are pushed into the buffer. Returns immediately; the
// tracer continues until Stop is called or ctx is canceled.
//
// Calling Start more than once on the same tracer returns an error.
func (t *StreamingTracer) Start(ctx context.Context, logPath string, rootPID int) error {
	if t.done != nil {
		return fmt.Errorf("tracer already started")
	}
	if t.buf == nil {
		return fmt.Errorf("tracer: nil event buffer")
	}

	f, err := os.Open(logPath) //nolint:gosec // log path supplied by sandbox manager (temp file)
	if err != nil {
		return fmt.Errorf("open eslogger log: %w", err)
	}

	t.pidSet = map[int]bool{}
	if rootPID > 0 {
		t.pidSet[rootPID] = true
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

	// individual eslogger JSON lines can be very large.
	reader := bufio.NewReaderSize(f, 4*1024*1024)
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
			pending.WriteString(chunk)
		} else if len(chunk) > 0 {
			pending.WriteString(chunk)
			line := strings.TrimRight(pending.String(), "\n")
			pending.Reset()
			t.handleLine(line)
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
		select {
		case <-ctx.Done():
			t.flushPending(reader, &pending)
			return
		case <-time.After(esloggerTailIdle):
		}
	}
}

func (t *StreamingTracer) flushPending(r *bufio.Reader, pending *strings.Builder) {
	for {
		chunk, err := r.ReadString('\n')
		if len(chunk) > 0 {
			pending.WriteString(chunk)
		}
		if strings.HasSuffix(pending.String(), "\n") {
			line := strings.TrimRight(pending.String(), "\n")
			pending.Reset()
			t.handleLine(line)
		}
		if err != nil {
			break
		}
	}
	if pending.Len() > 0 {
		line := strings.TrimRight(pending.String(), "\n")
		pending.Reset()
		t.handleLine(line)
	}
}

// handleLine parses a single eslogger JSON event, applies the incremental
// PID tracking, and pushes any matching filesystem events into the buffer.
func (t *StreamingTracer) handleLine(line string) {
	if line == "" {
		return
	}

	var ev esloggerEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		return
	}

	name := eventName(&ev)
	pid := ev.Process.AuditToken.PID

	if name == "fork" {
		t.handleFork(pid, ev.Event["fork"])
		return
	}

	if !t.pidTracked(pid) {
		return
	}

	// process.executable.path on the event itself is the binary the PID
	// was running when ES dispatched it. For ordinary file ops this is
	// the process's current binary; for an exec event this is the PRE-
	// exec binary (the post-exec path goes on the FsEvent.Path field
	// emitted by the classifier). Stamping every event with it lets
	// the dashboard answer "which binary did this read?" without an
	// auxiliary PID->exe map.
	exe := ""
	if !ev.Process.Executable.PathTruncated {
		exe = ev.Process.Executable.Path
	}
	for _, fsEvent := range classifyEsloggerStreamingEvent(&ev, name) {
		fsEvent.PID = pid
		fsEvent.Ts = nowTs()
		fsEvent.Exe = exe
		t.buf.Push(fsEvent)
		if t.onEvent != nil {
			t.onEvent(fsEvent)
		}
	}
}

// handleFork adds the child PID to the tracked set if the parent is
// already tracked. PIDs are never pruned — short-lived children may
// still emit relevant events shortly before the kernel notifies us of
// their exit.
func (t *StreamingTracer) handleFork(parentPID int, forkRaw json.RawMessage) {
	if !t.pidTracked(parentPID) {
		return
	}
	var fe esloggerForkEvent
	if err := json.Unmarshal(forkRaw, &fe); err != nil {
		return
	}
	child := fe.Child.AuditToken.PID
	if child <= 0 {
		return
	}
	t.pidMu.Lock()
	t.pidSet[child] = true
	t.pidMu.Unlock()
}

func (t *StreamingTracer) pidTracked(pid int) bool {
	t.pidMu.Lock()
	defer t.pidMu.Unlock()
	return t.pidSet[pid]
}

// classifyEsloggerStreamingEvent classifies an eslogger event into zero or
// more FsEvents. The Ts and PID fields are populated by the caller.
func classifyEsloggerStreamingEvent(ev *esloggerEvent, name string) []FsEvent {
	eventRaw, ok := ev.Event[name]
	if !ok {
		return nil
	}

	switch name {
	case "open":
		var oe esloggerOpenEvent
		if err := json.Unmarshal(eventRaw, &oe); err != nil {
			return nil
		}
		path := oe.File.Path
		if path == "" || oe.File.PathTruncated {
			return nil
		}
		if oe.Fflag&fwriteFlag != 0 {
			return []FsEvent{{Op: "open_write", Path: path}}
		}
		return []FsEvent{{Op: "open_read", Path: path}}

	case "create":
		var ce esloggerCreateEvent
		if err := json.Unmarshal(eventRaw, &ce); err != nil {
			return nil
		}
		if ce.Destination.ExistingFile != nil {
			path := ce.Destination.ExistingFile.Path
			if path != "" && !ce.Destination.ExistingFile.PathTruncated {
				return []FsEvent{{Op: "create", Path: path}}
			}
		}
		if ce.Destination.NewPath != nil {
			dir := ce.Destination.NewPath.Dir.Path
			filename := ce.Destination.NewPath.Filename
			if dir != "" && filename != "" {
				return []FsEvent{{Op: "create", Path: dir + "/" + filename}}
			}
		}
		return nil

	case "write", "truncate":
		var te esloggerTargetEvent
		if err := json.Unmarshal(eventRaw, &te); err != nil {
			return nil
		}
		path := te.Target.Path
		if path == "" || te.Target.PathTruncated {
			return nil
		}
		return []FsEvent{{Op: "open_write", Path: path}}

	case "unlink":
		var te esloggerTargetEvent
		if err := json.Unmarshal(eventRaw, &te); err != nil {
			return nil
		}
		path := te.Target.Path
		if path == "" || te.Target.PathTruncated {
			return nil
		}
		return []FsEvent{{Op: "unlink", Path: path}}

	case "rename":
		var re esloggerRenameEvent
		if err := json.Unmarshal(eventRaw, &re); err != nil {
			return nil
		}
		var src, dst string
		if re.Source.Path != "" && !re.Source.PathTruncated {
			src = re.Source.Path
		}
		if re.Destination.Path != "" && !re.Destination.PathTruncated {
			dst = re.Destination.Path
		}
		if src == "" && dst == "" {
			return nil
		}
		return []FsEvent{{Op: "rename", Path: src, Path2: dst}}

	case "link":
		var le esloggerLinkEvent
		if err := json.Unmarshal(eventRaw, &le); err != nil {
			return nil
		}
		var src, dst string
		if le.Source.Path != "" && !le.Source.PathTruncated {
			src = le.Source.Path
		}
		if le.TargetDir.Path != "" && !le.TargetDir.PathTruncated {
			dst = le.TargetDir.Path
		}
		if src == "" && dst == "" {
			return nil
		}
		return []FsEvent{{Op: "link", Path: src, Path2: dst}}

	case "exec":
		// A process swapped its binary. PID stays the same; only the
		// executable image changes. Surface this as an FsEvent in the
		// same stream as opens/writes so the dashboard timeline shows
		// the transition inline ("PID N became /usr/bin/osascript")
		// right before the new binary's first reads. Without this an
		// operator looking at activity attributed to a tracked PID has
		// no way to know the running program is no longer what they
		// think it is.
		var ee esloggerExecEvent
		if err := json.Unmarshal(eventRaw, &ee); err != nil {
			return nil
		}
		path := ee.Target.Executable.Path
		if path == "" || ee.Target.Executable.PathTruncated {
			return nil
		}
		return []FsEvent{{Op: "exec", Path: path}}
	}

	return nil
}
