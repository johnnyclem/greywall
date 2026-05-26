//go:build darwin

package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// makeEsloggerLine is defined in learning_darwin_test.go and reused here.
// Signature: makeEsloggerLine(eventName, eventTypeInt, pid, eventData) string.
// eslogger event_type ints (from comments in learning_darwin.go):
// 10=open, 11=fork, 13=create, 32=unlink, 33=write, 41=truncate.

func TestClassifyEsloggerStreamingEvent_OpenRead(t *testing.T) {
	ev := esloggerEvent{Event: map[string]json.RawMessage{
		"open": json.RawMessage(`{"file":{"path":"/etc/hosts"},"fflag":1}`),
	}}
	events := classifyEsloggerStreamingEvent(&ev, "open")
	if len(events) != 1 || events[0].Op != "open_read" || events[0].Path != "/etc/hosts" {
		t.Errorf("got %+v", events)
	}
}

func TestClassifyEsloggerStreamingEvent_OpenWrite(t *testing.T) {
	// fflag with FWRITE (0x0002) bit set.
	ev := esloggerEvent{Event: map[string]json.RawMessage{
		"open": json.RawMessage(`{"file":{"path":"/tmp/out"},"fflag":2}`),
	}}
	events := classifyEsloggerStreamingEvent(&ev, "open")
	if len(events) != 1 || events[0].Op != "open_write" || events[0].Path != "/tmp/out" {
		t.Errorf("got %+v", events)
	}
}

func TestClassifyEsloggerStreamingEvent_OpenTruncatedSkipped(t *testing.T) {
	ev := esloggerEvent{Event: map[string]json.RawMessage{
		"open": json.RawMessage(`{"file":{"path":"/x","path_truncated":true},"fflag":1}`),
	}}
	if events := classifyEsloggerStreamingEvent(&ev, "open"); len(events) != 0 {
		t.Errorf("expected no events, got %+v", events)
	}
}

func TestClassifyEsloggerStreamingEvent_CreateExisting(t *testing.T) {
	ev := esloggerEvent{Event: map[string]json.RawMessage{
		"create": json.RawMessage(`{"destination":{"existing_file":{"path":"/p/existing"}}}`),
	}}
	events := classifyEsloggerStreamingEvent(&ev, "create")
	if len(events) != 1 || events[0].Op != "create" || events[0].Path != "/p/existing" {
		t.Errorf("got %+v", events)
	}
}

func TestClassifyEsloggerStreamingEvent_CreateNewPath(t *testing.T) {
	ev := esloggerEvent{Event: map[string]json.RawMessage{
		"create": json.RawMessage(`{"destination":{"new_path":{"dir":{"path":"/p"},"filename":"f"}}}`),
	}}
	events := classifyEsloggerStreamingEvent(&ev, "create")
	if len(events) != 1 || events[0].Op != "create" || events[0].Path != "/p/f" {
		t.Errorf("got %+v", events)
	}
}

func TestClassifyEsloggerStreamingEvent_Write(t *testing.T) {
	ev := esloggerEvent{Event: map[string]json.RawMessage{
		"write": json.RawMessage(`{"target":{"path":"/p/file"}}`),
	}}
	events := classifyEsloggerStreamingEvent(&ev, "write")
	if len(events) != 1 || events[0].Op != "open_write" || events[0].Path != "/p/file" {
		t.Errorf("got %+v", events)
	}
}

func TestClassifyEsloggerStreamingEvent_Unlink(t *testing.T) {
	ev := esloggerEvent{Event: map[string]json.RawMessage{
		"unlink": json.RawMessage(`{"target":{"path":"/p/gone"}}`),
	}}
	events := classifyEsloggerStreamingEvent(&ev, "unlink")
	if len(events) != 1 || events[0].Op != "unlink" || events[0].Path != "/p/gone" {
		t.Errorf("got %+v", events)
	}
}

func TestClassifyEsloggerStreamingEvent_Rename(t *testing.T) {
	ev := esloggerEvent{Event: map[string]json.RawMessage{
		"rename": json.RawMessage(`{"source":{"path":"/a"},"destination_new_path":{"path":"/b"}}`),
	}}
	events := classifyEsloggerStreamingEvent(&ev, "rename")
	if len(events) != 1 || events[0].Op != "rename" || events[0].Path != "/a" || events[0].Path2 != "/b" {
		t.Errorf("got %+v", events)
	}
}

func TestClassifyEsloggerStreamingEvent_Link(t *testing.T) {
	ev := esloggerEvent{Event: map[string]json.RawMessage{
		"link": json.RawMessage(`{"source":{"path":"/a"},"target_dir":{"path":"/b"}}`),
	}}
	events := classifyEsloggerStreamingEvent(&ev, "link")
	if len(events) != 1 || events[0].Op != "link" || events[0].Path != "/a" || events[0].Path2 != "/b" {
		t.Errorf("got %+v", events)
	}
}

func TestClassifyEsloggerStreamingEvent_UnknownEvent(t *testing.T) {
	ev := esloggerEvent{Event: map[string]json.RawMessage{
		"exec": json.RawMessage(`{}`),
	}}
	if events := classifyEsloggerStreamingEvent(&ev, "exec"); len(events) != 0 {
		t.Errorf("expected no events for unknown type, got %+v", events)
	}
}

// TestStreamingTracer_PIDFiltering verifies that events from PIDs not in the
// root's process tree are dropped, while events from the root or from
// children added via fork are kept.
func TestStreamingTracer_PIDFiltering(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "eslogger.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	buf := NewFsEventBuffer(32)
	tracer := NewStreamingTracer(buf, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tracer.Start(ctx, logPath, 100); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tracer.Stop()

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	writeLine := func(line string) {
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}

	// Event from the root PID (100): should be kept.
	writeLine(makeEsloggerLine("open", 10, 100,
		map[string]any{"file": map[string]any{"path": "/root/file"}, "fflag": 1}))

	// Event from an unknown PID (999): should be dropped.
	writeLine(makeEsloggerLine("open", 10, 999,
		map[string]any{"file": map[string]any{"path": "/unknown/file"}, "fflag": 1}))

	// Fork: root (100) -> child (200).
	writeLine(makeEsloggerLine("fork", 11, 100,
		map[string]any{"child": map[string]any{
			"audit_token": map[string]int{"pid": 200},
			"executable":  map[string]any{"path": "/bin/sh"},
			"ppid":        100,
		}}))

	// Event from the new child PID (200): should now be kept.
	writeLine(makeEsloggerLine("open", 10, 200,
		map[string]any{"file": map[string]any{"path": "/child/file"}, "fflag": 1}))

	// Event from an unrelated PID (888): still dropped.
	writeLine(makeEsloggerLine("open", 10, 888,
		map[string]any{"file": map[string]any{"path": "/other/file"}, "fflag": 1}))

	_ = f.Sync()

	if !waitForLen(buf, 2, 2*time.Second) {
		t.Fatalf("timed out waiting for events; buffer has %d", buf.Len())
	}
	// Give the tracer a moment to process the unrelated PID line as well,
	// so we can be sure it would have shown up if filtering were broken.
	time.Sleep(150 * time.Millisecond)

	events, _ := buf.Drain()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d: %+v", len(events), events)
	}
	wantPaths := []string{"/root/file", "/child/file"}
	wantPIDs := []int{100, 200}
	for i, e := range events {
		if e.Path != wantPaths[i] {
			t.Errorf("event[%d].Path = %q, want %q", i, e.Path, wantPaths[i])
		}
		if e.PID != wantPIDs[i] {
			t.Errorf("event[%d].PID = %d, want %d", i, e.PID, wantPIDs[i])
		}
	}
}

func TestStreamingTracer_StopBeforeStart(t *testing.T) {
	tracer := NewStreamingTracer(NewFsEventBuffer(8), false)
	tracer.Stop()
}

// TestStreamingTracer_OnEventCallback verifies that an installed OnEvent
// fires once per pushed FsEvent, in order, with the same payload that
// landed in the buffer. This is the contract --record-fs-verbose relies
// on to stream a live transcript to stderr.
func TestStreamingTracer_OnEventCallback(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "eslogger.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	buf := NewFsEventBuffer(16)
	tracer := NewStreamingTracer(buf, false)

	var mu sync.Mutex
	var seen []FsEvent
	tracer.SetOnEvent(func(e FsEvent) {
		mu.Lock()
		seen = append(seen, e)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tracer.Start(ctx, logPath, 42); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tracer.Stop()

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	writeLine := func(line string) {
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}

	writeLine(makeEsloggerLine("open", 10, 42,
		map[string]any{"file": map[string]any{"path": "/a"}, "fflag": 1}))
	writeLine(makeEsloggerLine("open", 10, 42,
		map[string]any{"file": map[string]any{"path": "/b"}, "fflag": 2}))
	writeLine(makeEsloggerLine("unlink", 32, 42,
		map[string]any{"target": map[string]any{"path": "/c"}}))
	_ = f.Sync()

	if !waitForLen(buf, 3, 2*time.Second) {
		t.Fatalf("timed out; buffer has %d", buf.Len())
	}
	// Drain the buffer to read what was Pushed and compare against what
	// OnEvent observed; the two transcripts must match.
	pushed, _ := buf.Drain()

	// Allow the callback goroutine a moment to flush the last event;
	// waitForLen guarantees the third Push happened, and OnEvent fires
	// synchronously right after, but read under the lock to be safe.
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(pushed) {
		t.Fatalf("len(seen)=%d, len(pushed)=%d", len(seen), len(pushed))
	}
	for i := range pushed {
		if seen[i].Op != pushed[i].Op || seen[i].Path != pushed[i].Path || seen[i].PID != pushed[i].PID {
			t.Errorf("event %d: seen=%+v pushed=%+v", i, seen[i], pushed[i])
		}
	}
	// Spot-check op coverage.
	wantOps := []string{"open_read", "open_write", "unlink"}
	for i, op := range wantOps {
		if seen[i].Op != op {
			t.Errorf("seen[%d].Op = %q, want %q", i, seen[i].Op, op)
		}
	}
}

func TestStreamingTracer_DoubleStart(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "eslogger.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tracer := NewStreamingTracer(NewFsEventBuffer(8), false)
	ctx := context.Background()
	if err := tracer.Start(ctx, logPath, 100); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer tracer.Stop()
	if err := tracer.Start(ctx, logPath, 100); err == nil {
		t.Errorf("expected error on second Start")
	}
}

// waitForLen polls buf.Len() until it reaches target or timeout elapses.
func waitForLen(buf *FsEventBuffer, target int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if buf.Len() >= target {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return buf.Len() >= target
}
