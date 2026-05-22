//go:build linux

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClassifyStraceLine_OpenRead(t *testing.T) {
	line := `12345 openat(AT_FDCWD, "/home/user/.bashrc", O_RDONLY) = 3`
	e, ok := classifyStraceLine(line)
	if !ok {
		t.Fatalf("expected match")
	}
	if e.Op != "open_read" || e.Path != "/home/user/.bashrc" || e.PID != 12345 {
		t.Errorf("got %+v", e)
	}
}

func TestClassifyStraceLine_OpenWrite(t *testing.T) {
	line := `12345 openat(AT_FDCWD, "/home/user/out.txt", O_WRONLY|O_CREAT, 0644) = 4`
	e, ok := classifyStraceLine(line)
	if !ok {
		t.Fatalf("expected match")
	}
	if e.Op != "open_write" || e.Path != "/home/user/out.txt" {
		t.Errorf("got %+v", e)
	}
}

func TestClassifyStraceLine_SkipsDirectoryOpen(t *testing.T) {
	line := `12345 openat(AT_FDCWD, "/etc", O_RDONLY|O_DIRECTORY) = 3`
	if _, ok := classifyStraceLine(line); ok {
		t.Errorf("expected directory open to be skipped")
	}
}

func TestClassifyStraceLine_SkipsFailedSyscall(t *testing.T) {
	line := `12345 openat(AT_FDCWD, "/no/such/file", O_RDONLY) = -1 ENOENT (No such file or directory)`
	if _, ok := classifyStraceLine(line); ok {
		t.Errorf("expected failed syscall to be skipped")
	}
}

func TestClassifyStraceLine_SkipsUnfinished(t *testing.T) {
	line := `12345 openat(AT_FDCWD, "/x", O_RDONLY <unfinished ...>`
	if _, ok := classifyStraceLine(line); ok {
		t.Errorf("expected unfinished syscall to be skipped")
	}
}

func TestClassifyStraceLine_Mkdir(t *testing.T) {
	line := `12345 mkdirat(AT_FDCWD, "/home/user/newdir", 0755) = 0`
	e, ok := classifyStraceLine(line)
	if !ok {
		t.Fatalf("expected match")
	}
	if e.Op != "mkdir" || e.Path != "/home/user/newdir" {
		t.Errorf("got %+v", e)
	}
}

func TestClassifyStraceLine_Unlink(t *testing.T) {
	line := `12345 unlinkat(AT_FDCWD, "/home/user/junk", 0) = 0`
	e, ok := classifyStraceLine(line)
	if !ok {
		t.Fatalf("expected match")
	}
	if e.Op != "unlink" || e.Path != "/home/user/junk" {
		t.Errorf("got %+v", e)
	}
}

func TestClassifyStraceLine_Rename(t *testing.T) {
	line := `12345 renameat2(AT_FDCWD, "/home/user/a", AT_FDCWD, "/home/user/b", 0) = 0`
	e, ok := classifyStraceLine(line)
	if !ok {
		t.Fatalf("expected match")
	}
	if e.Op != "rename" || e.Path != "/home/user/a" || e.Path2 != "/home/user/b" {
		t.Errorf("got %+v", e)
	}
}

func TestClassifyStraceLine_Creat(t *testing.T) {
	line := `12345 creat("/home/user/new", 0644) = 5`
	e, ok := classifyStraceLine(line)
	if !ok {
		t.Fatalf("expected match")
	}
	if e.Op != "create" || e.Path != "/home/user/new" {
		t.Errorf("got %+v", e)
	}
}

func TestClassifyStraceLine_Symlink(t *testing.T) {
	line := `12345 symlinkat("/target", AT_FDCWD, "/home/user/link") = 0`
	e, ok := classifyStraceLine(line)
	if !ok {
		t.Fatalf("expected match")
	}
	if e.Op != "symlink" || e.Path != "/home/user/link" {
		t.Errorf("got %+v", e)
	}
}

func TestClassifyStraceLine_Link(t *testing.T) {
	line := `12345 linkat(AT_FDCWD, "/home/user/a", AT_FDCWD, "/home/user/b", 0) = 0`
	e, ok := classifyStraceLine(line)
	if !ok {
		t.Fatalf("expected match")
	}
	if e.Op != "link" || e.Path != "/home/user/a" || e.Path2 != "/home/user/b" {
		t.Errorf("got %+v", e)
	}
}

func TestClassifyStraceLine_NoMatch(t *testing.T) {
	cases := []string{
		"",
		"random text without a syscall",
		`12345 read(3, "...", 4096) = 4096`, // read syscall — not tracked
		`12345 close(3)               = 0`,
	}
	for _, line := range cases {
		if e, ok := classifyStraceLine(line); ok {
			t.Errorf("expected no match for %q, got %+v", line, e)
		}
	}
}

func TestExtractRenamePaths(t *testing.T) {
	src, dst := extractRenamePaths(`12345 renameat2(AT_FDCWD, "/a", AT_FDCWD, "/b", 0) = 0`)
	if src != "/a" || dst != "/b" {
		t.Errorf("got (%q, %q)", src, dst)
	}

	src, dst = extractRenamePaths(`no paths here`)
	if src != "" || dst != "" {
		t.Errorf("expected empty, got (%q, %q)", src, dst)
	}

	// Single AT_FDCWD: src present, dst empty.
	src, dst = extractRenamePaths(`12345 unlinkat(AT_FDCWD, "/a", 0) = 0`)
	if src != "/a" || dst != "" {
		t.Errorf("expected ('/a', ''), got (%q, %q)", src, dst)
	}
}

func TestExtractStracePID(t *testing.T) {
	cases := []struct {
		line string
		want int
	}{
		{`12345 openat(...)`, 12345},
		{`1 openat(...)`, 1},
		{`openat(...)`, 0}, // no PID prefix
		{``, 0},
		{`abc openat(...)`, 0},
	}
	for _, tc := range cases {
		got := extractStracePID(tc.line)
		if got != tc.want {
			t.Errorf("extractStracePID(%q) = %d, want %d", tc.line, got, tc.want)
		}
	}
}

// TestStreamingTracer_TailsFile writes strace-style lines to a file while the
// tracer is running and verifies events land in the buffer in order.
func TestStreamingTracer_TailsFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "strace.log")
	// Pre-create the file so Start can open it.
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	buf := NewFsEventBuffer(64)
	tracer := NewStreamingTracer(buf, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tracer.Start(ctx, logPath, 0); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tracer.Stop()

	// Append lines after the tracer has started.
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	lines := []string{
		`100 openat(AT_FDCWD, "/home/u/a", O_RDONLY) = 3` + "\n",
		`100 openat(AT_FDCWD, "/home/u/b", O_WRONLY|O_CREAT, 0644) = 4` + "\n",
		`100 mkdirat(AT_FDCWD, "/home/u/d", 0755) = 0` + "\n",
	}
	for _, l := range lines {
		if _, err := f.WriteString(l); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Sync()

	if !waitForLen(buf, 3, 2*time.Second) {
		t.Fatalf("timed out waiting for events; buffer has %d", buf.Len())
	}

	events, dropped := buf.Drain()
	if dropped != 0 {
		t.Errorf("unexpected dropped=%d", dropped)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	wantOps := []string{"open_read", "open_write", "mkdir"}
	wantPaths := []string{"/home/u/a", "/home/u/b", "/home/u/d"}
	for i, e := range events {
		if e.Op != wantOps[i] || e.Path != wantPaths[i] {
			t.Errorf("event[%d] = %+v, want op=%s path=%s", i, e, wantOps[i], wantPaths[i])
		}
		if e.PID != 100 {
			t.Errorf("event[%d].PID = %d, want 100", i, e.PID)
		}
		if e.Ts == "" {
			t.Errorf("event[%d].Ts is empty", i)
		}
	}
}

func TestStreamingTracer_StopBeforeStart(t *testing.T) {
	// Stop without Start should be a no-op, not panic.
	tracer := NewStreamingTracer(NewFsEventBuffer(8), false)
	tracer.Stop()
}

func TestStreamingTracer_DoubleStart(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "strace.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tracer := NewStreamingTracer(NewFsEventBuffer(8), false)
	ctx := context.Background()
	if err := tracer.Start(ctx, logPath, 0); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer tracer.Stop()
	if err := tracer.Start(ctx, logPath, 0); err == nil {
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
