package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// TestManager_StartFsTracer_DisabledByDefault verifies that StartFsTracer
// is a no-op when record-fs is off or the event buffer hasn't been set.
func TestManager_StartFsTracer_DisabledByDefault(t *testing.T) {
	cases := []struct {
		name     string
		recordFs bool
		setBuf   bool
	}{
		{"recordFs off, buf unset", false, false},
		{"recordFs off, buf set", false, true},
		{"recordFs on, buf unset", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(&config.Config{}, false, false)
			m.SetRecordFs(tc.recordFs)
			if tc.setBuf {
				m.SetFsEventBuffer(NewFsEventBuffer(8))
			}
			if err := m.StartFsTracer(context.Background()); err != nil {
				t.Errorf("expected nil, got %v", err)
			}
			if m.tracer != nil {
				t.Errorf("tracer should not have been started")
			}
		})
	}
}

// TestManager_StartFsTracer_NoLogPath verifies that calling StartFsTracer
// before a log path has been established returns an error.
func TestManager_StartFsTracer_NoLogPath(t *testing.T) {
	m := NewManager(&config.Config{}, false, false)
	m.SetRecordFs(true)
	m.SetFsEventBuffer(NewFsEventBuffer(8))

	err := m.StartFsTracer(context.Background())
	if err == nil {
		t.Errorf("expected error when log path is unset")
	}
}

// TestManager_StartFsTracer_TailsLog plumbs the manager end-to-end: set
// record-fs, install a buffer, point at a pre-created log file, write
// canned strace/eslogger lines, and verify events appear in the buffer.
// Cleanup must stop the tracer cleanly.
func TestManager_StartFsTracer_TailsLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "tracer.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(&config.Config{}, false, false)
	m.SetRecordFs(true)
	buf := NewFsEventBuffer(32)
	m.SetFsEventBuffer(buf)

	// Set the platform-specific log path directly. In production these are
	// set by Initialize()/wrapCommandWithTracing().
	switch runtime.GOOS {
	case "linux":
		m.straceLogPath = logPath
	case "darwin":
		m.esloggerLogPath = logPath
		m.SetRootPID(100)
	default:
		t.Skipf("fs tracer not supported on %s", runtime.GOOS)
	}

	if err := m.StartFsTracer(context.Background()); err != nil {
		t.Fatalf("StartFsTracer: %v", err)
	}
	if m.tracer == nil {
		t.Fatalf("tracer should have been started")
	}

	// Append a line matching the platform's expected log format.
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	var line string
	switch runtime.GOOS {
	case "linux":
		line = `100 openat(AT_FDCWD, "/home/u/x", O_RDONLY) = 3` + "\n"
	case "darwin":
		// Minimal eslogger JSON event for an open syscall.
		line = `{"event_type":10,"process":{"audit_token":{"pid":100},"executable":{"path":"/bin/test"},"ppid":1},"event":{"open":{"file":{"path":"/Users/u/x"},"fflag":1}}}` + "\n"
	}
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
	_ = f.Sync()

	// Poll until the event lands.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && buf.Len() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if buf.Len() == 0 {
		t.Fatalf("expected at least one event in buffer")
	}

	// Cleanup should stop the tracer and null out the field.
	m.Cleanup()
	if m.tracer != nil {
		t.Errorf("tracer should be nil after Cleanup")
	}
}

// TestManager_TracesEnabled covers the helper used by Initialize and
// WrapCommand to decide whether the platform tracer needs to run.
func TestManager_TracesEnabled(t *testing.T) {
	cases := []struct {
		name     string
		learning bool
		recordFs bool
		want     bool
	}{
		{"neither", false, false, false},
		{"learning only", true, false, true},
		{"recordFs only", false, true, true},
		{"both", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(&config.Config{}, false, false)
			m.SetLearning(tc.learning)
			m.SetRecordFs(tc.recordFs)
			if got := m.tracesEnabled(); got != tc.want {
				t.Errorf("tracesEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}
