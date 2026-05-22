package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// TestRecordFs_EndToEnd integrates everything wired in steps 3-5: a real
// StreamingTracer started via the manager pushes into the FsEventBuffer
// that StartHeartbeatLoop drains. A canned strace/eslogger line written
// to the log file should end up in the mock greyproxy's heartbeat body
// after the loop's final flush.
func TestRecordFs_EndToEnd(t *testing.T) {
	mock := newMockGreyproxy(t)

	dir := t.TempDir()
	logPath := filepath.Join(dir, "tracer.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(&config.Config{}, false, false)
	m.SetRecordFs(true)
	buf := NewFsEventBuffer(32)
	m.SetFsEventBuffer(buf)
	t.Cleanup(m.Cleanup)

	switch runtime.GOOS {
	case "linux":
		m.straceLogPath = logPath
	case "darwin":
		m.esloggerLogPath = logPath
		m.SetRootPID(4242)
	default:
		t.Skipf("record-fs integration not supported on %s", runtime.GOOS)
	}

	if err := m.StartFsTracer(context.Background()); err != nil {
		t.Fatalf("StartFsTracer: %v", err)
	}

	stop := StartHeartbeatLoop("sess-e2e", "test", nil, nil, nil, mock.URL(), nil, m.FsEventBuffer(), false)

	// Append a single platform-appropriate event to the log and wait
	// for the streaming tracer to push it into the buffer.
	var line string
	switch runtime.GOOS {
	case "linux":
		line = `4242 openat(AT_FDCWD, "/tmp/greywall-int-e2e", O_RDONLY) = 5` + "\n"
	case "darwin":
		line = `{"event_type":10,"process":{"audit_token":{"pid":4242},"executable":{"path":"/bin/test"},"ppid":1},"event":{"open":{"file":{"path":"/tmp/greywall-int-e2e"},"fflag":1}}}` + "\n"
	}
	if err := appendLine(logPath, line); err != nil {
		t.Fatal(err)
	}

	waitForBufferLen(t, buf, 1, 2*time.Second)

	// The 60s tick interval is far too long to wait for; rely on the
	// final-flush path the stop func provides.
	stop()

	bodies := mock.bodies()
	if len(bodies) != 1 {
		t.Fatalf("want exactly 1 heartbeat POST from final flush, got %d (%v)", len(bodies), bodies)
	}

	var got heartbeatRequest
	if err := json.Unmarshal([]byte(bodies[0]), &got); err != nil {
		t.Fatalf("unmarshal heartbeat body: %v (raw=%q)", err, bodies[0])
	}
	if len(got.Events) != 1 {
		t.Fatalf("want 1 event in heartbeat body, got %d", len(got.Events))
	}
	if got.Events[0].Path != "/tmp/greywall-int-e2e" {
		t.Errorf("path mismatch: got %q want /tmp/greywall-int-e2e", got.Events[0].Path)
	}
	if got.Events[0].Op != "open_read" {
		t.Errorf("op mismatch: got %q want open_read", got.Events[0].Op)
	}
	if buf.Len() != 0 {
		t.Errorf("buffer should be empty after final flush, got %d", buf.Len())
	}
}

// TestRecordFs_EndToEnd_DropAndFlush verifies that when the tracer
// overflows the buffer, the dropped counter reaches the mock greyproxy
// via the final flush.
func TestRecordFs_EndToEnd_DropAndFlush(t *testing.T) {
	mock := newMockGreyproxy(t)

	dir := t.TempDir()
	logPath := filepath.Join(dir, "tracer.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(&config.Config{}, false, false)
	m.SetRecordFs(true)
	buf := NewFsEventBuffer(2)
	m.SetFsEventBuffer(buf)
	t.Cleanup(m.Cleanup)

	switch runtime.GOOS {
	case "linux":
		m.straceLogPath = logPath
	case "darwin":
		m.esloggerLogPath = logPath
		m.SetRootPID(4242)
	default:
		t.Skipf("record-fs integration not supported on %s", runtime.GOOS)
	}

	if err := m.StartFsTracer(context.Background()); err != nil {
		t.Fatalf("StartFsTracer: %v", err)
	}
	stop := StartHeartbeatLoop("sess-drop", "test", nil, nil, nil, mock.URL(), nil, m.FsEventBuffer(), false)

	// Pump 4 events through a buffer of capacity 2 — expect 2 dropped.
	for _, path := range []string{"/p/a", "/p/b", "/p/c", "/p/d"} {
		var line string
		switch runtime.GOOS {
		case "linux":
			line = `4242 openat(AT_FDCWD, "` + path + `", O_RDONLY) = 5` + "\n"
		case "darwin":
			line = `{"event_type":10,"process":{"audit_token":{"pid":4242},"executable":{"path":"/bin/test"},"ppid":1},"event":{"open":{"file":{"path":"` + path + `"},"fflag":1}}}` + "\n"
		}
		if err := appendLine(logPath, line); err != nil {
			t.Fatal(err)
		}
	}

	// Wait until the tracer has processed all 4 events: buffer at cap
	// (2) and dropped counter at 2. Polling Drain would be destructive,
	// so use the non-consuming Dropped() accessor.
	waitForBufferDropped(t, buf, 2, 2*time.Second)

	stop()

	bodies := mock.bodies()
	if len(bodies) != 1 {
		t.Fatalf("want 1 final flush POST, got %d", len(bodies))
	}
	var got heartbeatRequest
	if err := json.Unmarshal([]byte(bodies[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Dropped != 2 {
		t.Errorf("dropped: got %d want 2", got.Dropped)
	}
	if len(got.Events) != 2 {
		t.Errorf("surviving events: got %d want 2", len(got.Events))
	}
}

// TestRecordFs_EndToEnd_NoEventsNoPost verifies the system stays quiet
// (no POSTs at all) when nothing fires through the tracer.
func TestRecordFs_EndToEnd_NoEventsNoPost(t *testing.T) {
	mock := newMockGreyproxy(t)

	dir := t.TempDir()
	logPath := filepath.Join(dir, "tracer.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(&config.Config{}, false, false)
	m.SetRecordFs(true)
	buf := NewFsEventBuffer(8)
	m.SetFsEventBuffer(buf)
	t.Cleanup(m.Cleanup)

	switch runtime.GOOS {
	case "linux":
		m.straceLogPath = logPath
	case "darwin":
		m.esloggerLogPath = logPath
		m.SetRootPID(4242)
	default:
		t.Skipf("record-fs integration not supported on %s", runtime.GOOS)
	}

	if err := m.StartFsTracer(context.Background()); err != nil {
		t.Fatalf("StartFsTracer: %v", err)
	}
	stop := StartHeartbeatLoop("sess-quiet", "test", nil, nil, nil, mock.URL(), nil, m.FsEventBuffer(), false)
	stop()

	if got := len(mock.bodies()); got != 0 {
		t.Errorf("want 0 heartbeats, got %d", got)
	}
}

// --- helpers ---

// mockGreyproxy stands up an httptest.Server that records the POST
// bodies sent to /api/sessions/{id}/heartbeat. It also accepts session
// (re-)registration requests with a 200 so the heartbeat loop's
// fallback path doesn't spin.
type mockGreyproxy struct {
	srv *httptest.Server
	mu  sync.Mutex
	rcv []string
}

func newMockGreyproxy(t *testing.T) *mockGreyproxy {
	t.Helper()
	m := &mockGreyproxy{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/heartbeat") {
			body, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			m.mu.Lock()
			m.rcv = append(m.rcv, string(body))
			m.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockGreyproxy) URL() string { return m.srv.URL }

func (m *mockGreyproxy) bodies() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.rcv))
	copy(out, m.rcv)
	return out
}

func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(line); err != nil {
		return err
	}
	return f.Sync()
}

// waitForBufferLen polls buf.Len until it reaches want or the deadline
// elapses. Fails the test on timeout.
func waitForBufferLen(t *testing.T, buf *FsEventBuffer, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if buf.Len() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("buffer never reached %d entries (got %d)", want, buf.Len())
}

// waitForBufferDropped polls buf.Dropped() until it reaches want or the
// deadline elapses. Fails the test on timeout.
func waitForBufferDropped(t *testing.T, buf *FsEventBuffer, want uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if buf.Dropped() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("buffer dropped count never reached %d (got %d)", want, buf.Dropped())
}
