package sandbox

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// heartbeatRecorder stands up a fake greyproxy that records every
// /api/sessions/{id}/heartbeat POST body in arrival order.
type heartbeatRecorder struct {
	mu     sync.Mutex
	bodies []string
}

func newHeartbeatRecorder(t *testing.T) (*heartbeatRecorder, *httptest.Server) {
	t.Helper()
	rec := &heartbeatRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/heartbeat") {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, string(body))
		rec.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return rec, srv
}

func (r *heartbeatRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.bodies))
	copy(out, r.bodies)
	return out
}

func TestHeartbeatSession_EmptyBody(t *testing.T) {
	rec, srv := newHeartbeatRecorder(t)

	if err := HeartbeatSession("sess1", srv.URL, nil, 0); err != nil {
		t.Fatalf("HeartbeatSession: %v", err)
	}

	bodies := rec.snapshot()
	if len(bodies) != 1 {
		t.Fatalf("want 1 heartbeat, got %d", len(bodies))
	}
	if bodies[0] != "" {
		t.Errorf("want empty body, got %q", bodies[0])
	}
}

func TestHeartbeatSession_WithEvents(t *testing.T) {
	rec, srv := newHeartbeatRecorder(t)
	events := []FsEvent{
		{Ts: "2026-05-22T00:00:00Z", Op: "open_read", Path: "/a"},
		{Ts: "2026-05-22T00:00:01Z", Op: "unlink", Path: "/b"},
	}

	if err := HeartbeatSession("sess1", srv.URL, events, 3); err != nil {
		t.Fatalf("HeartbeatSession: %v", err)
	}

	bodies := rec.snapshot()
	if len(bodies) != 1 {
		t.Fatalf("want 1 heartbeat, got %d", len(bodies))
	}

	var got heartbeatRequest
	if err := json.Unmarshal([]byte(bodies[0]), &got); err != nil {
		t.Fatalf("unmarshal body: %v (body=%q)", err, bodies[0])
	}
	if len(got.Events) != 2 || got.Events[0].Path != "/a" || got.Events[1].Op != "unlink" {
		t.Errorf("events mismatch: %+v", got.Events)
	}
	if got.Dropped != 3 {
		t.Errorf("dropped: got %d want 3", got.Dropped)
	}
}

func TestHeartbeatSession_DroppedOnly(t *testing.T) {
	rec, srv := newHeartbeatRecorder(t)

	if err := HeartbeatSession("sess1", srv.URL, nil, 7); err != nil {
		t.Fatalf("HeartbeatSession: %v", err)
	}

	bodies := rec.snapshot()
	if len(bodies) != 1 {
		t.Fatalf("want 1 heartbeat, got %d", len(bodies))
	}
	var got heartbeatRequest
	if err := json.Unmarshal([]byte(bodies[0]), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if got.Dropped != 7 {
		t.Errorf("dropped: got %d want 7", got.Dropped)
	}
	if len(got.Events) != 0 {
		t.Errorf("expected no events, got %d", len(got.Events))
	}
}

// TestStartHeartbeatLoop_FinalFlush verifies that pending events in the
// buffer are POSTed when the stop function runs, even if the periodic
// tick has not fired.
func TestStartHeartbeatLoop_FinalFlush(t *testing.T) {
	rec, srv := newHeartbeatRecorder(t)
	buf := NewFsEventBuffer(8)

	stop := StartHeartbeatLoop("sess-flush", "test", nil, nil, nil, srv.URL, nil, buf, false)

	buf.Push(FsEvent{Ts: nowTs(), Op: "open_read", Path: "/x"})
	buf.Push(FsEvent{Ts: nowTs(), Op: "unlink", Path: "/y"})

	stop()

	bodies := rec.snapshot()
	if len(bodies) != 1 {
		t.Fatalf("want exactly 1 final-flush heartbeat, got %d", len(bodies))
	}

	var got heartbeatRequest
	if err := json.Unmarshal([]byte(bodies[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v (body=%q)", err, bodies[0])
	}
	if len(got.Events) != 2 {
		t.Errorf("want 2 events in final flush, got %d", len(got.Events))
	}
	if buf.Len() != 0 {
		t.Errorf("buffer should be empty after final flush, got %d", buf.Len())
	}
}

// TestStartHeartbeatLoop_NilBufferEmptyBody verifies that when no
// FsEventBuffer is installed, the final flush sends nothing.
func TestStartHeartbeatLoop_NilBufferEmptyBody(t *testing.T) {
	rec, srv := newHeartbeatRecorder(t)

	stop := StartHeartbeatLoop("sess-nilbuf", "test", nil, nil, nil, srv.URL, nil, nil, false)
	stop()

	bodies := rec.snapshot()
	if len(bodies) != 0 {
		t.Fatalf("want 0 heartbeats (no ticks, nil buffer), got %d: %v", len(bodies), bodies)
	}
}

// TestStartHeartbeatLoop_FinalFlushNoEvents verifies that the final
// flush does not POST when the buffer is empty.
func TestStartHeartbeatLoop_FinalFlushNoEvents(t *testing.T) {
	rec, srv := newHeartbeatRecorder(t)
	buf := NewFsEventBuffer(8)

	stop := StartHeartbeatLoop("sess-empty", "test", nil, nil, nil, srv.URL, nil, buf, false)
	stop()

	bodies := rec.snapshot()
	if len(bodies) != 0 {
		t.Fatalf("want 0 heartbeats (empty buffer), got %d", len(bodies))
	}
}

// TestStartHeartbeatLoop_FinalFlushForwardsDropped verifies that the
// dropped counter is reported even when no events remain in the buffer.
func TestStartHeartbeatLoop_FinalFlushForwardsDropped(t *testing.T) {
	rec, srv := newHeartbeatRecorder(t)
	buf := NewFsEventBuffer(2)

	// Fill + overflow so the dropped counter goes up.
	buf.Push(FsEvent{Op: "open_read", Path: "/a"})
	buf.Push(FsEvent{Op: "open_read", Path: "/b"})
	buf.Push(FsEvent{Op: "open_read", Path: "/c"}) // drops /a
	buf.Push(FsEvent{Op: "open_read", Path: "/d"}) // drops /b

	stop := StartHeartbeatLoop("sess-drop", "test", nil, nil, nil, srv.URL, nil, buf, false)
	stop()

	bodies := rec.snapshot()
	if len(bodies) != 1 {
		t.Fatalf("want 1 heartbeat, got %d", len(bodies))
	}
	var got heartbeatRequest
	if err := json.Unmarshal([]byte(bodies[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Dropped != 2 {
		t.Errorf("dropped: got %d want 2", got.Dropped)
	}
	if len(got.Events) != 2 {
		t.Errorf("want 2 events surviving, got %d", len(got.Events))
	}
}

