package sandbox

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// readEvents parses every NDJSON line in the file.
func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer func() { _ = f.Close() }()

	var events []Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("invalid NDJSON line %q: %v", scanner.Text(), err)
		}
		events = append(events, ev)
	}
	return events
}

func TestEventLog_WritesNDJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")

	log, err := OpenEventLog(path, "gw-test1234", "claude --help")
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	log.Emit(EventFsViolation, "/etc/shadow", VerdictDenied, "file-read-data (cat:123)")
	log.Emit(EventNetworkAttempt, "evil.example.com", VerdictDenied, "connect")
	log.Emit(EventNetworkAttempt, "evil.example.com", VerdictDenied, "connect")
	log.Close(3)

	events := readEvents(t, path)
	if len(events) != 6 {
		t.Fatalf("expected 6 events, got %d: %+v", len(events), events)
	}

	wantKinds := []string{
		EventSessionStart, EventFsViolation, EventNetworkAttempt,
		EventNetworkAttempt, EventSessionEnd, EventSessionSummary,
	}
	for i, want := range wantKinds {
		if events[i].Kind != want {
			t.Errorf("event %d kind = %q, want %q", i, events[i].Kind, want)
		}
		if events[i].Session != "gw-test1234" {
			t.Errorf("event %d session = %q, want gw-test1234", i, events[i].Session)
		}
		if events[i].Command != "claude --help" {
			t.Errorf("event %d command = %q, want the wrapped command", i, events[i].Command)
		}
		if events[i].Time == "" {
			t.Errorf("event %d has no timestamp", i)
		}
	}

	end := events[4]
	if end.ExitCode == nil || *end.ExitCode != 3 {
		t.Errorf("session_end exitCode = %v, want 3", end.ExitCode)
	}

	summary := events[5].Summary
	if summary == nil {
		t.Fatal("session_summary has no summary payload")
	}
	if summary.CountsByKind[EventFsViolation] != 1 || summary.CountsByKind[EventNetworkAttempt] != 2 {
		t.Errorf("unexpected counts: %+v", summary.CountsByKind)
	}
	if len(summary.TopDeniedTargets) != 2 {
		t.Fatalf("expected 2 denied targets, got %+v", summary.TopDeniedTargets)
	}
	if summary.TopDeniedTargets[0].Target != "evil.example.com" || summary.TopDeniedTargets[0].Count != 2 {
		t.Errorf("expected evil.example.com (2) first, got %+v", summary.TopDeniedTargets[0])
	}
}

func TestEventLog_DirectoryPath(t *testing.T) {
	dir := t.TempDir()

	log, err := OpenEventLog(dir, "gw-dirtest", "echo hi")
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	log.Close(0)

	want := filepath.Join(dir, "gw-dirtest.ndjson")
	if log.Path() != want {
		t.Errorf("Path() = %q, want %q", log.Path(), want)
	}
	events := readEvents(t, want)
	if len(events) != 3 {
		t.Fatalf("expected start/end/summary, got %d events", len(events))
	}
}

func TestEventLog_CreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "events.ndjson")
	log, err := OpenEventLog(path, "gw-nested", "echo hi")
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	log.Close(0)
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected event log file to exist: %v", err)
	}
}

func TestEventLog_TopDeniedTargetsCapped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	log, err := OpenEventLog(path, "gw-cap", "cmd")
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	for i := range 15 {
		log.Emit(EventNetworkAttempt, fmt.Sprintf("host-%02d.example.com", i), VerdictDenied, "")
	}
	log.Close(0)

	events := readEvents(t, path)
	summary := events[len(events)-1].Summary
	if summary == nil {
		t.Fatal("missing summary")
	}
	if len(summary.TopDeniedTargets) != maxSummaryDeniedTargets {
		t.Errorf("expected %d targets, got %d", maxSummaryDeniedTargets, len(summary.TopDeniedTargets))
	}
	if summary.CountsByKind[EventNetworkAttempt] != 15 {
		t.Errorf("counts should include all events, got %d", summary.CountsByKind[EventNetworkAttempt])
	}
}

func TestEventLog_NilSafe(t *testing.T) {
	var log *EventLog
	log.Emit(EventFsViolation, "/etc/shadow", VerdictDenied, "")
	log.Close(0)
	if log.Path() != "" {
		t.Error("nil Path() should be empty")
	}
}

func TestEventLog_CloseIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	log, err := OpenEventLog(path, "gw-close", "cmd")
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	log.Close(0)
	log.Close(1)                 // must not panic or write more events
	log.Emit("late", "", "", "") // must not write after close

	events := readEvents(t, path)
	if len(events) != 3 {
		t.Errorf("expected 3 events after double close, got %d", len(events))
	}
}
