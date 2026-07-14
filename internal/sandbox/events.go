package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event kinds emitted on the machine-readable event stream.
const (
	EventSessionStart   = "session_start"
	EventSessionEnd     = "session_end"
	EventSessionSummary = "session_summary"
	EventCommandBlock   = "command_block"
	EventFsViolation    = "fs_violation"
	EventNetworkAttempt = "network_attempt"
)

// Event verdicts.
const (
	VerdictAllowed  = "allowed"
	VerdictDenied   = "denied"
	VerdictObserved = "observed"
)

// Event is a single NDJSON record on the event stream. Every event carries
// the session ID and the wrapped command so a consumer can process any line
// without needing earlier context.
type Event struct {
	Time     string        `json:"time"`               // RFC3339Nano, UTC
	Session  string        `json:"session"`            // greywall session ID (gw-...), shared with greyproxy
	Command  string        `json:"command"`            // the wrapped command
	Kind     string        `json:"kind"`               // one of the Event* kind constants
	Target   string        `json:"target,omitempty"`   // host, path, or command the event is about
	Verdict  string        `json:"verdict,omitempty"`  // allowed | denied | observed
	Detail   string        `json:"detail,omitempty"`   // free-text context (errno, process, matched rule)
	ExitCode *int          `json:"exitCode,omitempty"` // session_end only
	Summary  *EventSummary `json:"summary,omitempty"`  // session_summary only
}

// EventSummary aggregates a session's events. It is emitted as the final
// session_summary event and is shaped to map onto a single downstream
// ingestion call (e.g. an audit-log entry per session).
type EventSummary struct {
	CountsByKind     map[string]int      `json:"countsByKind"`
	TopDeniedTargets []DeniedTargetCount `json:"topDeniedTargets,omitempty"`
}

// DeniedTargetCount is one denied target and how often it was denied.
type DeniedTargetCount struct {
	Target string `json:"target"`
	Kind   string `json:"kind"`
	Count  int    `json:"count"`
}

// maxSummaryDeniedTargets caps the topDeniedTargets list in the summary.
const maxSummaryDeniedTargets = 10

// EventLog writes session events as NDJSON (one JSON object per line) to a
// file another process can tail. All methods are safe on a nil receiver and
// safe for concurrent use, so call sites don't need to guard.
type EventLog struct {
	mu        sync.Mutex
	f         *os.File
	path      string
	sessionID string
	command   string
	closed    bool
	counts    map[string]int
	denied    map[string]*DeniedTargetCount // key: kind + "\x00" + target
}

// OpenEventLog opens (appending) the NDJSON event log and emits the
// session_start event. If path is an existing directory (or ends with a path
// separator), a per-session file <sessionID>.ndjson is created inside it;
// otherwise path is used as the file. Parent directories are created.
func OpenEventLog(path, sessionID, command string) (*EventLog, error) {
	if strings.HasSuffix(path, string(os.PathSeparator)) {
		path = filepath.Join(path, sessionID+".ndjson")
	} else if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, sessionID+".ndjson")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create event log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // user-provided log path - intentional
	if err != nil {
		return nil, fmt.Errorf("open event log: %w", err)
	}

	l := &EventLog{
		f:         f,
		path:      path,
		sessionID: sessionID,
		command:   command,
		counts:    make(map[string]int),
		denied:    make(map[string]*DeniedTargetCount),
	}
	cwd, _ := os.Getwd()
	l.write(Event{Kind: EventSessionStart, Detail: "cwd: " + cwd})
	return l, nil
}

// Path returns the file the event log writes to.
func (l *EventLog) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Emit records one event on the stream.
func (l *EventLog) Emit(kind, target, verdict, detail string) {
	if l == nil {
		return
	}
	l.write(Event{Kind: kind, Target: target, Verdict: verdict, Detail: detail})
}

// Close emits the session_end and session_summary events and closes the
// underlying file. Safe to call more than once.
func (l *EventLog) Close(exitCode int) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true

	code := exitCode
	l.writeLocked(Event{Kind: EventSessionEnd, ExitCode: &code})
	l.writeLocked(Event{Kind: EventSessionSummary, Summary: l.summaryLocked()})
	_ = l.f.Close()
	l.mu.Unlock()
}

// write serializes and appends one event, stamping time/session/command and
// updating the summary counters.
func (l *EventLog) write(ev Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.writeLocked(ev)
}

// writeLocked is write without locking; the caller must hold l.mu.
func (l *EventLog) writeLocked(ev Event) {
	ev.Time = time.Now().UTC().Format(time.RFC3339Nano)
	ev.Session = l.sessionID
	ev.Command = l.command

	l.counts[ev.Kind]++
	if ev.Verdict == VerdictDenied && ev.Target != "" {
		key := ev.Kind + "\x00" + ev.Target
		if d, ok := l.denied[key]; ok {
			d.Count++
		} else {
			l.denied[key] = &DeniedTargetCount{Target: ev.Target, Kind: ev.Kind, Count: 1}
		}
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = l.f.Write(data)
}

// summaryLocked builds the session summary; the caller must hold l.mu.
func (l *EventLog) summaryLocked() *EventSummary {
	counts := make(map[string]int, len(l.counts))
	for k, v := range l.counts {
		counts[k] = v
	}

	targets := make([]DeniedTargetCount, 0, len(l.denied))
	for _, d := range l.denied {
		targets = append(targets, *d)
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Count != targets[j].Count {
			return targets[i].Count > targets[j].Count
		}
		if targets[i].Target != targets[j].Target {
			return targets[i].Target < targets[j].Target
		}
		return targets[i].Kind < targets[j].Kind
	})
	if len(targets) > maxSummaryDeniedTargets {
		targets = targets[:maxSummaryDeniedTargets]
	}

	return &EventSummary{CountsByKind: counts, TopDeniedTargets: targets}
}
