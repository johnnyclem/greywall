package sandbox

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/GreyhavenHQ/greywall/internal/platform"
)

// LogMonitor monitors sandbox violations via macOS log stream.
type LogMonitor struct {
	sessionSuffix string
	cmd           *exec.Cmd
	cancel        context.CancelFunc
	running       bool
	echo          bool      // print violations to stderr
	events        *EventLog // optional machine-readable event stream
}

// NewLogMonitor creates a new log monitor for the given session suffix.
// Returns nil on non-macOS platforms.
func NewLogMonitor(sessionSuffix string) *LogMonitor {
	if platform.Detect() != platform.MacOS {
		return nil
	}
	return &LogMonitor{
		sessionSuffix: sessionSuffix,
		echo:          true,
	}
}

// SetEventLog attaches a machine-readable event stream to the monitor.
func (m *LogMonitor) SetEventLog(l *EventLog) {
	if m != nil {
		m.events = l
	}
}

// SetEcho controls whether violations are printed to stderr.
func (m *LogMonitor) SetEcho(echo bool) {
	if m != nil {
		m.echo = echo
	}
}

// Start begins monitoring the macOS unified log for sandbox violations.
func (m *LogMonitor) Start() error {
	if m == nil {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	// Build predicate to filter for this session's violations only
	predicate := fmt.Sprintf(`eventMessage ENDSWITH "%s"`, m.sessionSuffix)

	m.cmd = exec.CommandContext( //nolint:gosec // predicate is constructed from trusted session suffix
		ctx, "log", "stream",
		"--predicate", predicate,
		"--style", "compact",
	)

	stdout, err := m.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start log stream: %w", err)
	}

	m.running = true

	// Parse log output in background
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			v := parseViolationLine(line)
			if v == nil {
				continue
			}
			if m.echo {
				fmt.Fprintf(os.Stderr, "%s\n", v.format()) //nolint:gosec // stderr output
			}
			kind := EventFsViolation
			if strings.HasPrefix(v.operation, "network-") {
				kind = EventNetworkAttempt
			}
			target := v.details
			if target == "" {
				target = v.operation
			}
			m.events.Emit(kind, target, VerdictDenied,
				fmt.Sprintf("%s (%s:%s)", v.operation, v.process, v.pid))
		}
	}()

	// Give log stream a moment to initialize
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Stop stops the log monitor.
func (m *LogMonitor) Stop() {
	if m == nil || !m.running {
		return
	}

	// Give a moment for any pending events to be processed
	time.Sleep(500 * time.Millisecond)

	if m.cancel != nil {
		m.cancel()
	}

	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_ = m.cmd.Wait()
	}

	m.running = false
}

// violationPattern matches sandbox denial log entries
var violationPattern = regexp.MustCompile(`Sandbox: (\w+)\((\d+)\) deny\(\d+\) (\S+)(.*)`)

// macViolation is a parsed sandbox denial from the macOS unified log.
type macViolation struct {
	process   string
	pid       string
	operation string
	details   string
}

// format renders a violation for human-readable stderr output.
func (v *macViolation) format() string {
	timestamp := time.Now().Format("15:04:05")
	if v.details != "" {
		return fmt.Sprintf("[greywall:logstream] %s ✗ %s %s (%s:%s)", timestamp, v.operation, v.details, v.process, v.pid)
	}
	return fmt.Sprintf("[greywall:logstream] %s ✗ %s (%s:%s)", timestamp, v.operation, v.process, v.pid)
}

// parseViolationLine extracts a sandbox violation from a log line.
// Returns nil if the line should be filtered out.
func parseViolationLine(line string) *macViolation {
	if strings.HasPrefix(line, "Filtering") || strings.HasPrefix(line, "Timestamp") {
		return nil
	}

	if strings.Contains(line, "duplicate report") {
		return nil
	}

	if strings.HasPrefix(line, "CMD64_") {
		return nil
	}

	// Match violation pattern
	matches := violationPattern.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	v := &macViolation{
		process:   matches[1],
		pid:       matches[2],
		operation: matches[3],
		details:   strings.TrimSpace(matches[4]),
	}

	if !shouldShowViolation(v.operation) {
		return nil
	}

	if isNoisyViolation(v.details) {
		return nil
	}

	return v
}

// shouldShowViolation returns true if this violation type should be displayed.
func shouldShowViolation(operation string) bool {
	if strings.HasPrefix(operation, "network-") {
		return true
	}

	if strings.HasPrefix(operation, "file-read") ||
		strings.HasPrefix(operation, "file-write") {
		return true
	}

	// Filter out everything else (mach-lookup, file-ioctl, etc.)
	return false
}

// isNoisyViolation returns true if this violation is system noise that should be filtered.
func isNoisyViolation(details string) bool {
	// Filter out TTY/terminal writes (very noisy from any process that prints output)
	if strings.HasPrefix(details, "/dev/tty") ||
		strings.HasPrefix(details, "/dev/pts") {
		return true
	}

	// Filter out mDNSResponder (system DNS resolution socket)
	if strings.Contains(details, "mDNSResponder") {
		return true
	}

	// Filter out other system sockets that are typically noise
	if strings.HasPrefix(details, "/private/var/run/syslog") {
		return true
	}

	return false
}

// GetSessionSuffix returns the session suffix used for filtering.
// This is the same suffix used in macOS sandbox-exec profiles.
func GetSessionSuffix() string {
	return sessionSuffix
}
