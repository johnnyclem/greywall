package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/platform"
)

// Manager handles sandbox initialization and command wrapping.
type Manager struct {
	config        *config.Config
	proxyBridge   *ProxyBridge
	dnsBridge     *DnsBridge
	reverseBridge *ReverseBridge
	forwardBridge *ForwardBridge
	dbusBridge    *DbusBridge
	tun2socksPath string // path to extracted tun2socks binary on host
	exposedPorts  []int
	debug         bool
	monitor       bool
	initialized   bool
	learning      bool   // learning mode: permissive sandbox with strace/eslogger
	watch         bool   // watch mode: permissive sandbox for pure observability (no strace, no profile gen)
	recordFs      bool   // stream filesystem events to greyproxy via the shared FsEventBuffer
	straceLogPath string // host-side temp file for strace output (Linux)
	commandName   string // name of the command being learned
	// rootPID is the PID of the sandboxed command's top-level process. Used by
	// the macOS eslogger parser to filter events to that process tree.
	rootPID           int
	esloggerLogPath   string            // temp file for eslogger output (macOS)
	esloggerCmd       *exec.Cmd         // eslogger subprocess (macOS)
	rewrittenEnvFiles map[string]string // original path -> temp path with credential placeholders
	macOSTmpDir       string            // per-session TMPDIR created on macOS (cleaned up on exit)
	// Streaming filesystem-event recorder. When fsBuf is non-nil and
	// tracing is active, the tracer pushes events into the buffer.
	fsBuf  *FsEventBuffer
	tracer *StreamingTracer
}

// NewManager creates a new sandbox manager.
func NewManager(cfg *config.Config, debug, monitor bool) *Manager {
	return &Manager{
		config:  cfg,
		debug:   debug,
		monitor: monitor,
	}
}

// SetExposedPorts sets the ports to expose for inbound connections.
func (m *Manager) SetExposedPorts(ports []int) {
	m.exposedPorts = ports
}

// SetLearning enables or disables learning mode.
func (m *Manager) SetLearning(enabled bool) {
	m.learning = enabled
}

// SetCommandName sets the command name for learning mode profile generation.
func (m *Manager) SetCommandName(name string) {
	m.commandName = name
}

// IsLearning returns whether learning mode is enabled.
func (m *Manager) IsLearning() bool {
	return m.learning
}

// SetWatch enables or disables watch (observability) mode.
func (m *Manager) SetWatch(enabled bool) {
	m.watch = enabled
}

// IsWatch returns whether watch mode is enabled.
func (m *Manager) IsWatch() bool {
	return m.watch
}

// SetRecordFs enables or disables filesystem-event recording. When enabled,
// the manager launches the platform tracer (strace on Linux, eslogger on
// macOS) so the streaming tracer can observe filesystem activity. Must be
// set before Initialize/WrapCommand.
//
// Recording requires landlock and seccomp disabled because strace uses
// ptrace which seccomp blocks.
func (m *Manager) SetRecordFs(enabled bool) {
	m.recordFs = enabled
}

// IsRecordFs returns whether filesystem-event recording is enabled.
func (m *Manager) IsRecordFs() bool {
	return m.recordFs
}

// SetFsEventBuffer installs the ring buffer that the streaming tracer will
// push events into. If nil, the tracer is not started even if SetRecordFs
// is true.
func (m *Manager) SetFsEventBuffer(buf *FsEventBuffer) {
	m.fsBuf = buf
}

// FsEventBuffer returns the installed ring buffer, or nil if none has
// been set. Callers (e.g. the heartbeat loop) drain it to ship events.
func (m *Manager) FsEventBuffer() *FsEventBuffer {
	return m.fsBuf
}

// tracesEnabled reports whether the manager needs the platform tracer
// (strace or eslogger) running.
func (m *Manager) tracesEnabled() bool {
	return m.learning || m.recordFs
}

// SetRewrittenEnvFiles sets the map of .env files rewritten with credential placeholders.
func (m *Manager) SetRewrittenEnvFiles(files map[string]string) {
	m.rewrittenEnvFiles = files
}

// Initialize sets up the sandbox infrastructure.
func (m *Manager) Initialize() error {
	if m.initialized {
		return nil
	}

	if !platform.IsSupported() {
		return fmt.Errorf("sandbox is not supported on platform: %s", platform.Detect())
	}

	// On macOS in learning or record-fs mode, launch eslogger via sudo to trace
	// filesystem access. Only eslogger itself needs root (Endpoint Security
	// framework) — the sandboxed command runs as the current user.
	if platform.Detect() == platform.MacOS && m.tracesEnabled() {
		logFile, err := os.CreateTemp("", "greywall-eslogger-*.log")
		if err != nil {
			return fmt.Errorf("failed to create eslogger log file: %w", err)
		}
		m.esloggerLogPath = logFile.Name()
		m.logDebug("Starting eslogger (via sudo), log: %s", m.esloggerLogPath)

		// Validate sudo credentials upfront so the password prompt happens before
		// the user's command starts (which may take over the terminal).
		//nolint:gosec // sudo path is hardcoded
		sudoValidate := exec.Command("/usr/bin/sudo", "-v")
		sudoValidate.Stdin = os.Stdin
		sudoValidate.Stdout = os.Stderr
		sudoValidate.Stderr = os.Stderr
		if err := sudoValidate.Run(); err != nil {
			_ = logFile.Close()
			_ = os.Remove(m.esloggerLogPath)
			return fmt.Errorf("sudo authentication failed (needed for eslogger): %w", err)
		}

		//nolint:gosec // eslogger and sudo paths are hardcoded, event types are constants
		cmd := exec.Command("/usr/bin/sudo", "/usr/bin/eslogger", "open", "create", "write", "unlink", "truncate", "rename", "link", "fork")
		cmd.Stdout = logFile
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			_ = logFile.Close()
			_ = os.Remove(m.esloggerLogPath)
			return fmt.Errorf("failed to start eslogger: %w", err)
		}
		m.esloggerCmd = cmd
		_ = logFile.Close() // eslogger owns the fd now via its stdout

		// Wait for eslogger to connect to Endpoint Security and start emitting events.
		// Once connected, it immediately logs events from all processes on the system,
		// so any data in the log file means it's ready.
		m.logDebug("Waiting for eslogger to become ready...")
		ready := false
		for range 50 { // up to 5 seconds
			info, err := os.Stat(m.esloggerLogPath)
			if err == nil && info.Size() > 0 {
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ready {
			m.logDebug("eslogger did not produce output within 5s, proceeding anyway")
		} else {
			m.logDebug("eslogger is ready")
		}

		m.initialized = true
		return nil
	}

	// On Linux, set up proxy bridge and tun2socks if proxy is configured
	if platform.Detect() == platform.Linux {
		if m.config.Network.ProxyURL != "" {
			// Extract embedded tun2socks binary
			tun2socksPath, err := extractTun2Socks()
			if err != nil {
				m.logDebug("Failed to extract tun2socks: %v (will fall back to env-var proxying)", err)
			} else {
				m.tun2socksPath = tun2socksPath
			}

			// Create proxy bridge (socat: Unix socket -> external SOCKS5 proxy)
			bridge, err := NewProxyBridge(m.config.Network.ProxyURL, m.debug)
			if err != nil {
				if m.tun2socksPath != "" {
					_ = os.Remove(m.tun2socksPath)
				}
				return fmt.Errorf("failed to initialize proxy bridge: %w", err)
			}
			m.proxyBridge = bridge

			// Create DNS bridge if a DNS server is configured
			if m.config.Network.DnsAddr != "" {
				dnsBridge, err := NewDnsBridge(m.config.Network.DnsAddr, m.debug)
				if err != nil {
					m.proxyBridge.Cleanup()
					if m.tun2socksPath != "" {
						_ = os.Remove(m.tun2socksPath)
					}
					return fmt.Errorf("failed to initialize DNS bridge: %w", err)
				}
				m.dnsBridge = dnsBridge
			}
		}

		// Set up reverse bridge for exposed ports (inbound connections)
		// Only needed when network namespace is available - otherwise they share the network
		features := DetectLinuxFeatures()
		if len(m.exposedPorts) > 0 && features.CanUnshareNet {
			reverseBridge, err := NewReverseBridge(m.exposedPorts, m.debug)
			if err != nil {
				if m.proxyBridge != nil {
					m.proxyBridge.Cleanup()
				}
				if m.tun2socksPath != "" {
					_ = os.Remove(m.tun2socksPath)
				}
				return fmt.Errorf("failed to initialize reverse bridge: %w", err)
			}
			m.reverseBridge = reverseBridge
		} else if len(m.exposedPorts) > 0 && m.debug {
			m.logDebug("Skipping reverse bridge (no network namespace, ports accessible directly)")
		}

		// Set up forward bridge for localhost outbound (sandbox -> host localhost ports)
		if len(m.config.Network.ForwardPorts) > 0 && features.CanUnshareNet {
			forwardBridge, err := NewForwardBridge(m.config.Network.ForwardPorts, m.debug)
			if err != nil {
				if m.proxyBridge != nil {
					m.proxyBridge.Cleanup()
				}
				if m.reverseBridge != nil {
					m.reverseBridge.Cleanup()
				}
				if m.tun2socksPath != "" {
					_ = os.Remove(m.tun2socksPath)
				}
				return fmt.Errorf("failed to initialize forward bridge: %w", err)
			}
			m.forwardBridge = forwardBridge
		} else if len(m.config.Network.ForwardPorts) > 0 && m.debug {
			m.logDebug("Skipping forward bridge (no network namespace, ports accessible directly)")
		}

		// Set up filtered D-Bus proxy for notify-send support
		// Returns nil gracefully if xdg-dbus-proxy is not installed
		m.dbusBridge = NewDbusBridge(m.debug)
	}

	// On macOS (when not tracing), create a per-session temp directory and expose
	// it as TMPDIR inside the sandbox. This avoids the need to allow arbitrary
	// writes to /private/tmp, while giving sandboxed processes a working temp
	// directory. Skipped when tracing because the tracer path returns earlier.
	if platform.Detect() == platform.MacOS && !m.tracesEnabled() {
		tmpDir, err := os.MkdirTemp("", "greywall-")
		if err != nil {
			m.logDebug("warning: failed to create per-session TMPDIR: %v", err)
		} else {
			m.macOSTmpDir = tmpDir
			m.logDebug("Created per-session TMPDIR: %s", tmpDir)
		}
	}

	m.initialized = true
	if m.config.Network.ProxyURL != "" {
		dnsInfo := "none"
		if m.config.Network.DnsAddr != "" {
			dnsInfo = m.config.Network.DnsAddr
		}
		m.logDebug("Sandbox manager initialized (proxy: %s, dns: %s)", m.config.Network.ProxyURL, dnsInfo)
	} else {
		m.logDebug("Sandbox manager initialized (no proxy, network blocked)")
	}
	return nil
}

// WrapCommand wraps a command with sandbox restrictions.
// Returns an error if the command is blocked by policy.
func (m *Manager) WrapCommand(command string) (string, error) {
	if !m.initialized {
		if err := m.Initialize(); err != nil {
			return "", err
		}
	}

	// Check if command is blocked by policy
	if err := CheckCommand(command, m.config); err != nil {
		return "", err
	}

	plat := platform.Detect()
	switch plat {
	case platform.MacOS:
		if m.learning {
			// In learning mode, run command directly (no sandbox-exec wrapping).
			// Record-fs on macOS does not change command wrapping because
			// eslogger runs out-of-band; the existing Seatbelt path is reused
			// when watch or normal mode is also active.
			return command, nil
		}
		// Watch mode goes through the normal macOS path so the sandbox-exec
		// wrapper still exports proxy env vars (HTTP_PROXY, ALL_PROXY, ...).
		// The permissive overrides applied in main.go ensure the generated
		// Seatbelt profile is wide-open for filesystem reads.
		return WrapCommandMacOS(m.config, command, m.exposedPorts, m.rewrittenEnvFiles, m.macOSTmpDir, m.debug)
	case platform.Linux:
		if m.tracesEnabled() {
			return m.wrapCommandWithTracing(command)
		}
		return WrapCommandLinuxWithOptions(m.config, command, m.proxyBridge, m.dnsBridge, m.reverseBridge, m.forwardBridge, m.dbusBridge, m.tun2socksPath, LinuxSandboxOptions{
			UseLandlock:       !m.watch,
			UseSeccomp:        !m.watch,
			UseEBPF:           !m.watch,
			Debug:             m.debug,
			Watch:             m.watch,
			RewrittenEnvFiles: m.rewrittenEnvFiles,
			AllowAudio:        m.config != nil && m.config.AllowAudio,
		})
	default:
		return "", fmt.Errorf("unsupported platform: %s", plat)
	}
}

// wrapCommandWithTracing creates a permissive sandbox with strace for either
// learning or record-fs mode on Linux. Landlock and seccomp must be disabled
// because seccomp blocks ptrace which strace requires.
func (m *Manager) wrapCommandWithTracing(command string) (string, error) {
	// Create host-side temp file for strace output.
	tmpFile, err := os.CreateTemp("", "greywall-strace-*.log")
	if err != nil {
		return "", fmt.Errorf("failed to create strace log file: %w", err)
	}
	_ = tmpFile.Close()
	m.straceLogPath = tmpFile.Name()

	m.logDebug("Strace log file: %s (learning=%v recordFs=%v)", m.straceLogPath, m.learning, m.recordFs)

	return WrapCommandLinuxWithOptions(m.config, command, m.proxyBridge, m.dnsBridge, m.reverseBridge, m.forwardBridge, m.dbusBridge, m.tun2socksPath, LinuxSandboxOptions{
		UseLandlock:       false, // Disabled: seccomp blocks ptrace which strace needs
		UseSeccomp:        false, // Disabled: conflicts with strace
		UseEBPF:           false,
		Debug:             m.debug,
		Learning:          m.learning,
		RecordFs:          m.recordFs,
		Watch:             m.watch,
		StraceLogPath:     m.straceLogPath,
		RewrittenEnvFiles: m.rewrittenEnvFiles,
		AllowAudio:        m.config != nil && m.config.AllowAudio,
	})
}

// GenerateLearnedTemplate generates a config profile from the trace log collected during learning.
// Platform-specific implementation in manager_linux.go / manager_darwin.go.
func (m *Manager) GenerateLearnedTemplate(cmdName string) (string, error) {
	return m.generateLearnedTemplatePlatform(cmdName)
}

// SetRootPID records the PID of the sandboxed command's top-level process.
// Used by the macOS batch eslogger parser to build the process tree from
// fork events, and by the streaming tracer to seed its PID filter.
func (m *Manager) SetRootPID(pid int) {
	m.rootPID = pid
	m.logDebug("Set root PID: %d", pid)
}

// StartFsTracer launches the streaming filesystem-event tracer if
// record-fs is enabled and an FsEventBuffer has been installed. Safe to
// call when record-fs is off (returns nil without starting anything).
//
// Timing: on Linux this can be called any time after WrapCommand has run
// (the strace log path exists, even if strace itself hasn't written to it
// yet). On macOS it should be called after SetRootPID so the tracer can
// filter to the sandboxed process tree.
//
// The tracer continues running until Cleanup is called. ctx is propagated
// to the tracer goroutine; canceling it also stops the tracer.
func (m *Manager) StartFsTracer(ctx context.Context) error {
	if !m.recordFs || m.fsBuf == nil {
		return nil
	}
	if m.tracer != nil {
		return nil // already started
	}

	var logPath string
	switch platform.Detect() {
	case platform.Linux:
		logPath = m.straceLogPath
	case platform.MacOS:
		logPath = m.esloggerLogPath
	default:
		return fmt.Errorf("fs-event recording not supported on this platform")
	}
	if logPath == "" {
		return fmt.Errorf("fs tracer: no log path available (was tracing initialized?)")
	}

	tracer := NewStreamingTracer(m.fsBuf, m.debug)
	if err := tracer.Start(ctx, logPath, m.rootPID); err != nil {
		return fmt.Errorf("start fs tracer: %w", err)
	}
	m.tracer = tracer
	m.logDebug("Started fs event tracer (log=%s rootPID=%d)", logPath, m.rootPID)
	return nil
}

// Cleanup stops the proxies and cleans up resources.
func (m *Manager) Cleanup() {
	// Stop the streaming fs tracer first so it can drain any remaining
	// bytes from the strace/eslogger log before those processes exit.
	if m.tracer != nil {
		m.logDebug("Stopping fs event tracer")
		m.tracer.Stop()
		m.tracer = nil
	}

	// Stop macOS eslogger if running
	if m.esloggerCmd != nil && m.esloggerCmd.Process != nil {
		m.logDebug("Stopping eslogger (PID %d)", m.esloggerCmd.Process.Pid)
		_ = m.esloggerCmd.Process.Signal(os.Interrupt)
		_ = m.esloggerCmd.Wait()
		m.esloggerCmd = nil
	}

	if m.dbusBridge != nil {
		m.dbusBridge.Cleanup()
	}
	if m.forwardBridge != nil {
		m.forwardBridge.Cleanup()
	}
	if m.reverseBridge != nil {
		m.reverseBridge.Cleanup()
	}
	if m.dnsBridge != nil {
		m.dnsBridge.Cleanup()
	}
	if m.proxyBridge != nil {
		m.proxyBridge.Cleanup()
	}
	if m.tun2socksPath != "" {
		_ = os.Remove(m.tun2socksPath)
	}
	if m.straceLogPath != "" {
		_ = os.Remove(m.straceLogPath)
		m.straceLogPath = ""
	}
	if m.esloggerLogPath != "" {
		_ = os.Remove(m.esloggerLogPath)
		m.esloggerLogPath = ""
	}
	if m.macOSTmpDir != "" {
		_ = os.RemoveAll(m.macOSTmpDir)
		m.macOSTmpDir = ""
	}
	m.logDebug("Sandbox manager cleaned up")
}

func (m *Manager) logDebug(format string, args ...interface{}) {
	if m.debug {
		fmt.Fprintf(os.Stderr, "[greywall] "+format+"\n", args...)
	}
}
