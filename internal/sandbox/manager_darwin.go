//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// generateLearnedTemplatePlatform stops eslogger,
// parses the eslogger log with PID-based process tree filtering,
// and generates a profile (macOS).
func (m *Manager) generateLearnedTemplatePlatform(cmdName string) (string, error) {
	if m.esloggerLogPath == "" {
		return "", fmt.Errorf("no eslogger log available (was learning mode enabled?)")
	}

	// Stop eslogger before parsing. It's detached (reparented to launchd),
	// so we signal the process group and poll until it exits — we can't
	// Wait() on a non-child. SIGTERM gives eslogger a chance to flush;
	// fall back to SIGKILL after a short grace period.
	if m.esloggerPid > 0 {
		_ = syscall.Kill(-m.esloggerPid, syscall.SIGTERM)
		for range 20 { // up to 1s
			if syscall.Kill(m.esloggerPid, 0) != nil {
				break // process gone
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = syscall.Kill(-m.esloggerPid, syscall.SIGKILL)
		m.esloggerPid = 0
	}

	// Parse eslogger log with root PID for process tree tracking
	result, err := ParseEsloggerLog(m.esloggerLogPath, m.rootPID, m.debug)
	if err != nil {
		return "", fmt.Errorf("failed to parse eslogger log: %w", err)
	}

	templatePath, err := GenerateLearnedTemplate(result, cmdName, m.debug)
	if err != nil {
		return "", err
	}

	// Clean up eslogger log
	_ = os.Remove(m.esloggerLogPath)
	m.esloggerLogPath = ""

	return templatePath, nil
}
