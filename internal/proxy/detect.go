// Package proxy provides greyproxy detection, installation, and lifecycle management.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	healthURL     = "http://localhost:43080/api/health"
	healthTimeout = 2 * time.Second
	cmdTimeout    = 5 * time.Second

	// MinVersionFsEvents is the minimum greyproxy version that accepts
	// FsEvent payloads in the heartbeat body. Older versions ignore the
	// JSON body or 400 the request, so greywall must disable --record-fs
	// against them. Placeholder above the latest shipped greyproxy until
	// the maintainer lands the handler — bump (downward, to the actual
	// release tag) when that ships.
	MinVersionFsEvents = "0.5.0"
)

// GreyproxyStatus holds the detected state of greyproxy.
type GreyproxyStatus struct {
	Installed  bool   // found via exec.LookPath
	Path       string // full path from LookPath
	Version    string // parsed version (e.g. "0.1.1")
	Running    bool   // health endpoint responded with valid greyproxy response
	RunningErr error  // error from the running check (for diagnostics)
}

// healthResponse is the expected JSON from GET /api/health.
type healthResponse struct {
	Service string         `json:"service"`
	Version string         `json:"version"`
	Status  string         `json:"status"`
	Ports   map[string]int `json:"ports"`
}

var versionRegex = regexp.MustCompile(`^greyproxy\s+v?(\S+)`)

// Detect checks greyproxy installation status, version, and whether it's running.
// This function never returns an error; all detection failures are captured
// in the GreyproxyStatus fields so the caller can present them diagnostically.
func Detect() *GreyproxyStatus {
	s := &GreyproxyStatus{}

	// 1. Check if installed
	s.Path, s.Installed = checkInstalled()

	// 2. Check if running (via health endpoint)
	running, ver, err := checkRunning()
	s.Running = running
	s.RunningErr = err
	if running && ver != "" {
		s.Version = ver
	}

	// 3. Version fallback: if installed but version not yet known, parse from CLI
	if s.Installed && s.Version == "" {
		s.Version, _ = checkVersion(s.Path)
	}

	return s
}

// checkInstalled uses exec.LookPath to find greyproxy on PATH.
func checkInstalled() (path string, found bool) {
	p, err := exec.LookPath("greyproxy")
	if err != nil {
		return "", false
	}
	return p, true
}

// checkVersion runs "greyproxy -V" and parses the output.
// Expected format: "greyproxy 0.1.1 (go1.x linux/amd64)"
func checkVersion(binaryPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, binaryPath, "-V").Output() //nolint:gosec // binaryPath comes from exec.LookPath
	if err != nil {
		return "", fmt.Errorf("failed to run greyproxy -V: %w", err)
	}

	matches := versionRegex.FindStringSubmatch(strings.TrimSpace(string(out)))
	if len(matches) < 2 {
		return "", fmt.Errorf("unexpected version output: %s", strings.TrimSpace(string(out)))
	}
	return matches[1], nil
}

// SupportsFsEvents reports whether the given greyproxy version accepts
// FsEvent payloads in the heartbeat body. An empty version or the
// "dev" sentinel is treated as supported so local development builds
// are not blocked.
func SupportsFsEvents(version string) bool {
	if version == "" || version == "dev" {
		return true
	}
	return !IsOlderVersion(version, MinVersionFsEvents)
}

// checkRunning hits GET http://localhost:43080/api/health and verifies
// the response is from greyproxy (not some other service on that port).
// Returns running status, version string from health response, and any error.
func checkRunning() (bool, string, error) {
	client := &http.Client{Timeout: healthTimeout}

	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req) //nolint:gosec // healthURL is a hardcoded localhost constant
	if err != nil {
		return false, "", fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	var health healthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return false, "", fmt.Errorf("failed to parse health response: %w", err)
	}

	if health.Service != "greyproxy" {
		return false, "", fmt.Errorf("unexpected service: %q (expected greyproxy)", health.Service)
	}

	return true, health.Version, nil
}
