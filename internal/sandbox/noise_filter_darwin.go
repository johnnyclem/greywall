//go:build darwin

package sandbox

import "strings"

// IsStartupNoise reports whether an FsEvent should be hidden from the
// --record-fs-verbose stderr transcript on macOS. It targets paths that
// every exec on macOS touches — dyld preflight, locale lookups, the
// dtrace helper device — and the directory enumerations the loader does
// when resolving binaries on PATH. None of these convey signal about
// what the wrapped command is doing; they just bury the interesting
// events under tens of duplicates per exec.
//
// The dashboard heartbeat is unaffected: it still ships every event to
// greyproxy. This filter only runs on the stderr verbose sink.
func IsStartupNoise(e FsEvent) bool {
	path := e.Path
	if path == "" {
		return false
	}

	// dyld preflight: the loader stats / and the cryptex root on every
	// exec to find the system framework set.
	if path == "/" {
		return true
	}
	if strings.HasPrefix(path, "/System/Volumes/Preboot/Cryptexes/OS") {
		return true
	}

	// Locale resolution. setlocale() probes a deterministic list of
	// directories on every process start; none of it is interesting.
	if strings.HasPrefix(path, "/usr/share/locale/") {
		return true
	}

	// dtrace shim + controlling terminal opens libc does at startup.
	switch path {
	case "/dev/dtracehelper", "/dev/tty", "/dev/null":
		return true
	}

	// Directory enumerations done while the kernel resolves the exec
	// binary on PATH. The actual executable open (e.g. /bin/cat) is
	// kept — that one carries signal about what was run.
	switch path {
	case "/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin":
		return e.Op == "open_read"
	}

	return false
}
