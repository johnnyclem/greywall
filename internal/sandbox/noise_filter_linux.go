//go:build linux

package sandbox

import "strings"

// IsStartupNoise reports whether an FsEvent should be hidden from the
// --record-fs-verbose stderr transcript on Linux. It targets paths the
// dynamic linker and libc touch on every process start: the ld.so cache,
// the linker itself, the glibc locale archive, and the /proc self-
// introspection files. None of these convey signal about what the
// wrapped command is doing.
//
// The dashboard heartbeat is unaffected: it still ships every event to
// greyproxy. This filter only runs on the stderr verbose sink.
func IsStartupNoise(e FsEvent) bool {
	path := e.Path
	if path == "" {
		return false
	}

	// Dynamic linker cache + the linker itself across the usual arches.
	if path == "/etc/ld.so.cache" {
		return true
	}
	if strings.HasPrefix(path, "/lib/ld-") ||
		strings.HasPrefix(path, "/lib64/ld-") ||
		strings.HasPrefix(path, "/lib/x86_64-linux-gnu/ld-") ||
		strings.HasPrefix(path, "/lib/aarch64-linux-gnu/ld-") ||
		strings.HasPrefix(path, "/usr/lib/ld-") {
		return true
	}

	// glibc consolidates all locales into one mmap'd archive; setlocale
	// touches it on every startup.
	if path == "/usr/lib/locale/locale-archive" {
		return true
	}

	// /proc self-introspection done by the runtime on startup.
	if strings.HasPrefix(path, "/proc/self/") {
		return true
	}

	// Common device opens libc / shells do at startup.
	switch path {
	case "/dev/null", "/dev/urandom", "/dev/random", "/dev/tty":
		return true
	}

	return false
}
