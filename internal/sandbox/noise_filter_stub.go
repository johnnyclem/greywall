//go:build !darwin && !linux

package sandbox

// IsStartupNoise is a no-op on platforms without a filesystem tracer.
// Returning false keeps every event in the verbose stream — there is
// no tracer producing events here anyway.
func IsStartupNoise(_ FsEvent) bool { return false }
