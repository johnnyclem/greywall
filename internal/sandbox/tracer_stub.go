//go:build !linux && !darwin

package sandbox

import (
	"context"
	"fmt"
)

// StreamingTracer is a no-op on platforms without a filesystem tracer
// (anything other than Linux strace and macOS eslogger). All methods are
// safe to call; Start returns an error to signal the feature is
// unavailable.
type StreamingTracer struct {
	buf   *FsEventBuffer
	debug bool
}

// NewStreamingTracer constructs a no-op tracer.
func NewStreamingTracer(buf *FsEventBuffer, debug bool) *StreamingTracer {
	return &StreamingTracer{buf: buf, debug: debug}
}

// Start returns an error: filesystem event streaming is only available on
// Linux and macOS.
func (t *StreamingTracer) Start(_ context.Context, _ string, _ int) error {
	return fmt.Errorf("filesystem event streaming is not supported on this platform")
}

// Stop is a no-op.
func (t *StreamingTracer) Stop() {}
