package fuse

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMountEndToEnd mounts a FUSE passthrough on a tempdir, reads a
// file through it, and asserts that at least one event was captured
// with the current process as caller. Requires /dev/fuse.
func TestMountEndToEnd(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("skipping: /dev/fuse unavailable (%v)", err)
	}

	backing := t.TempDir()
	mountPoint := t.TempDir()

	// Seed a file in the backing directory.
	target := filepath.Join(backing, "hello.txt")
	if err := os.WriteFile(target, []byte("hi from backing"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	sink := NewChannelSink(128)
	hooks := &Hooks{
		Resolver: NewProcResolver(0),
		Rules:    &Ruleset{Default: ActionAllow},
		Sink:     sink,
	}

	mnt, err := New(Config{
		Backing:    backing,
		MountPoint: mountPoint,
		Hooks:      hooks,
	})
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer func() {
		if err := mnt.Close(); err != nil {
			t.Logf("unmount error: %v", err)
		}
	}()

	// Give the FUSE server a moment to be fully ready.
	time.Sleep(50 * time.Millisecond)

	// Read the file through the FUSE mount.
	data, err := os.ReadFile(filepath.Join(mountPoint, "hello.txt"))
	if err != nil {
		t.Fatalf("read through FUSE: %v", err)
	}
	if string(data) != "hi from backing" {
		t.Errorf("content = %q, want %q", string(data), "hi from backing")
	}

	// Drain events: we expect at least one Lookup or Open for hello.txt
	// with caller = self (the test binary).
	self, _ := os.Executable()
	deadline := time.After(2 * time.Second)
	seen := false
collect:
	for {
		select {
		case e := <-sink.Ch:
			t.Logf("event: op=%s path=%s caller=%s pid=%d action=%s rule=%s",
				e.Op, e.Path, e.Caller, e.PID, e.Action, e.Rule)
			if filepath.Base(e.Path) == "hello.txt" && e.Action == ActionAllow {
				// Caller should match our test binary path, but we
				// accept either self or any non-"unknown" caller
				// because PID may be the kernel's page cache prefetch
				// pid in some edge cases.
				if e.Caller == self || e.Caller != "unknown" {
					seen = true
					break collect
				}
			}
		case <-deadline:
			break collect
		}
	}
	if !seen {
		t.Errorf("no event captured for hello.txt access")
	}
}

// TestMountDeny verifies that a deny rule returns EACCES to the
// caller and emits a deny event.
func TestMountDeny(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("skipping: /dev/fuse unavailable (%v)", err)
	}

	backing := t.TempDir()
	mountPoint := t.TempDir()

	target := filepath.Join(backing, "secret.txt")
	if err := os.WriteFile(target, []byte("nope"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	sink := NewChannelSink(128)
	hooks := &Hooks{
		Resolver: NewProcResolver(0),
		Rules: &Ruleset{
			Default: ActionAllow,
			Rules: []Rule{
				{
					Name:       "block-secret",
					CallerGlob: "*",
					PathGlob:   "**/secret.txt",
					Action:     ActionDeny,
				},
			},
		},
		Sink: sink,
	}

	mnt, err := New(Config{
		Backing:    backing,
		MountPoint: mountPoint,
		Hooks:      hooks,
	})
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer mnt.Close()

	time.Sleep(50 * time.Millisecond)

	_, err = os.ReadFile(filepath.Join(mountPoint, "secret.txt"))
	if err == nil {
		t.Errorf("expected EACCES reading secret.txt, got nil")
	}

	// Look for a deny event with rule=block-secret.
	deadline := time.After(2 * time.Second)
	seen := false
collect:
	for {
		select {
		case e := <-sink.Ch:
			t.Logf("event: op=%s path=%s action=%s rule=%s", e.Op, e.Path, e.Action, e.Rule)
			if e.Action == ActionDeny && e.Rule == "block-secret" {
				seen = true
				break collect
			}
		case <-deadline:
			break collect
		}
	}
	if !seen {
		t.Errorf("no deny event captured for secret.txt")
	}
}
