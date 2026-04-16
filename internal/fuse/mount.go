package fuse

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	gofs "github.com/hanwen/go-fuse/v2/fs"
	gofuse "github.com/hanwen/go-fuse/v2/fuse"
)

// Mount represents a live FUSE passthrough mount.
type Mount struct {
	Point   string
	Backing string
	Server  *gofuse.Server
}

// Config is the set of knobs for creating a Mount.
type Config struct {
	// Backing is the directory on the real filesystem that the FUSE
	// mount exposes. Defaults to "/".
	Backing string
	// MountPoint is where the FUSE filesystem will be mounted.
	MountPoint string
	// Hooks carries the rules engine, resolver, and event sink.
	Hooks *Hooks
	// Debug enables go-fuse's verbose request logging.
	Debug bool
}

// New mounts a FUSE passthrough at cfg.MountPoint backed by cfg.Backing.
// The caller must invoke Close to unmount.
func New(cfg Config) (*Mount, error) {
	if cfg.Backing == "" {
		cfg.Backing = "/"
	}
	if cfg.MountPoint == "" {
		return nil, fmt.Errorf("mount point required")
	}
	if cfg.Hooks == nil {
		return nil, fmt.Errorf("hooks required")
	}
	if err := os.MkdirAll(cfg.MountPoint, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir mount point: %w", err)
	}

	_, rootNode, err := newHookedRoot(cfg.Backing, cfg.Hooks)
	if err != nil {
		return nil, fmt.Errorf("build root: %w", err)
	}

	opts := &gofs.Options{}
	opts.Debug = cfg.Debug
	opts.MountOptions = gofuse.MountOptions{
		Debug:      cfg.Debug,
		Name:       "greywall-fuse",
		FsName:     cfg.Backing,
		AllowOther: false,
		// Short entry/attr TTLs so rule decisions stay live rather
		// than being cached inside the kernel.
	}
	opts.EntryTimeout = ptrDuration(200 * time.Millisecond)
	opts.AttrTimeout = ptrDuration(200 * time.Millisecond)

	server, err := gofs.Mount(cfg.MountPoint, rootNode, opts)
	if err != nil {
		return nil, fmt.Errorf("mount: %w", err)
	}

	return &Mount{
		Point:   cfg.MountPoint,
		Backing: cfg.Backing,
		Server:  server,
	}, nil
}

// Wait blocks until the mount is unmounted (e.g. via fusermount3 -u or
// Close).
func (m *Mount) Wait() {
	m.Server.Wait()
}

// Close unmounts and removes the mount point directory. It is safe to
// call multiple times; the second call is a no-op.
func (m *Mount) Close() error {
	if m == nil || m.Server == nil {
		return nil
	}
	err := m.Server.Unmount()
	// Fallback: if go-fuse could not unmount cleanly, try fusermount3.
	if err != nil {
		if fm, ferr := exec.LookPath("fusermount3"); ferr == nil {
			_ = exec.Command(fm, "-u", m.Point).Run()
		}
	}
	m.Server = nil
	return err
}

func ptrDuration(d time.Duration) *time.Duration { return &d }
