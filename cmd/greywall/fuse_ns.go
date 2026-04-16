//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
)

// newFuseNsSetupCmd returns the hidden `fuse-ns-setup` subcommand that
// runs inside the child of a CLONE_NEWUSER|CLONE_NEWNS fork spawned by
// `greywall fuse --transparent`. It:
//
//  1. Makes the root mount propagation private so its bind mounts do
//     not leak back to the parent namespace.
//  2. Bind-mounts the real /proc, /sys, /dev over the corresponding
//     paths inside the FUSE mount point. This means pseudo-filesystems
//     are served from the kernel, not through the FUSE daemon (which
//     lives in the parent namespace and would serve the wrong view of
//     /proc/self, /proc/<pid>, etc).
//  3. chroots into the FUSE mount so `/` for this child IS the FUSE
//     passthrough. Every absolute path the child resolves now goes
//     through the hook layer.
//  4. chdirs to the configured target.
//  5. execs the user command.
//
// Invocation (positional, no flag parsing):
//
//	greywall fuse-ns-setup <mountPoint> <chdirInChroot> <target> [args...]
func newFuseNsSetupCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "fuse-ns-setup",
		Hidden:             true,
		DisableFlagParsing: true,
		SilenceUsage:       true,
		SilenceErrors:      false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFuseNsSetup(args)
		},
	}
}

func runFuseNsSetup(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("fuse-ns-setup: need <mountPoint> <chdir> <target> [args...], got %d arg(s)", len(args))
	}
	mountPoint := args[0]
	chdirTo := args[1]
	targetArgs := args[2:]

	// 1. Make / propagation private so our new bind mounts do not
	//    leak back to the parent namespace.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / rprivate: %w", err)
	}

	// 2. Bind-mount essential pseudo-filesystems.
	binds := []struct {
		src, dst string
		flags    uintptr
	}{
		{"/proc", filepath.Join(mountPoint, "proc"), syscall.MS_BIND | syscall.MS_REC},
		{"/sys", filepath.Join(mountPoint, "sys"), syscall.MS_BIND | syscall.MS_REC},
		{"/dev", filepath.Join(mountPoint, "dev"), syscall.MS_BIND | syscall.MS_REC},
	}
	for _, b := range binds {
		if _, err := os.Stat(b.src); err != nil {
			fmt.Fprintf(os.Stderr, "[fuse-ns-setup] skip %s: %v\n", b.src, err)
			continue
		}
		// Target directory already exists via FUSE passthrough in the
		// common case (backing = /), but MkdirAll is harmless when the
		// backing already has it.
		_ = os.MkdirAll(b.dst, 0o755)
		if err := syscall.Mount(b.src, b.dst, "", b.flags, ""); err != nil {
			fmt.Fprintf(os.Stderr, "[fuse-ns-setup] warning: bind %s -> %s: %v\n", b.src, b.dst, err)
		}
	}

	// 3. chroot into the FUSE mount. After this, `/` is the FUSE root.
	if err := syscall.Chroot(mountPoint); err != nil {
		return fmt.Errorf("chroot %s: %w", mountPoint, err)
	}

	// 4. chdir inside the new root.
	target := "/"
	if chdirTo != "" && chdirTo != "-" {
		target = chdirTo
	}
	if err := syscall.Chdir(target); err != nil {
		fmt.Fprintf(os.Stderr, "[fuse-ns-setup] warning: chdir %s: %v, falling back to /\n", target, err)
		_ = syscall.Chdir("/")
	}

	// 5. Resolve the target binary via PATH if necessary and exec.
	bin := targetArgs[0]
	if !filepath.IsAbs(bin) {
		if p, err := exec.LookPath(bin); err == nil {
			bin = p
		}
	}
	if err := syscall.Exec(bin, targetArgs, os.Environ()); err != nil {
		return fmt.Errorf("exec %s: %w", bin, err)
	}
	// unreachable
	return nil
}
