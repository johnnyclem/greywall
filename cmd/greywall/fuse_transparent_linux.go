//go:build linux

package main

import (
	"os"
	"syscall"
)

// transparentSysProcAttr returns SysProcAttr that unshares a user and
// mount namespace with the calling uid/gid mapped to root in the new
// namespace. The helper process (greywall fuse-ns-setup) then runs as
// "root" in its own user namespace — enough to call mount(2) and
// chroot(2) without any real-world privilege.
func transparentSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getuid(),
			Size:        1,
		}},
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getgid(),
			Size:        1,
		}},
		// setgroups must be denied before writing gid_map in an
		// unprivileged user namespace; Go handles this automatically
		// when GidMappingsEnableSetgroups is false.
		GidMappingsEnableSetgroups: false,
	}
}
