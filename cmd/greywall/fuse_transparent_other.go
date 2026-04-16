//go:build !linux

package main

import "syscall"

// transparentSysProcAttr is a no-op on non-Linux platforms. The
// transparent mode relies on Linux user and mount namespaces and
// is blocked at the CLI level elsewhere.
func transparentSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
