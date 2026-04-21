//go:build linux

// greywall-netns-helper creates and enters a persistent network namespace
// with a tun2socks bridge to an external SOCKS5 proxy. It is intended to be
// installed with file capabilities so it (and only it) can create and enter
// netns as an unprivileged user:
//
//	setcap cap_net_admin,cap_sys_admin+ep /usr/local/bin/greywall-netns-helper
//
// This binary has three subcommands:
//
//	create  --proxy URL [--tun2socks PATH]
//	    Creates a new netns, sets up tun0 + default route via tun2socks,
//	    pins the netns at /run/greywall/ns-<uuid>, writes the tun2socks PID
//	    at <pin>.pid, prints the pin path and exits.
//
//	exec    --netns PATH -- COMMAND [ARGS...]
//	    Enters the pinned netns, drops ALL capabilities, then exec's
//	    COMMAND. Used by greywall's --netns flag to run the wrapped command
//	    inside the netns without handing the caller any privilege.
//
//	destroy PATH
//	    Kills the tun2socks process, unmounts the netns pin, removes the
//	    pin file + sidecar .pid file.
//
// It does not act as a general-purpose nsenter / shell wrapper: the `exec`
// subcommand strictly refuses netns paths outside /run/greywall and drops
// all caps before exec'ing the user command.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	pinDir = "/run/greywall"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "create":
		cmdCreate(os.Args[2:])
	case "exec":
		cmdExec(os.Args[2:])
	case "destroy":
		cmdDestroy(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "greywall-netns-helper: unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  greywall-netns-helper create --proxy socks5://host:port [--tun2socks /path/to/tun2socks]")
	fmt.Fprintln(os.Stderr, "  greywall-netns-helper exec --netns /run/greywall/ns-<id> -- <command> [args...]")
	fmt.Fprintln(os.Stderr, "  greywall-netns-helper destroy /run/greywall/ns-<id>")
}

// -----------------------------------------------------------------------------
// create
// -----------------------------------------------------------------------------

func cmdCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	proxy := fs.String("proxy", "", "SOCKS5 proxy URL, e.g. socks5://host:port (required)")
	tun2socksBin := fs.String("tun2socks", "/usr/local/bin/tun2socks", "Path to tun2socks binary")
	debug := fs.Bool("debug", false, "Verbose stderr logging")
	_ = fs.Parse(args)

	if *proxy == "" {
		die("create: --proxy is required")
	}
	if _, err := os.Stat(*tun2socksBin); err != nil {
		die("create: tun2socks binary not found at %s: %v", *tun2socksBin, err)
	}

	// Lock OS thread so the netns unshare only affects this thread. We
	// exec tun2socks (as a child) and exit, so the lock is temporary.
	runtime.LockOSThread()

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		die("create: unshare(CLONE_NEWNET) failed: %v (need CAP_SYS_ADMIN)", err)
	}

	// File caps put CAP_NET_ADMIN/CAP_SYS_ADMIN in our permitted+effective,
	// but children do NOT inherit those unless we raise them into the
	// ambient set. `ip` and `tun2socks` are separate binaries that need
	// CAP_NET_ADMIN to manipulate interfaces.
	if err := raiseAmbient(capNetAdmin); err != nil {
		die("create: raise ambient CAP_NET_ADMIN: %v", err)
	}

	// We're now in a fresh netns. lo is down; tun0 does not yet exist.
	setupCmds := [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "tuntap", "add", "dev", "tun0", "mode", "tun"},
		{"ip", "addr", "add", "198.18.0.1/15", "dev", "tun0"},
		{"ip", "link", "set", "tun0", "up"},
		{"ip", "route", "add", "default", "via", "198.18.0.1", "dev", "tun0"},
	}
	for _, c := range setupCmds {
		cmd := exec.Command(c[0], c[1:]...) //nolint:gosec // args are fixed strings
		if out, err := cmd.CombinedOutput(); err != nil {
			die("create: %s failed: %v\n  %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
		if *debug {
			fmt.Fprintf(os.Stderr, "[netns-helper] %s ok\n", strings.Join(c, " "))
		}
	}

	// Pin the netns at /run/greywall/ns-<uuid>
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		die("create: mkdir %s: %v", pinDir, err)
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		die("create: rand: %v", err)
	}
	pinPath := filepath.Join(pinDir, fmt.Sprintf("ns-%s", hex.EncodeToString(id)))

	// Pre-create the mount target as an empty regular file.
	f, err := os.OpenFile(pinPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		die("create: pin file %s: %v", pinPath, err)
	}
	_ = f.Close()

	if err := unix.Mount("/proc/self/ns/net", pinPath, "", unix.MS_BIND, ""); err != nil {
		_ = os.Remove(pinPath)
		die("create: bind mount netns to %s: %v", pinPath, err)
	}

	// Launch tun2socks inside this netns. Because we unshared earlier, our
	// children inherit the new netns.
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		cleanupPin(pinPath)
		die("create: open /dev/null: %v", err)
	}

	cmd := exec.Command(*tun2socksBin, "-device", "tun0", "-proxy", *proxy) //nolint:gosec // proxy/tun2socks validated above
	cmd.Stdin = devnull
	cmd.Stdout = devnull
	cmd.Stderr = devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = devnull.Close()
		cleanupPin(pinPath)
		die("create: tun2socks start: %v", err)
	}
	_ = devnull.Close()

	// Record the pid so destroy can stop it cleanly.
	if err := os.WriteFile(pinPath+".pid", []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o644); err != nil {
		if *debug {
			fmt.Fprintf(os.Stderr, "[netns-helper] warning: failed to write pidfile: %v\n", err)
		}
	}

	if *debug {
		fmt.Fprintf(os.Stderr, "[netns-helper] tun2socks pid=%d, pin=%s\n", cmd.Process.Pid, pinPath)
	}
	fmt.Println(pinPath)
}

func cleanupPin(path string) {
	_ = unix.Unmount(path, 0)
	_ = os.Remove(path)
	_ = os.Remove(path + ".pid")
}

// -----------------------------------------------------------------------------
// exec
// -----------------------------------------------------------------------------

func cmdExec(args []string) {
	// Parse: --netns PATH [--] <command> [args...]
	var netnsPath string
	var cmdStart int
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--netns":
			if i+1 >= len(args) {
				die("exec: --netns requires a value")
			}
			netnsPath = args[i+1]
			i++
		case "--":
			cmdStart = i + 1
			goto runit
		default:
			cmdStart = i
			goto runit
		}
	}
runit:
	if netnsPath == "" {
		die("exec: --netns is required")
	}
	if cmdStart >= len(args) {
		die("exec: no command specified")
	}
	if err := validatePinPath(netnsPath); err != nil {
		die("exec: %v", err)
	}
	command := args[cmdStart:]

	// Open the netns fd first (while we still have CAP_SYS_ADMIN).
	fd, err := unix.Open(netnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		die("exec: open %s: %v", netnsPath, err)
	}

	// Lock the thread, enter the netns, then drop caps. We will exec
	// momentarily which replaces the whole process so the lock is safe.
	runtime.LockOSThread()

	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		die("exec: setns: %v", err)
	}
	_ = unix.Close(fd)

	if err := dropAllCaps(); err != nil {
		die("exec: dropAllCaps: %v", err)
	}
	// Also clear the bounding set so exec'd program cannot gain caps from
	// any file caps on the target binary.
	if err := clearBoundingSet(); err != nil {
		// Non-fatal: bounding-set clear can fail in some containers, but
		// we've already cleared permitted+effective which is the primary
		// defense.
		fmt.Fprintf(os.Stderr, "[netns-helper] warning: clearBoundingSet: %v\n", err)
	}

	// Find the target and exec (replaces current process).
	execPath, err := exec.LookPath(command[0])
	if err != nil {
		die("exec: command not found: %s", command[0])
	}
	if err := syscall.Exec(execPath, command, os.Environ()); err != nil { //nolint:gosec
		die("exec: syscall.Exec: %v", err)
	}
}

// validatePinPath rejects anything outside pinDir to prevent abuse of the
// file caps for arbitrary netns entry.
func validatePinPath(path string) error {
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", path, err)
	}
	if !strings.HasPrefix(clean, pinDir+"/") {
		return fmt.Errorf("netns path must be under %s (got %s)", pinDir, clean)
	}
	if strings.Contains(clean, "/..") {
		return errors.New("netns path must not contain ..")
	}
	return nil
}

// -----------------------------------------------------------------------------
// destroy
// -----------------------------------------------------------------------------

func cmdDestroy(args []string) {
	if len(args) != 1 {
		die("destroy: exactly one pin path required")
	}
	path := args[0]
	if err := validatePinPath(path); err != nil {
		die("destroy: %v", err)
	}

	// Stop tun2socks if we know its pid.
	if data, err := os.ReadFile(path + ".pid"); err == nil {
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil && pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
	}

	cleanupPin(path)
}

// -----------------------------------------------------------------------------
// capability helpers
// -----------------------------------------------------------------------------

// capUserHeader matches Linux's cap_user_header_t.
type capUserHeader struct {
	version uint32
	pid     int32
}

// capUserData matches Linux's cap_user_data_t for _LINUX_CAPABILITY_VERSION_3.
type capUserData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// _LINUX_CAPABILITY_VERSION_3 (linux/capability.h)
const linuxCapabilityVersion3 = 0x20080522

// Capability numbers we use; matches include/uapi/linux/capability.h.
const (
	capNetAdmin = 12
	capSysAdmin = 21
)

// prctlCapAmbientClearAll = PR_CAP_AMBIENT_CLEAR_ALL (prctl.h).
const prctlCapAmbientClearAll = 4

// raiseAmbient promotes a capability into the ambient set so that children
// exec'd by this process inherit it. The cap must already be in both the
// permitted and inheritable sets — we add it to inheritable first.
func raiseAmbient(capNum int) error {
	hdr := capUserHeader{version: linuxCapabilityVersion3, pid: 0}
	var data [2]capUserData
	if _, _, errno := unix.Syscall(
		unix.SYS_CAPGET,
		uintptr(unsafe.Pointer(&hdr)),  //nolint:gosec
		uintptr(unsafe.Pointer(&data)), //nolint:gosec
		0,
	); errno != 0 {
		return fmt.Errorf("capget: %w", errno)
	}

	idx := capNum / 32
	bit := uint32(1) << (capNum % 32) //nolint:gosec // capNum fits in uint32
	if data[idx].permitted&bit == 0 {
		return fmt.Errorf("cap %d not in permitted set (file caps missing?)", capNum)
	}
	data[idx].inheritable |= bit

	if _, _, errno := unix.Syscall(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),  //nolint:gosec
		uintptr(unsafe.Pointer(&data)), //nolint:gosec
		0,
	); errno != 0 {
		return fmt.Errorf("capset (add to inheritable): %w", errno)
	}

	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(capNum), 0, 0); err != nil {
		return fmt.Errorf("PR_CAP_AMBIENT_RAISE(%d): %w", capNum, err)
	}
	return nil
}

// dropAllCaps clears effective, permitted, inheritable AND the ambient
// capability set for the calling thread. We call this just before
// syscall.Exec so the exec'd program starts with empty caps and cannot
// pick any up via ambient inheritance.
func dropAllCaps() error {
	// Clear ambient first (requires only caller privilege; no caps needed).
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, prctlCapAmbientClearAll, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_CAP_AMBIENT_CLEAR_ALL: %w", err)
	}

	hdr := capUserHeader{version: linuxCapabilityVersion3, pid: 0}
	var data [2]capUserData // all zero
	_, _, errno := unix.Syscall(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),  //nolint:gosec // syscall needs pointer
		uintptr(unsafe.Pointer(&data)), //nolint:gosec // syscall needs pointer
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// clearBoundingSet drops every capability from the thread's bounding set
// via repeated PR_CAPBSET_DROP calls. Enumerates 0..64 which covers all
// currently-defined caps.
func clearBoundingSet() error {
	for capNum := 0; capNum < 64; capNum++ {
		// Ignore EINVAL for unknown cap numbers.
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capNum), 0, 0, 0)
	}
	return nil
}

// -----------------------------------------------------------------------------

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "greywall-netns-helper: "+format+"\n", args...)
	os.Exit(1)
}
