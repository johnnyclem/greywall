package fuse

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestProcResolverResolveSelf(t *testing.T) {
	r := NewProcResolver(1 * time.Second)
	info := r.Resolve(uint32(os.Getpid()))

	if info.PID != uint32(os.Getpid()) {
		t.Errorf("PID = %d, want %d", info.PID, os.Getpid())
	}
	if info.Exe == "" || info.Exe == "unknown" {
		t.Errorf("Exe should resolve for self, got %q", info.Exe)
	}
	// Self exe is the Go test binary; it should be an absolute path.
	if !strings.HasPrefix(info.Exe, "/") {
		t.Errorf("Exe %q should be absolute", info.Exe)
	}
	if info.Comm == "" {
		t.Errorf("Comm should be non-empty for self")
	}
}

func TestProcResolverCacheHit(t *testing.T) {
	r := NewProcResolver(5 * time.Second)
	a := r.Resolve(uint32(os.Getpid()))
	b := r.Resolve(uint32(os.Getpid()))
	if a != b {
		t.Errorf("cached Resolve should return identical CallerInfo")
	}
}

func TestProcResolverUnknownPID(t *testing.T) {
	r := NewProcResolver(0)
	info := r.Resolve(1 << 30) // impossible PID
	if info.Exe != "unknown" {
		t.Errorf("Exe for unknown PID should be 'unknown', got %q", info.Exe)
	}
}

func TestParseStat(t *testing.T) {
	// Synthetic stat line: pid 1234, comm "my (odd) proc", state S,
	// ppid 1000, then filler until starttime at field 22.
	// /proc/<pid>/stat format:
	//   pid (comm) state ppid pgrp session tty_nr tpgid flags
	//   minflt cminflt majflt cmajflt utime stime cutime cstime
	//   priority nice num_threads itrealvalue starttime ...
	s := "1234 (my (odd) proc) S 1000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4242 xxx"
	ppid, start := parseStat(s)
	if ppid != 1000 {
		t.Errorf("ppid = %d, want 1000", ppid)
	}
	if start != 4242 {
		t.Errorf("starttime = %d, want 4242", start)
	}
}
