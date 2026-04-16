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

func TestStripPrefix(t *testing.T) {
	cases := []struct {
		name       string
		exe        string
		prefix     string
		wantPath   string
		wantOk     bool
	}{
		{"no prefix", "/usr/bin/bash", "", "/usr/bin/bash", false},
		{"prefix matches", "/tmp/gw/usr/bin/bash", "/tmp/gw", "/usr/bin/bash", true},
		{"prefix with trailing slash", "/tmp/gw/usr/bin/bash", "/tmp/gw/", "/usr/bin/bash", true},
		{"prefix is root", "/usr/bin/bash", "/", "/usr/bin/bash", false}, // "/" prefix is a no-op
		{"prefix sibling not substring", "/tmp/gwfoo/bin/bash", "/tmp/gw", "/tmp/gwfoo/bin/bash", false},
		{"prefix equals exe", "/tmp/gw", "/tmp/gw", "/tmp/gw", false}, // no trailing component
		{"no match", "/other/bin/bash", "/tmp/gw", "/other/bin/bash", false},
		{"empty exe", "", "/tmp/gw", "", false},
	}
	for _, c := range cases {
		got, ok := stripPrefix(c.exe, c.prefix)
		if got != c.wantPath || ok != c.wantOk {
			t.Errorf("%s: stripPrefix(%q,%q) = (%q,%v), want (%q,%v)",
				c.name, c.exe, c.prefix, got, ok, c.wantPath, c.wantOk)
		}
	}
}

func TestResolverStripPrefixApplied(t *testing.T) {
	// Build a resolver with a strip prefix and check Resolve(self)
	// returns the exe without the prefix if it happens to match. We
	// synthesize a "prefix match" by using os.Executable as the exe
	// and stripping its leading dir.
	r := NewProcResolver(0)
	selfExe, err := os.Executable()
	if err != nil || selfExe == "" {
		t.Skip("no self exe")
	}
	// Strip the first directory component to simulate a prefix.
	// e.g. "/tmp/go-build.../fuse.test" → prefix "/tmp" → "/go-build.../fuse.test"
	if len(selfExe) < 5 {
		t.Skip("self exe too short")
	}
	slash := strings.Index(selfExe[1:], "/")
	if slash < 0 {
		t.Skip("no leading dir")
	}
	r.StripPrefix = selfExe[:1+slash]
	info := r.Resolve(uint32(os.Getpid()))
	if strings.HasPrefix(info.Exe, r.StripPrefix+"/") {
		t.Errorf("StripPrefix not applied: exe=%q prefix=%q", info.Exe, r.StripPrefix)
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
