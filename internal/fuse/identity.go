package fuse

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// CallerInfo describes the process that issued a FUSE operation.
type CallerInfo struct {
	PID       uint32
	PPID      uint32
	Exe       string // resolved /proc/<pid>/exe target, or "unknown"
	Comm      string // /proc/<pid>/comm
	StartTime uint64 // from /proc/<pid>/stat, used as cache key guard
}

// Resolver maps a PID to a CallerInfo.
type Resolver interface {
	Resolve(pid uint32) CallerInfo
}

// ProcResolver reads /proc/<pid>/* to resolve caller identity. It keeps a
// small LRU-ish cache keyed by (pid, startTime) with a short TTL to absorb
// repeated lookups for the same operation burst.
type ProcResolver struct {
	TTL  time.Duration
	mu   sync.Mutex
	seen map[uint32]cacheEntry
}

type cacheEntry struct {
	info CallerInfo
	at   time.Time
}

// NewProcResolver returns a ProcResolver with the given cache TTL. A zero
// TTL disables caching.
func NewProcResolver(ttl time.Duration) *ProcResolver {
	return &ProcResolver{
		TTL:  ttl,
		seen: make(map[uint32]cacheEntry),
	}
}

// Resolve returns caller info for pid. On any read error the returned
// CallerInfo has Exe="unknown".
func (r *ProcResolver) Resolve(pid uint32) CallerInfo {
	now := time.Now()

	if r.TTL > 0 {
		r.mu.Lock()
		if e, ok := r.seen[pid]; ok && now.Sub(e.at) < r.TTL {
			r.mu.Unlock()
			return e.info
		}
		r.mu.Unlock()
	}

	info := readProc(pid)

	if r.TTL > 0 {
		r.mu.Lock()
		if cached, ok := r.seen[pid]; ok && cached.info.StartTime != info.StartTime {
			// PID was recycled — drop stale entry.
			delete(r.seen, pid)
		}
		r.seen[pid] = cacheEntry{info: info, at: now}
		// Opportunistic GC: if the map grows large, prune expired entries.
		if len(r.seen) > 4096 {
			for k, v := range r.seen {
				if now.Sub(v.at) >= r.TTL {
					delete(r.seen, k)
				}
			}
		}
		r.mu.Unlock()
	}

	return info
}

func readProc(pid uint32) CallerInfo {
	info := CallerInfo{PID: pid, Exe: "unknown"}

	if tgt, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		info.Exe = tgt
	}

	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		info.Comm = strings.TrimRight(string(b), "\n")
	}

	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		info.PPID, info.StartTime = parseStat(string(b))
	}

	return info
}

// parseStat extracts PPID (field 4) and starttime (field 22) from a
// /proc/<pid>/stat line, handling the fact that field 2 (comm) is wrapped
// in parens and may itself contain spaces or parens.
func parseStat(s string) (ppid uint32, starttime uint64) {
	lp := strings.LastIndex(s, ")")
	if lp < 0 || lp+2 >= len(s) {
		return 0, 0
	}
	rest := s[lp+2:]
	fields := strings.Fields(rest)
	// fields[0] is state, fields[1] is ppid (field 4 overall),
	// fields[19] is starttime (field 22 overall).
	if len(fields) >= 2 {
		var p uint32
		_, _ = fmt.Sscan(fields[1], &p)
		ppid = p
	}
	if len(fields) >= 20 {
		var st uint64
		_, _ = fmt.Sscan(fields[19], &st)
		starttime = st
	}
	return
}
