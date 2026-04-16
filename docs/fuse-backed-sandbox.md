# FUSE-backed filesystem sandbox

> Status: **experimental**, branch `mathieu/exp-fuse-layer`. Lives behind
> the `greywall fuse` subcommand and is independent of the main
> bubblewrap/Landlock/seccomp pipeline. Linux only.

## What it is

A userland FUSE passthrough filesystem that sits between a sandboxed
process and the real filesystem, observing **every** operation that
crosses the mount, resolving the **calling binary** of each operation,
and applying a **per-caller × per-path × per-op** rule engine.

It answers questions the current Landlock-based stack cannot:

| Question | Landlock | FUSE backend |
|---|---|---|
| What files did the process actually touch? | no | yes — one JSON event per op |
| Can git read `.git/` but claude cannot? | no (policy is per-path, not per-caller) | yes |
| Can rules change without restarting the sandbox? | no | yes (future: hot-reload) |
| Does it work for statically linked binaries? | yes (kernel-level) | yes (VFS-level) |
| Can it modify file contents in flight? | no | yes (future) |

## Why

Nick's April feedback — *"are you able to watch filesystem access
without blocking? even that's good enough"* — is precisely the gap
this layer fills. The current stack enforces policy, but once the
sandboxed process is running there is zero runtime visibility: neither
the user nor greyproxy can see which files the agent is touching, in
what order, for what purpose.

The proposal in `proposal-junction.md` also calls out filesystem
events → greyproxy dashboard as a Phase 3 goal. FUSE is the
mechanism that makes that stream exist.

## Architecture

```
       ┌───────────────────────────────────┐
       │           user process            │
       │     (bash, git, claude, ...)      │
       └──────────────┬────────────────────┘
                      │ syscalls: open/read/write/stat/...
                      │
                      │ (pid is visible to FUSE via fuse.Context)
                      ▼
       ┌───────────────────────────────────┐
       │         kernel VFS layer          │
       └──────────────┬────────────────────┘
                      │
                      ▼
       ┌───────────────────────────────────┐
       │     /dev/fuse (unprivileged)      │
       └──────────────┬────────────────────┘
                      │ fuse protocol
                      ▼
       ┌───────────────────────────────────┐
       │     greywall fuse daemon (Go)     │
       │                                   │
       │  hookedNode (internal/fuse/       │
       │              passthrough.go)      │
       │     │                             │
       │     ├─ decide(op, path, ctx):     │
       │     │   ├─ Resolver.Resolve(pid)  │
       │     │   │    → /proc/<pid>/exe    │
       │     │   ├─ Ruleset.Match(         │
       │     │   │     caller, path, op)   │
       │     │   ├─ Sink.Emit(FsEvent{…})  │
       │     │   └─ return EACCES OR       │
       │     │          forward            │
       │     ▼                             │
       │  gofs.LoopbackNode (real fs op)   │
       └──────────────┬────────────────────┘
                      │ real syscalls against the backing dir
                      ▼
       ┌───────────────────────────────────┐
       │       real filesystem             │
       └───────────────────────────────────┘
```

Every FUSE operation goes through `hookedNode.decide(...)` before
reaching the loopback layer. The decision has four outcomes:

1. **allow** — event is emitted, call is forwarded to the real fs
2. **deny** — event is emitted, `EACCES` is returned to the process
3. **log** — same as allow but the rule explicitly says "just observe"
4. **observe-only mode** — every deny is demoted to log; the process
   always gets through. Used during learning/discovery.

## Package layout

```
internal/fuse/
  events.go         FsEvent type; EventSink interface with
                    NoopSink, ChannelSink (tests), StdoutSink
                    (JSON-lines writer, mutex-protected).

  rules.go          Rule{caller glob, path glob, ops, action}
                    Ruleset{default, rules} with first-match-wins
                    Match() and Validate().

  config.go         LoadRuleset(path): YAML → Ruleset with validation.

  identity.go       ProcResolver: reads /proc/<pid>/exe, comm, stat
                    and caches by pid with a short TTL. parseStat()
                    correctly handles comm fields that contain
                    parens or spaces.

  passthrough.go    hookedNode embeds gofs.LoopbackNode and overrides:
                    Lookup, Open, Create, Unlink, Rmdir, Mkdir,
                    Rename, Getattr. Each override computes the
                    backing path, calls decide(), and either
                    short-circuits with EACCES or delegates to the
                    embedded loopback method. newHookedRoot() wires
                    LoopbackRoot.NewNode so every inode in the tree
                    is a hookedNode.

  mount.go          Mount lifecycle: New(cfg) mounts via
                    gofs.Mount(); Wait() blocks until unmount;
                    Close() tries Server.Unmount() then falls back
                    to `fusermount3 -u`.

cmd/greywall/fuse.go   Cobra subcommand wiring.

testdata/fuse/example-rules.yaml   Sample ruleset.
```

## Usage

### Build

```sh
cd /path/to/greywall
git checkout mathieu/exp-fuse-layer
go build ./cmd/greywall
```

### Run

```sh
greywall fuse \
    --backing <REAL_DIR> \
    --mount   <WHERE_TO_MOUNT> \
    --rules   <RULES_YAML> \
    --cwd     <WHERE_TO_CHDIR_INSIDE_MOUNT> \
    --events-file <EVENTS_JSONL> \
    -- <COMMAND> [ARGS...]
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--backing` | `/` | Directory on the real filesystem to expose through FUSE |
| `--mount` | `/tmp/greywall-fuse-$PID` | Where to mount; created if missing |
| `--rules` | *(none)* | YAML rules file; if empty, `default=allow` and everything is logged |
| `--observe-only` | `false` | Force every deny to `log`; nothing is ever blocked |
| `--cwd` | *(derived)* | chdir target for the child command, interpreted inside the mount |
| `--events-file` | *(stdout)* | Write JSON events here instead of stdout |
| `--debug` | `false` | Enable go-fuse's verbose protocol logging on stderr |

### Example: quick smoke test

```sh
# 1. Set up a test directory with a real git repo and a fake ssh key.
rm -rf /tmp/gw-test /tmp/gw-mount
mkdir -p /tmp/gw-test /tmp/gw-mount
cd /tmp/gw-test
git init -q -b main
echo "# hello" > README.md
git -c user.email=x@y -c user.name=x add README.md
git -c user.email=x@y -c user.name=x commit -q -m init
mkdir .ssh && echo "FAKE" > .ssh/id_rsa

# 2. Write a rules file that allows only git inside .git/.
cat > /tmp/gw-rules.yaml <<'YAML'
default: allow
rules:
  - name: git-owns-dotgit
    caller: "**/git"
    path:   "**/.git/**"
    action: allow
  - name: non-git-blocked-from-dotgit
    caller: "*"
    path:   "**/.git/**"
    action: deny
  - name: block-ssh-private-keys
    caller: "*"
    path:   "**/.ssh/id_*"
    action: deny
YAML

# 3. Run a shell inside the FUSE mount.
greywall fuse \
    --backing /tmp/gw-test \
    --mount   /tmp/gw-mount \
    --rules   /tmp/gw-rules.yaml \
    --cwd     /tmp/gw-mount \
    --events-file /tmp/gw-events.jsonl \
    -- bash

# Inside the shell:
cat README.md          # → allowed, prints "# hello"
cat .git/HEAD          # → Permission denied (caller is cat, not git)
git log -1             # → allowed (caller is /usr/bin/git)
cat .ssh/id_rsa        # → Permission denied
python3 -c "open('.git/HEAD').read()"  # → PermissionError
exit
```

In another terminal, watch the event stream live:

```sh
tail -f /tmp/gw-events.jsonl | jq -c '{op, path, caller, action, rule}'
```

Sample output from an actual run:

```json
{"op":"lookup","path":"/tmp/gw-test/.git","caller":"/usr/bin/git","action":"allow","rule":"git-owns-dotgit"}
{"op":"read","path":"/tmp/gw-test/.git/HEAD","caller":"/usr/bin/git","action":"allow","rule":"git-owns-dotgit"}
{"op":"read","path":"/tmp/gw-test/.git/config","caller":"/usr/bin/git","action":"allow","rule":"git-owns-dotgit"}
{"op":"lookup","path":"/tmp/gw-test/.git","caller":"/usr/bin/cat","action":"deny","rule":"non-git-blocked-from-dotgit"}
{"op":"read","path":"/tmp/gw-test/.git/HEAD","caller":"/usr/bin/python3.14","action":"deny","rule":"non-git-blocked-from-dotgit"}
{"op":"lookup","path":"/tmp/gw-test/.ssh/id_rsa","caller":"/usr/bin/cat","action":"deny","rule":"block-ssh-private-keys"}
```

Note: same `.git/config` path, two different callers, two different
decisions. That's the whole point.

## Rules

### File format (YAML)

```yaml
default: allow       # action when nothing matches; allow | deny | log

rules:
  - name: git-owns-dotgit
    caller: "**/git"            # glob against resolved /proc/<pid>/exe
    path:   "**/.git/**"        # glob against the backing-absolute path
    ops:    [read, write, lookup, open]   # optional; empty = any op
    action: allow               # allow | deny | log

  - name: block-ssh
    caller: "*"
    path:   "**/.ssh/id_*"
    action: deny
```

### Semantics

- **First-match-wins.** Rules are evaluated top-to-bottom; the first
  whose caller, path, and op all match is applied.
- **Caller** is the absolute path from `/proc/<pid>/exe` for the
  process that issued the operation. For unresolvable PIDs the caller
  is literally `"unknown"`.
- **Path** is the absolute path on the **backing** filesystem. If you
  mount `/` at `/tmp/gw` and a process opens `/tmp/gw/home/u/.bashrc`,
  the rule sees `/home/u/.bashrc`.
- **Globs** use [`doublestar`](https://github.com/bmatcuk/doublestar);
  `**` matches recursively. `""` or `"*"` in caller/path matches any.
- **Ops** (optional) limits a rule to specific operations. Empty means
  "any op".

### Op vocabulary

| Op | When emitted |
|---|---|
| `lookup` | directory entry lookup (resolving a name to an inode) |
| `getattr` | stat/fstat on a node |
| `open` | `open(2)` without O_WRONLY/O_RDWR — classified as read intent |
| `read` | same as `open` for read-only opens (coarse classification) |
| `write` | `open(2)` with O_WRONLY or O_RDWR |
| `create` | `creat(2)` / `open(O_CREAT)` producing a new file |
| `unlink` | file deletion |
| `rmdir` | directory deletion |
| `mkdir` | directory creation |
| `rename` | `rename(2)` / `renameat(2)` |

> **Caveat (coarse write detection):** the op is decided at `open`
> time based on the `O_*` flags. A process that opens a file RDWR and
> then only reads from it still gets classified `write`. Individual
> reads and writes on an already-open fd do **not** generate events
> in this experiment — the fd goes straight to the loopback layer
> after open. Fixing this requires a per-`FileHandle` wrapper, listed
> under Future work.

### Example rulesets

A copy-paste starter lives at `testdata/fuse/example-rules.yaml`.

**Permissive observability (no blocking, everything logged):**

```yaml
default: log
rules: []
```

Or equivalently, pass `--observe-only` and any rules file.

**Deny-by-default, allow a project tree:**

```yaml
default: deny
rules:
  - name: allow-project
    caller: "*"
    path:   "/home/tito/code/myproject/**"
    action: allow
```

## Event stream

### Schema

One JSON object per line (`application/x-ndjson`):

```json
{
  "ts":     "2026-04-15T18:44:55.873-06:00",
  "op":     "read",
  "path":   "/tmp/gw-test/.git/config",
  "caller": "/usr/bin/git",
  "pid":    1730456,
  "ppid":   1730450,
  "comm":   "git",
  "action": "allow",
  "rule":   "git-owns-dotgit"
}
```

| Field | Type | Notes |
|---|---|---|
| `ts` | RFC3339Nano | local timestamp with nanosecond precision |
| `op` | string | one of the ops listed above |
| `path` | string | absolute path on the backing filesystem |
| `caller` | string | resolved `/proc/<pid>/exe` or `"unknown"` |
| `pid` | uint32 | calling thread's PID from FUSE context |
| `ppid` | uint32 | parent PID from `/proc/<pid>/stat` |
| `comm` | string | contents of `/proc/<pid>/comm` |
| `action` | string | `allow` / `deny` / `log` (deny may become `log` under `--observe-only`) |
| `rule` | string | name of the matched rule, empty when the default was used |
| `errno` | string | reserved; not populated in this iteration |

### Sinks (pluggable)

`EventSink` is an interface. The experiment ships three
implementations:

- `StdoutSink` — JSON-lines to any `io.Writer`, mutex-serialized
- `ChannelSink` — bounded channel for tests, drops when full
- `NoopSink` — discards everything

Future sinks: HTTP POST to `greyproxy /api/fs-events`, Unix socket
streaming, compressed rolling log.

## How it works internally

### 1. Mount lifecycle (`mount.go`)

`fuse.New(Config)`:

1. Stat the backing dir to get the underlying device number.
2. Build a `gofs.LoopbackRoot{Path, Dev}` whose `NewNode` callback
   returns `hookedNode` instances so every inode in the tree is
   intercepted.
3. Call `gofs.Mount(mountPoint, rootNode, opts)` with short entry/attr
   TTLs (200ms) so rule decisions stay live instead of being cached
   for seconds inside the kernel.

`mnt.Close()` calls `Server.Unmount()`, and if that fails (common on
crash or busy fd), falls back to `fusermount3 -u <point>` via
`exec.LookPath`.

### 2. Hook layer (`passthrough.go`)

Each intercepted operation follows the same template:

```go
func (n *hookedNode) Lookup(ctx, name, out) (*Inode, Errno) {
    errno, deny := n.decide(ctx, OpLookup, n.backingPath(name))
    if deny {
        return nil, errno
    }
    return n.LoopbackNode.Lookup(ctx, name, out)
}
```

`decide()`:

```go
caller := fuse.FromContext(ctx)           // pid, uid, gid
info   := resolver.Resolve(caller.Pid)    // /proc/<pid>/exe etc
action, rule := ruleset.Match(info.Exe, path, op)
sink.Emit(FsEvent{...})
if action == deny && !observeOnly {
    return EACCES, true
}
return 0, false
```

The template is repeated for `Lookup`, `Open`, `Create`, `Unlink`,
`Rmdir`, `Mkdir`, `Rename`, and `Getattr`. Everything else (Read,
Write on an already-open fd, xattrs, link, symlink, readlink) falls
through the embedded `LoopbackNode` untouched.

### 3. Caller resolution (`identity.go`)

`ProcResolver.Resolve(pid)`:

1. Check the LRU cache keyed by `(pid, starttime)`. Hit → return.
2. `readlink /proc/<pid>/exe` → `Exe`
3. Read `/proc/<pid>/comm` → `Comm`
4. Parse `/proc/<pid>/stat` → `PPID`, `StartTime`
5. Store `{info, at=now}` in the cache.
6. If the map grows past 4096 entries, GC expired ones.

`parseStat()` handles the nasty case where the `comm` field is wrapped
in parens and may itself contain spaces or parens by slicing at the
**last** `)` instead of tokenizing from the front.

**Race note:** between the FUSE op arriving and readlink being called,
the process may have `execve`'d a new binary. The resolver samples at
op time and accepts that staleness; the cache key is guarded by
`starttime` so PID recycling does not return a confidently wrong
binary. If the cached `starttime` mismatches the current one, the
entry is dropped and re-read.

### 4. Rule matching (`rules.go`)

```go
func (rs *Ruleset) Match(caller, path string, op Op) (Action, string) {
    for i := range rs.Rules {
        r := &rs.Rules[i]
        if !matchOp(r.Ops, op)          { continue }
        if !matchGlob(r.CallerGlob, caller) { continue }
        if !matchGlob(r.PathGlob, path)     { continue }
        return r.Action, r.Name
    }
    return rs.Default, ""
}
```

Glob matching uses `doublestar.PathMatch`. A malformed glob is not a
runtime panic — it is reported at `LoadRuleset` time by `Validate()`.

## Verification

### Unit tests

```sh
go test ./internal/fuse/... -v
```

Covers:

- Rule matching (simple, first-match-wins, default fallback)
- Rule validation (bad action, unknown op)
- ProcResolver: resolve self, cache hit, unknown PID, stat parsing

### Integration tests

The same package contains `TestMountEndToEnd` and `TestMountDeny`.
Both create tempdirs, mount a real FUSE filesystem, read a file
through it, and assert on the captured event stream. They
`t.Skip` if `/dev/fuse` is unavailable (e.g. in CI sandboxes).

### Manual smoke test

Already walked through under *Usage → Example*. The success criteria
are:

- `cat README.md` → success
- `git log -1` → success, events show `caller=/usr/bin/git`,
  `rule=git-owns-dotgit`
- `cat .git/HEAD` → `Permission denied`, event with
  `caller=/usr/bin/cat`, `rule=non-git-blocked-from-dotgit`
- `python3 -c "open('.git/HEAD').read()"` → `PermissionError`
- `cat .ssh/id_rsa` → `Permission denied`, `rule=block-ssh-private-keys`

## Limitations (by design, for now)

| Limitation | Why | Mitigation / future |
|---|---|---|
| **Not transparent** — the sandboxed process must operate under the mount path, not its real paths | Experiment deliberately avoids touching bwrap | Phase 2: `unshare(CLONE_NEWNS\|CLONE_NEWUSER)` + mount FUSE over the process's view of `/`, then exec inside the namespace. This is how rootless containers and bubblewrap itself work |
| **Coarse read/write classification** — decided at `open` by `O_*` flags, not per syscall | Per-op interception on open fds requires a `FileHandle` wrapper | Wrap `loopbackFile` to intercept per-read/per-write |
| **No content rewriting** | Scope kept tight; observe+allow/deny only | The hook layer already has the op in its hands; rewriting means returning different bytes from `Read` |
| **No hot-reload of rules** | Config file loaded once at startup | Add `fsnotify` on the rules file; atomic pointer swap |
| **No greyproxy forwarding yet** | Keep the experiment self-contained | Add an `HTTPSink` that POSTs to `greyproxy /api/fs-events` (or `WebsocketSink` against the existing EventBus) |
| **PID race on execve** | `/proc/<pid>/exe` can shift mid-operation | Acceptable for observability; the `(pid, starttime)` cache key keeps things honest across recycling |
| **Linux only** | `/proc/<pid>/exe` + Linux FUSE | macOS path would use `fuse-t` + `libproc_pidpath` |
| **Single mount** | CLI wraps one command per invocation | Daemon mode with multiple mount points is straightforward once we have a supervisor |

## Where this could go

1. **Phase 2: transparent namespace wrap.** Launcher uses
   `unshare(CLONE_NEWNS|CLONE_NEWUSER)`, mounts FUSE over the child's
   view of `/`, and execs the target command. Zero code changes for
   the target; it sees a normal filesystem.
2. **Greyproxy integration.** `HTTPSink` posts events to a new
   greyproxy endpoint (`POST /api/fs-events`) which republishes on
   the existing WebSocket `EventBus` as a new event type
   (`fs_event.new`). Frontend activity feed gets a new row kind:
   filesystem event with caller/op/path/action.
2. **Per-session rules from profiles.** Greywall profiles already
   carry network rules; add a `filesystem_rules:` section and push
   it into the FUSE daemon at session start.
3. **Replace Landlock for the filesystem layer.** Once transparent
   wrap exists, FUSE is strictly more expressive than Landlock for
   this use case (per-caller, dynamic, observable). Landlock becomes
   optional belt-and-braces for deep-kernel paths FUSE cannot see
   (mmap edge cases, cgroup fs, etc.).
4. **Content redaction.** Intercept `Read` on an open fd backed by a
   `hookedFile` and substitute redacted bytes for specific paths
   (e.g. credentials appearing in `.env` files get replaced with
   `***REDACTED***` before reaching the sandboxed process).
5. **Snapshot/rollback.** Inspired by nono.sh — keep a scratch
   overlay so every write is stashed, and a session-end step can
   diff-and-rollback. Orthogonal to the policy work but cheap to add
   on top of a FUSE layer that already sees every write.

## Prior art and inspiration

- **nono.sh** — Content-addressable before/after snapshots with
  Merkle-tree integrity. Pure userland, no FUSE. Solves rollback but
  not runtime visibility. Object store design is worth borrowing
  directly if we add snapshotting later.
- **bubblewrap** — The namespace-wrap pattern this experiment would
  adopt in Phase 2. bwrap bind-mounts a view; we would FUSE-mount a
  view.
- **fuse-overlayfs** — Rootless Docker's storage driver. Same
  unprivileged-FUSE approach.
- **proot** — ptrace-based path interception. Works without FUSE but
  is slow and per-syscall; FUSE is the correct layer for this
  granularity.

## Troubleshooting

### Mount is stuck after a crash

```sh
fusermount3 -u /tmp/greywall-fuse-<pid>
```

or

```sh
fusermount -u /tmp/greywall-fuse-<pid>
```

### `fusermount: /dev/fuse: permission denied`

The current user does not have access to `/dev/fuse`. On most modern
distros `/dev/fuse` is world-accessible (`crw-rw-rw-`). Check:

```sh
ls -la /dev/fuse
```

If restricted, add your user to the `fuse` group and re-login, or
relax the device permissions.

### Events come out all with `caller: "unknown"`

Possible causes:

- `/proc/<pid>/exe` is unreadable because of SELinux, AppArmor, or
  restricted ptrace. The resolver silently falls back to `"unknown"`.
- You are running in a namespace where `/proc` is not mounted. Make
  sure `/proc` is available to the `greywall fuse` daemon.

### The child command doesn't see changes to the real filesystem

FUSE caches attributes for 200ms by default (configured in
`mount.go`). If you need zero-caching, lower the TTL. If you need
higher throughput and can tolerate short staleness, raise it.
