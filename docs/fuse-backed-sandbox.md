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
| `--transparent` | `false` | Wrap child in a private user+mount namespace and chroot into the FUSE mount. Every absolute path the child resolves now goes through the hook layer. Rootless — requires kernel user namespace support. See *Transparent mode* below. |
| `--cwd` | *(derived)* | chdir target for the child command |
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

## Transparent mode (`--transparent`)

Without this flag, only paths physically under the FUSE mount are
intercepted. A process can bypass the sandbox by resolving the real
absolute path:

```sh
# non-transparent mode:
python3 -c "open('/tmp/gw-test/.git/HEAD').read()"   # hits the mount
python3 -c "open('/tmp/gw-test/.git/HEAD').read()"   # same, but:
# ... if the process uses the BACKING path instead of the mount path,
# FUSE never sees the call and the rule cannot fire.
```

With `--transparent`, greywall:

1. Mounts the FUSE passthrough in the parent namespace (as before).
2. `exec.Command` re-executes `greywall fuse-ns-setup` (a hidden
   helper subcommand) with `SysProcAttr.Cloneflags = CLONE_NEWUSER |
   CLONE_NEWNS` and a 1:1 uid/gid map so the helper runs as "root" in
   its own user namespace. **No real root is required.**
3. Inside the helper, before exec-ing the target:
   - `mount("", "/", "", MS_REC|MS_PRIVATE, "")` — make root mount
     propagation private so our new bind mounts do not leak back.
   - Bind-mount the real `/proc`, `/sys`, `/dev` over the corresponding
     paths inside the FUSE mount. Without this, `/proc/self`,
     `/dev/tty`, etc. would be served by the FUSE daemon from the
     parent's point of view, which is wrong for the child.
   - `chroot(mountPoint)` so the child's `/` IS the FUSE mount.
   - `chdir` into the target working directory.
   - `execve` the user command.

After this, the child sees `/home/tito/.ssh/id_rsa`, `/etc/shadow`,
`/usr/lib/python3.14/...` — all as normal absolute paths — and every
one of them routes through the FUSE hook layer. There is no "real
path" to escape to, because the child's mount namespace is structured
such that the only filesystem it can see (other than `/proc`, `/sys`,
`/dev`) is the FUSE passthrough.

### Why caller resolution needs extra care in transparent mode

Two non-obvious issues, both now fixed in the implementation:

1. **`/proc/<pid>/exe` from the parent namespace is mount-prefixed.**
   The FUSE daemon lives outside the chroot. When it reads
   `/proc/<child_pid>/exe`, the kernel reconstructs the symlink target
   using the **reader's** mount namespace, which has the FUSE mount at
   `/tmp/gw-mount`. So the result is
   `/tmp/gw-mount/usr/bin/bash` instead of `/usr/bin/bash`, and a rule
   written as `caller: "**/bash"` is technically still matched by the
   `**` wildcard but the event field is ugly and confusing. The
   resolver has an optional `StripPrefix` field that removes the mount
   point so events carry the backing path (`/usr/bin/bash`).

2. **Cache invalidation across `execve`.** The `ProcResolver` was
   originally keyed by `(pid, starttime)`. But `starttime` is set at
   fork and does **not** change across `execve`. So when bash forks
   and the child execs `cat`, the child's PID is the same, the
   starttime is the same, and the cache happily returns the stale
   "bash" entry — which would make every `cat` invocation look like
   bash. Transparent mode aggressively fails over to **TTL=0** (no
   caching) so each operation re-reads `/proc/<pid>/exe`. This is a
   ~20μs read per op, well within budget for observability.

### Example run

```sh
greywall fuse --transparent \
    --backing / \
    --mount   /tmp/gw-mount \
    --rules   /tmp/gw-rules.yaml \
    --events-file /tmp/gw-events.jsonl \
    -- bash
```

Inside the shell:

```sh
pwd                                     # /home/tito/code (real path!)
id                                      # uid=0 (inside the namespace)
cat /tmp/gw-test/README.md              # goes through FUSE, allowed
cat /tmp/gw-test/.git/HEAD              # DENIED (cat is not git)
git -C /tmp/gw-test log -1              # ALLOWED (caller /usr/bin/git)
python3 -c "open('/tmp/gw-test/.git/HEAD').read()"  # DENIED
```

The last line is the win over non-transparent mode: python's absolute
real path is intercepted because there **is** no real path anymore.

## Limitations (by design, for now)

| Limitation | Why | Mitigation / future |
|---|---|---|
| **Coarse read/write classification** — decided at `open` by `O_*` flags, not per syscall | Per-op interception on open fds requires a `FileHandle` wrapper | Wrap `loopbackFile` to intercept per-read/per-write |
| **Non-transparent mode leaks** — without `--transparent`, a process can bypass FUSE by using real backing paths | Non-transparent is simpler; keeps the hook layer standalone | Use `--transparent` (now available) for full coverage |
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
