# FUSE experiment (branch `mathieu/exp-fuse-layer`)

Experimental userland FUSE passthrough layer that observes every
filesystem operation crossing a mount and optionally denies ones that
violate per-caller rules.

This lives behind `greywall fuse` and is **independent** of the
bubblewrap/Landlock pipeline in `internal/sandbox/`. The existing
sandbox path is not touched.

## Why

- Current stack (bwrap + Landlock + seccomp + eBPF) enforces policy but
  gives no runtime stream of filesystem operations.
- Nick's feedback (see `greywall-nick-feedback.md` in the greyproxy
  repo) explicitly asks: "are you able to watch filesystem access
  without blocking? even that's good enough."
- Rules today are static and do not depend on which process is calling.
  With FUSE we know the caller PID on every operation and can resolve
  it to a binary via `/proc/<pid>/exe`, so a rule like
  "git may read `.git/`, but claude may not" becomes expressible.

## Architecture

```
greywall fuse --rules rules.yaml --mount /tmp/gw -- bash
   │
   ├── (1) load YAML rules
   ├── (2) start FUSE server: hanwen/go-fuse/v2 LoopbackRoot wrapped
   │       with hookedNode that intercepts lookup/open/create/read/
   │       write/unlink/rmdir/mkdir/rename/getattr
   ├── (3) exec `bash`, stdio inherited, CWD set to the FUSE mount
   ├── (4) each FUSE op: resolve caller PID -> binary,
   │       consult Ruleset.Match(caller, path, op),
   │       emit FsEvent as JSON-line to stdout,
   │       forward to the loopback or return EACCES
   └── (5) wait for child; on exit or SIGINT, unmount cleanly
```

## Packages

- `internal/fuse/events.go` — `FsEvent`, `EventSink` (Stdout, Channel, Noop)
- `internal/fuse/rules.go` — `Rule`, `Ruleset`, first-match-wins
- `internal/fuse/config.go` — YAML loader + validation
- `internal/fuse/identity.go` — `ProcResolver`: `/proc/<pid>/{exe,comm,stat}`
- `internal/fuse/passthrough.go` — `hookedNode` embedding `gofs.LoopbackNode`
- `internal/fuse/mount.go` — `Mount`, `New`, `Close`
- `cmd/greywall/fuse.go` — cobra subcommand

## Rules

See `testdata/fuse/example-rules.yaml`. Format:

```yaml
default: allow
rules:
  - name: git-owns-dotgit
    caller: "**/git"
    path:   "**/.git/**"
    ops:    [read, write, lookup, open, create, unlink, rename]
    action: allow
  - name: non-git-blocked-from-dotgit
    caller: "*"
    path:   "**/.git/**"
    action: deny
```

Matching:
- `caller` is the resolved binary path from `/proc/<pid>/exe`.
- `path` is the absolute path on the backing filesystem (backing + relative path inside mount).
- Globs are doublestar — `**` for recursive.
- `ops` may be empty, meaning "any op".
- First matching rule wins; if nothing matches, the `default` action applies.

## How to run

```sh
# Build
go build ./cmd/greywall

# Mount / at /tmp/gw-test and spawn a shell that sees the FUSE view
mkdir -p /tmp/gw-test
./greywall fuse \
    --backing / \
    --mount /tmp/gw-test \
    --rules testdata/fuse/example-rules.yaml \
    -- bash

# Inside the shell, events stream as JSON-lines to stdout:
ls /tmp/gw-test/home/$USER/
cd /tmp/gw-test/home/$USER/code/monadical/greywall
git status
python3 -c "open('.git/config').read()"      # should fail (EACCES)
cat /tmp/gw-test/home/$USER/.ssh/id_rsa      # should fail (EACCES)
```

Each event looks like:

```json
{"ts":"2026-04-15T14:32:01.123Z","op":"lookup","path":"/home/tito/.git/config","caller":"/usr/bin/git","pid":12345,"action":"allow","rule":"git-owns-dotgit"}
```

Clean unmount on Ctrl-C or child exit. If something gets stuck:

```sh
fusermount3 -u /tmp/gw-test
```

## Limitations

- **Not transparent**: the sandboxed process must operate under the
  FUSE mount path (e.g. `/tmp/gw-test/home/...`) rather than its real
  path. The transparent approach (unshare + FUSE-over-/) is Phase 2.
- **No content rewriting**: initial version is observe + allow/deny.
- **PID resolution races**: after an `execve`, a cached entry may point
  at the previous binary. The resolver uses `(pid, starttime)` as key
  but still samples at operation time, accepting some staleness.
- **Write detection is coarse**: any `open` with `O_WRONLY`/`O_RDWR`
  is classified as `write`, not `read`. Reads after open are not
  individually intercepted (they go to the underlying fd).
- **No greyproxy integration yet**: events go to stdout only. A
  channel sink + HTTP POST to greyproxy `/api/events` is trivial to
  add later.
- **Linux only** for this experiment.
