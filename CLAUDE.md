# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Greywall

Deny-by-default command sandbox for AI coding agents. Wraps commands with restricted filesystem access (current directory only by default) and routes network through [greyproxy](https://github.com/GreyhavenHQ/greyproxy). Linux uses bubblewrap + seccomp/Landlock/eBPF + tun2socks; macOS uses sandbox-exec Seatbelt profiles.

Two entry points share one binary (argv[0] dispatch via symlink, created by `make build`):

- `greywall` — deny-by-default sandbox (the primary mode).
- `greywatch` — equivalent to `greywall --watch`: no profile, `*/*` allow rule with greyproxy, permissive filesystem. Use it to observe what a tool does before locking it down.

## Build & Run

```bash
make setup          # deps + lint tools + git pre-commit hook (first time)
make build          # compile binary + create ./greywatch symlink (downloads tun2socks on first run)
make run            # build and run
./greywall --help
./greywall check    # verify deps, kernel features, and greyproxy status
```

## Test

```bash
make test                                   # all unit + integration tests
make test-ci                                # with -race -coverprofile (CI parity)
go test -v -run TestName ./internal/sandbox # single test
go test -v ./internal/sandbox/...           # one package
GREYWALL_TEST_NETWORK=1 ./scripts/smoke_test.sh ./greywall  # network smoke tests
```

Many sandbox tests are platform-gated by `_linux_test.go` / `_darwin_test.go` suffixes — running `go test ./...` on macOS skips Linux-only integration tests automatically.

## Lint & Format

```bash
make fmt            # gofumpt
make lint           # golangci-lint v2 (see .golangci.yml)
```

`make setup` installs a pre-commit hook that runs both. Always run `make fmt && make lint` before committing if you skipped `setup`.

## Architecture

For the full architecture (diagrams of the proxy/DNS bridges, reverse bridges for inbound connections, execution flow, platform comparison, monitoring layers) see [ARCHITECTURE.md](ARCHITECTURE.md). The short version:

```
cmd/greywall/main.go     CLI entry. Also hosts the --landlock-apply re-exec wrapper used inside the sandbox.
internal/
  config/                JSON+comments config (tidwall/jsonc), pointer fields for three-state bools.
  platform/              OS detection.
  proxy/                 greyproxy detect/install/start lifecycle + brew helper.
  profiles/              Built-in agent + toolchain profiles, drift detection, keyring access, prompt UX.
  sandbox/               Platform-specific sandboxing (~7k lines).
    manager.go           Sandbox lifecycle orchestration.
    command.go           Command deny/allow lists, chain & nested-shell detection.
    linux.go             bubblewrap wrapper + ProxyBridge/DnsBridge (socat + Unix sockets across netns).
    macos.go             sandbox-exec Seatbelt profile generation.
    linux_seccomp.go     Seccomp BPF syscall filter.
    linux_landlock.go    Landlock filesystem control.
    linux_ebpf.go        eBPF violation monitor (-m flag, needs CAP_BPF/root).
    learning_*.go        --learning mode: strace (Linux) / eslogger (macOS) tracing → profile generation.
    tracer_*.go          Streaming tracer for --record-fs: tails the strace/eslogger log and pushes FsEvents into a ring buffer.
    fsevents.go          FsEvent wire type + bounded ring buffer (drop-oldest, shared between tracer and heartbeat loop).
    credentials.go       Credential substitution (gh/glab via libsecret keyring); StartHeartbeatLoop ships FsEvents to greyproxy on each tick.
    sanitize.go          Strips LD_*/DYLD_* and other dangerous env vars.
    dangerous.go         Hard-floor protected files/dirs (e.g. ~/.ssh/authorized_keys, git hooks).
    tun2socks_embed.go   Embeds tun2socks v2.5.2 binary (downloaded by Makefile).
pkg/greywall/            Public Go API.
docs/                    User-facing documentation (also mirrored to docs.greywall.io).
scripts/                 smoke_test.sh, benchmark.sh, release.sh, pre-commit hook.
```

Key cross-cutting points:

- **Network on Linux:** `bwrap --unshare-net` isolates the netns. socat bridges Unix sockets bind-mounted into the sandbox to the host's SOCKS5 proxy + DNS server; `tun2socks` inside the sandbox creates a TUN device and routes all traffic through the Unix socket. Falls back to `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` env vars if TUN is unavailable.
- **Network on macOS:** no namespace isolation; Seatbelt blocks direct egress except to the proxy address, and proxy env vars steer well-behaved clients.
- **Watch mode (`--watch` / `greywatch`):** skips profile load, registers a `*/*` allow rule with greyproxy, and runs the command with a permissive filesystem. Hard-floor denies (`dangerous.go`) and credential substitution stay on. Traffic still goes through greyproxy so the dashboard sees every request.
- **Learning mode (`--learning`):** traces the command (strace/eslogger), collapses observed paths into glob patterns, and writes a per-command template under the user's profile directory. Re-running the same command auto-loads the learned template.
- **Filesystem event recording (`--record-fs`):** reuses the learning-mode tracer to push live FsEvents into a ring buffer that `StartHeartbeatLoop` drains on each tick and POSTs to greyproxy in the heartbeat body. Auto-enabled by `--watch`; only valid alongside `--watch` or `--learning` because strace requires ptrace, which seccomp/landlock would block. Version-gated via `proxy.SupportsFsEvents` so older greyproxy builds aren't sent payloads they don't understand.

## Code Conventions

- **Go 1.25+**, formatted with `gofumpt`, linted with `golangci-lint` v2 (errcheck, gocritic, gosec, govet, ineffassign, misspell, revive, staticcheck, unused).
- **Import groups:** stdlib, third-party, local (`github.com/GreyhavenHQ/greywall`). Enforced by `gci`/`goimports` config.
- **Platform code:** build tags (`//go:build linux`, `//go:build darwin`) with a `*_stub.go` sibling so the non-target platform still compiles and tests cleanly. When adding a Linux-only file, always add the matching `_stub.go`.
- **Error handling:** prefer typed errors (e.g. `CommandBlockedError`) over string matching.
- **Logging:** stderr with `[greywall:<component>]` prefixes (e.g. `[greywall:ebpf]`, `[greywall:logstream]`).
- **Config:** JSON-with-comments via `tidwall/jsonc`; optional bools are `*bool` to distinguish "unset" from `false`.

## Dependencies

4 direct Go deps: `doublestar` (glob matching), `cobra` (CLI), `jsonc` (config parsing), `golang.org/x/sys`.

Runtime: Linux requires `bubblewrap` + `socat` (optional `xdg-dbus-proxy`, `libsecret-tools`); macOS has no external runtime deps. `tun2socks` v2.5.2 is downloaded by the Makefile and embedded into the binary.

## CI & Release

GitHub Actions: `main.yml` (build/lint/test on Linux + macOS), `release.yml` (GoReleaser + SLSA provenance), `benchmark.yml`.

```bash
make release          # patch (vX.Y.Z+1)
make release-minor    # minor (vX.Y+1.0)
make release-beta     # beta tag
```
