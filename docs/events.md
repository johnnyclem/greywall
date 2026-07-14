---
id: events
title: Event Stream
---

# Machine-Readable Event Stream

Greywall can emit session activity as **NDJSON** (one JSON object per line) so another process can consume it — feed an audit log, forward sessions to a memory/knowledge store, or alert on denied activity. Without this, session activity is only visible on the greyproxy dashboard.

## Enabling

Pass `--event-log` with a file or directory path, or set the `GREYWALL_EVENT_LOG` environment variable (the flag wins when both are set):

```bash
# One file per session inside the directory: <session-id>.ndjson
greywall --event-log ~/.local/state/greywall/events/ -- claude

# A single file (appended across sessions)
greywall --event-log /tmp/greywall-events.ndjson -- npm install

# Via environment variable
GREYWALL_EVENT_LOG=~/.local/state/greywall/events/ greywall -- claude
```

When the path is an existing directory (or ends with a path separator), each session writes its own `<session-id>.ndjson` file. Otherwise the path is treated as a single file and events are appended.

Enabling the event log also activates the platform violation monitors (macOS log stream, Linux eBPF) so filesystem and network denials are recorded — without echoing them to stderr unless `--monitor` is also set.

## Event schema

Every line is a JSON object with at least:

| Field | Description |
|-------|-------------|
| `time` | RFC 3339 timestamp (UTC, nanosecond precision) |
| `session` | Greywall session ID (`gw-...`). The same ID is used for the greyproxy session, so events correlate with dashboard activity. |
| `command` | The wrapped command |
| `kind` | One of `session_start`, `command_block`, `fs_violation`, `network_attempt`, `session_end`, `session_summary` |
| `target` | What the event is about: a path, host, or command (omitted when not applicable) |
| `verdict` | `allowed`, `denied`, or `observed` (omitted for lifecycle events) |
| `detail` | Free-text context: matched rule, errno, process name/PID |

Kind-specific fields:

- `session_end` carries `exitCode` (the wrapped command's exit code).
- `session_summary` carries `summary` with `countsByKind` (event counts keyed by kind) and `topDeniedTargets` (up to 10 denied targets with per-target counts, most-denied first). It is always the final event of a session and is designed to map onto a single downstream ingestion call.

Example session:

```json
{"time":"2026-07-14T22:56:54.487Z","session":"gw-62600abf4f3bda48","command":"shutdown -h now","kind":"session_start","detail":"cwd: /work"}
{"time":"2026-07-14T22:56:54.694Z","session":"gw-62600abf4f3bda48","command":"shutdown -h now","kind":"command_block","target":"shutdown -h now","verdict":"denied","detail":"matched deny rule: shutdown"}
{"time":"2026-07-14T22:56:54.696Z","session":"gw-62600abf4f3bda48","command":"shutdown -h now","kind":"session_end","exitCode":1}
{"time":"2026-07-14T22:56:54.696Z","session":"gw-62600abf4f3bda48","command":"shutdown -h now","kind":"session_summary","summary":{"countsByKind":{"command_block":1,"session_end":1,"session_start":1},"topDeniedTargets":[{"target":"shutdown -h now","kind":"command_block","count":1}]}}
```

## What is (and isn't) captured

| Kind | Source | Availability |
|------|--------|--------------|
| `session_start` / `session_end` / `session_summary` | greywall itself | Always |
| `command_block` | greywall's command policy | Always |
| `fs_violation` | macOS unified log stream / Linux eBPF (bpftrace) | Requires the platform monitor to be available (Linux needs `bpftrace` and CAP_BPF or root) |
| `network_attempt` | Denied `connect()` syscalls (Linux eBPF) and macOS `network-*` sandbox denials | Same as above |

Requests that reach greyproxy (allowed traffic, proxy-level denials) are recorded by greyproxy, not on this stream — the shared session ID lets a consumer join the two. New event kinds and fields may be added over time; consumers should ignore unknown values.

## Notes

- Event files are created with mode `0600`. The `command` field can contain whatever was on the command line, so treat the files as sensitive if your command lines embed secrets (better: use [credential protection](./credential-protection) so they don't).
- Timestamps, IDs, and the summary are written by the greywall process on the host, outside the sandbox; the sandboxed command cannot write to the event log unless you point `--event-log` inside a writable sandbox path.
