---
id: agents
title: AI Agent Integration
---

# Using Greywall with AI Agents

Many popular coding agents already include sandboxing. Greywall can still be useful when you want a tool-agnostic policy layer that works the same way across:

- local developer machines
- CI jobs
- custom/internal agents or automation scripts
- different agent products (as defense-in-depth)

## Recommended approach

Treat an agent as "semi-trusted automation":

- Restrict writes to the workspace (and maybe `/tmp`)
- Configure the external proxy to allow only the network destinations you need
- Use `-m` (monitor mode) to audit blocked attempts and tighten policy

Greywall can also reduce the risk of running agents with fewer interactive permission prompts (e.g. "skip permissions"), as long as your Greywall config tightly scopes writes and outbound destinations. It's defense-in-depth, not a substitute for the agent's own safeguards.

## Example: API-only agent

```json
{
  "filesystem": {
    "allowWrite": ["."]
  }
}
```

Run:

```bash
greywall --settings ./greywall.json <agent-command>
```

## Popular CLI coding agents

We provide these template for guardrailing CLI coding agents:

- [`code`](https://github.com/GreyhavenHQ/greywall/blob/main/internal/templates/code.json) - Routes all network traffic through an external SOCKS5 proxy. Protects secrets, restricts dangerous commands.
- [`code-relaxed`](https://github.com/GreyhavenHQ/greywall/blob/main/internal/templates/code-relaxed.json) - Same filesystem/command protections as `code`, with relaxed network settings for environments where TUN is unavailable.

You can use it like `greywall --profile code -- claude`.

| Agent | Works with template | Notes |
|-------|--------| ----- |
| Claude Code | `code` | - |
| Codex | `code` | - |
| Gemini CLI | `code` | - |
| OpenCode | `code` | - |
| Droid | `code` | - |
| Cursor Agent | `code-relaxed` | Node.js/undici doesn't respect HTTP_PROXY |

These configs can drift as agents evolve. If you encounter false positives on blocked requests or want a CLI agent listed, please open an issue or PR.

Note: On Linux, if OpenCode or Gemini CLI is installed via Linuxbrew, Landlock can block the Linuxbrew node binary unless you widen filesystem access. Installing OpenCode/Gemini under your home directory (e.g., via nvm or npm prefix) avoids this without relaxing the template.

## MCP servers

Agents commonly spawn MCP servers as child processes, so an MCP server runs inside the same sandbox as the agent — its network destinations and credentials need to be part of the agent's profile.

For recognized MCP servers, greywall detects them in the agent's MCP configuration (`.mcp.json` in the working directory, `~/.mcp.json`, `~/.claude.json` including per-project entries, the Claude Desktop config, `~/.cursor/mcp.json`) and folds the required config into the recommended profile automatically. Detection prints a `[greywall:mcp]` notice on stderr whenever it widens the profile.

### HyperVault (`hypervault-mcp`)

When [hypervault-mcp](https://github.com/johnnyclem/hypervault) appears in the agent's MCP config, the profile gains:

- **Network:** an allow rule for the HyperVault API origin — `hypervault.store:443` by default, or the host from the `HYPERVAULT_API_URL` env var in the server's MCP config entry when set.
- **Credentials:** `HYPERVAULT_API_KEY` is added to `credentials.secrets`. The key travels in the `X-HyperVault-Key` request header, which is exactly the shape [credential protection](./credential-protection) handles: the sandboxed agent only ever sees a placeholder, and greyproxy substitutes the real key at the proxy.
- **Filesystem:** nothing — the server only reads the Python interpreter and site-packages, which the `python` toolchain profile covers.

The profile is also registered standalone, so you can apply it explicitly:

```bash
greywall --profile claude,hypervault -- claude
```

Opt-outs: `--no-network-rules` drops the network rule along with all other profile rules, and `--ignore-secret HYPERVAULT_API_KEY` excludes the key from credential detection.

If `extract_source_prompt` fails under greywall against a vanity-domain artifact URL, the HyperVault backend predates the single-host `/api/extract` endpoint and the tool is falling back to a direct page fetch, which deny-by-default correctly blocks. The fix is to update the backend, not to widen the allowlist.

### macOS proxy caveat

macOS has no transparent proxy: sandboxed traffic rides the `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` environment variables that greywall exports. MCP servers built on clients that honor those variables (Python `httpx`, `requests`, most Go clients) work unchanged — but an MCP server whose HTTP client **ignores** proxy env vars will silently bypass greyproxy on macOS (see Cursor Agent's Node.js/undici note above for the same issue in an agent). On Linux this doesn't apply: tun2socks captures all traffic at the kernel level. If you're writing an MCP server that should behave under greywall, use a proxy-aware HTTP client.

## Protecting your environment

Greywall includes additional "dangerous file protection" (writes blocked regardless of config) to reduce persistence and environment-tampering vectors like:

- `.git/hooks/*`
- shell startup files (`.zshrc`, `.bashrc`, etc.)
- some editor/tool config directories

See [Architecture](./architecture) for the full list and rationale.
