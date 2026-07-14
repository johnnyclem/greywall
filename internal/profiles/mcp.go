package profiles

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// MCPServer describes an MCP server entry found in an agent's MCP
// configuration file (Claude Code, Claude Desktop, Cursor, ...).
type MCPServer struct {
	Name    string
	Command string
	Args    []string
	Env     map[string]string
	Source  string // config file the entry came from
}

// mcpServerJSON is the on-disk shape of a single MCP server entry.
type mcpServerJSON struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// mcpFileJSON covers the common MCP config layouts:
//   - {"mcpServers": {...}}                        (.mcp.json, Claude Desktop, Cursor)
//   - {"mcpServers": {...}, "projects": {"<dir>": {"mcpServers": {...}}}}  (~/.claude.json)
type mcpFileJSON struct {
	MCPServers map[string]mcpServerJSON `json:"mcpServers"`
	Projects   map[string]struct {
		MCPServers map[string]mcpServerJSON `json:"mcpServers"`
	} `json:"projects"`
}

// mcpConfigPaths returns the MCP configuration files to scan, in order.
// cwd scopes project-level entries; home locates per-user configs.
func mcpConfigPaths(cwd, home string) []string {
	var paths []string
	if cwd != "" {
		paths = append(paths, filepath.Join(cwd, ".mcp.json"))
	}
	if home != "" {
		paths = append(
			paths,
			filepath.Join(home, ".mcp.json"),
			filepath.Join(home, ".claude.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
		)
		if runtime.GOOS == "darwin" {
			paths = append(paths, filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"))
		} else {
			paths = append(paths, filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"))
		}
	}
	return paths
}

// DetectMCPServers scans well-known MCP configuration files and returns every
// server entry found. Project-scoped entries in ~/.claude.json are only
// included when they belong to cwd. Unreadable or malformed files are skipped.
func DetectMCPServers(cwd, home string) []MCPServer {
	var servers []MCPServer
	for _, path := range mcpConfigPaths(cwd, home) {
		data, err := os.ReadFile(path) //nolint:gosec // fixed list of well-known config paths
		if err != nil {
			continue
		}
		var parsed mcpFileJSON
		if err := json.Unmarshal(data, &parsed); err != nil {
			continue
		}
		for name, s := range parsed.MCPServers {
			servers = append(servers, MCPServer{
				Name: name, Command: s.Command, Args: s.Args, Env: s.Env, Source: path,
			})
		}
		if cwd != "" {
			if proj, ok := parsed.Projects[cwd]; ok {
				for name, s := range proj.MCPServers {
					servers = append(servers, MCPServer{
						Name: name, Command: s.Command, Args: s.Args, Env: s.Env, Source: path,
					})
				}
			}
		}
	}
	return servers
}

// HyperVault MCP server constants. The hypervault-mcp server talks to a
// single API origin and authenticates with an hv_ key sent in the
// X-HyperVault-Key request header.
const (
	hypervaultDefaultHost = "hypervault.store"
	hypervaultDefaultPort = "443"
	hypervaultKeyEnvVar   = "HYPERVAULT_API_KEY"
	hypervaultURLEnvVar   = "HYPERVAULT_API_URL"
)

// isHypervaultServer reports whether an MCP server entry runs hypervault-mcp,
// either directly (command) or via a launcher (e.g. "uvx hypervault-mcp").
func isHypervaultServer(s MCPServer) bool {
	if strings.Contains(strings.ToLower(filepath.Base(s.Command)), "hypervault-mcp") {
		return true
	}
	for _, arg := range s.Args {
		if strings.Contains(strings.ToLower(arg), "hypervault-mcp") {
			return true
		}
	}
	return false
}

// hypervaultHostPort resolves the API host and port for a hypervault-mcp
// entry. HYPERVAULT_API_URL in the server's env block overrides the default
// origin; an unparsable value falls back to the default.
func hypervaultHostPort(s MCPServer) (host, port string) {
	host, port = hypervaultDefaultHost, hypervaultDefaultPort
	raw := s.Env[hypervaultURLEnvVar]
	if raw == "" {
		return host, port
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return host, port
	}
	host = u.Hostname()
	switch {
	case u.Port() != "":
		port = u.Port()
	case u.Scheme == "http":
		port = "80"
	default:
		port = "443"
	}
	return host, port
}

// HypervaultOverlay returns the config fragment for the HyperVault MCP
// server. Empty host/port select the default API origin. The overlay allows
// exactly one origin and protects HYPERVAULT_API_KEY: the sandboxed agent
// only ever sees a placeholder — greyproxy substitutes the real key into the
// X-HyperVault-Key header at the proxy (which means the proxy sees the key in
// plaintext inside the TLS stream on that path; that is how credential
// protection works by design).
func HypervaultOverlay(host, port string) *config.Config {
	if host == "" {
		host = hypervaultDefaultHost
	}
	if port == "" {
		port = hypervaultDefaultPort
	}
	return &config.Config{
		Network: config.NetworkConfig{
			Rules: []config.NetworkRule{{
				Destination: host,
				Port:        port,
				Action:      "allow",
				Notes:       "HyperVault API (hypervault-mcp); HYPERVAULT_API_KEY is substituted at the proxy",
			}},
		},
		Credentials: config.CredentialConfig{
			Secrets: []string{hypervaultKeyEnvVar},
		},
	}
}

// mcpOverlayFromServers builds a single overlay from the recognized MCP
// servers in the list. Returns nil when nothing recognized is configured.
// Currently hypervault-mcp is the only recognized server.
func mcpOverlayFromServers(servers []MCPServer, notify func(format string, args ...any)) *config.Config {
	var overlay *config.Config
	for _, s := range servers {
		if !isHypervaultServer(s) {
			continue
		}
		host, port := hypervaultHostPort(s)
		fragment := HypervaultOverlay(host, port)
		if notify != nil {
			notify("[greywall:mcp] Detected hypervault-mcp in %s: allowing %s:%s and protecting %s\n",
				s.Source, host, port, hypervaultKeyEnvVar)
		}
		if overlay == nil {
			overlay = fragment
		} else {
			overlay = config.Merge(overlay, fragment)
		}
	}
	return overlay
}

// mcpOverlayOnce caches the per-run detection result so the overlay is
// computed (and its notice printed) at most once per process, no matter how
// many profile paths ask for it.
var mcpOverlayOnce = sync.OnceValue(func() *config.Config {
	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	servers := DetectMCPServers(cwd, home)
	return mcpOverlayFromServers(servers, func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format, args...)
	})
})

// DetectMCPOverlay returns a config fragment derived from MCP servers
// configured for the current user/project (e.g. hypervault-mcp), or nil when
// none are found. The result is cached for the lifetime of the process.
func DetectMCPOverlay() *config.Config {
	return mcpOverlayOnce()
}
