package profiles

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestDetectMCPServers_ProjectMCPJSON(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	writeFile(t, filepath.Join(cwd, ".mcp.json"), `{
		"mcpServers": {
			"hypervault": {
				"command": "hypervault-mcp",
				"env": {"HYPERVAULT_API_KEY": "hv_test"}
			}
		}
	}`)

	servers := DetectMCPServers(cwd, home)
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Name != "hypervault" || servers[0].Command != "hypervault-mcp" {
		t.Errorf("unexpected server: %+v", servers[0])
	}
	if servers[0].Source != filepath.Join(cwd, ".mcp.json") {
		t.Errorf("unexpected source: %s", servers[0].Source)
	}
}

func TestDetectMCPServers_ClaudeJSONGlobalAndProject(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	otherProject := "/some/other/project"
	writeFile(t, filepath.Join(home, ".claude.json"), `{
		"mcpServers": {
			"global-server": {"command": "global-mcp"}
		},
		"projects": {
			"`+cwd+`": {
				"mcpServers": {"project-server": {"command": "project-mcp"}}
			},
			"`+otherProject+`": {
				"mcpServers": {"foreign-server": {"command": "foreign-mcp"}}
			}
		}
	}`)

	servers := DetectMCPServers(cwd, home)
	names := make(map[string]bool)
	for _, s := range servers {
		names[s.Name] = true
	}
	if !names["global-server"] {
		t.Error("expected global-server to be detected")
	}
	if !names["project-server"] {
		t.Error("expected project-server (scoped to cwd) to be detected")
	}
	if names["foreign-server"] {
		t.Error("foreign-server belongs to a different project and must not be detected")
	}
}

func TestDetectMCPServers_SkipsMalformedFiles(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	writeFile(t, filepath.Join(cwd, ".mcp.json"), `{not valid json`)
	writeFile(t, filepath.Join(home, ".mcp.json"), `{"mcpServers": {"ok": {"command": "ok-mcp"}}}`)

	servers := DetectMCPServers(cwd, home)
	if len(servers) != 1 || servers[0].Name != "ok" {
		t.Fatalf("expected only the valid file's server, got %+v", servers)
	}
}

func TestIsHypervaultServer(t *testing.T) {
	tests := []struct {
		name   string
		server MCPServer
		want   bool
	}{
		{"direct command", MCPServer{Command: "hypervault-mcp"}, true},
		{"absolute path", MCPServer{Command: "/usr/local/bin/hypervault-mcp"}, true},
		{"via uvx", MCPServer{Command: "uvx", Args: []string{"hypervault-mcp"}}, true},
		{"via pipx run", MCPServer{Command: "pipx", Args: []string{"run", "hypervault-mcp"}}, true},
		{"unrelated", MCPServer{Command: "github-mcp", Args: []string{"stdio"}}, false},
		{"empty", MCPServer{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHypervaultServer(tt.server); got != tt.want {
				t.Errorf("isHypervaultServer(%+v) = %v, want %v", tt.server, got, tt.want)
			}
		})
	}
}

func TestHypervaultHostPort(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantHost string
		wantPort string
	}{
		{"default", nil, "hypervault.store", "443"},
		{"custom https", map[string]string{"HYPERVAULT_API_URL": "https://api.example.com"}, "api.example.com", "443"},
		{"custom with port", map[string]string{"HYPERVAULT_API_URL": "https://api.example.com:8443"}, "api.example.com", "8443"},
		{"http scheme", map[string]string{"HYPERVAULT_API_URL": "http://localhost.dev"}, "localhost.dev", "80"},
		{"unparsable falls back", map[string]string{"HYPERVAULT_API_URL": "::not a url::"}, "hypervault.store", "443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := hypervaultHostPort(MCPServer{Env: tt.env})
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("got %s:%s, want %s:%s", host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestHypervaultOverlay(t *testing.T) {
	overlay := HypervaultOverlay("", "")
	if len(overlay.Network.Rules) != 1 {
		t.Fatalf("expected 1 network rule, got %d", len(overlay.Network.Rules))
	}
	rule := overlay.Network.Rules[0]
	if rule.Destination != "hypervault.store" || rule.Port != "443" || rule.Action != "allow" {
		t.Errorf("unexpected rule: %+v", rule)
	}
	found := false
	for _, s := range overlay.Credentials.Secrets {
		if s == "HYPERVAULT_API_KEY" {
			found = true
		}
	}
	if !found {
		t.Error("expected HYPERVAULT_API_KEY in credentials.secrets")
	}
}

func TestMCPOverlayFromServers(t *testing.T) {
	t.Run("no servers", func(t *testing.T) {
		if overlay := mcpOverlayFromServers(nil, nil); overlay != nil {
			t.Errorf("expected nil overlay, got %+v", overlay)
		}
	})

	t.Run("unrecognized servers only", func(t *testing.T) {
		servers := []MCPServer{{Name: "other", Command: "other-mcp"}}
		if overlay := mcpOverlayFromServers(servers, nil); overlay != nil {
			t.Errorf("expected nil overlay, got %+v", overlay)
		}
	})

	t.Run("hypervault with custom host", func(t *testing.T) {
		servers := []MCPServer{{
			Name:    "hypervault",
			Command: "uvx",
			Args:    []string{"hypervault-mcp"},
			Env:     map[string]string{"HYPERVAULT_API_URL": "https://staging.example.com"},
			Source:  "/tmp/.mcp.json",
		}}
		notices := 0
		overlay := mcpOverlayFromServers(servers, func(string, ...any) { notices++ })
		if overlay == nil {
			t.Fatal("expected overlay")
		}
		if len(overlay.Network.Rules) != 1 || overlay.Network.Rules[0].Destination != "staging.example.com" {
			t.Errorf("unexpected rules: %+v", overlay.Network.Rules)
		}
		if notices != 1 {
			t.Errorf("expected 1 notice, got %d", notices)
		}
	})

	t.Run("duplicate entries deduplicate", func(t *testing.T) {
		server := MCPServer{Name: "hypervault", Command: "hypervault-mcp"}
		overlay := mcpOverlayFromServers([]MCPServer{server, server}, nil)
		if overlay == nil {
			t.Fatal("expected overlay")
		}
		if len(overlay.Network.Rules) != 1 {
			t.Errorf("expected 1 deduplicated rule, got %d", len(overlay.Network.Rules))
		}
		if len(overlay.Credentials.Secrets) != 1 {
			t.Errorf("expected 1 deduplicated secret, got %d", len(overlay.Credentials.Secrets))
		}
	})
}
