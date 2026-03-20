//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLinux_SymlinkedShellConfigReadable verifies that symlinked dotfiles
// (e.g., ~/.zshrc managed by GNU Stow) are readable inside the sandbox in
// deny-by-default mode. Previously, canMountOver() rejected symlinks entirely,
// causing bwrap to skip them.
func TestLinux_SymlinkedShellConfigReadable(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "bwrap")

	workspace := createTempWorkspace(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}

	// Check if any shell config is a symlink
	shellConfigs := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv"}
	var symlinkConfig string
	for _, f := range shellConfigs {
		p := filepath.Join(home, f)
		if isSymlink(p) {
			symlinkConfig = p
			break
		}
	}
	if symlinkConfig == "" {
		// Create a symlinked shell config for testing
		dotfilesDir := filepath.Join(workspace, "dotfiles")
		if err := os.MkdirAll(dotfilesDir, 0o755); err != nil {
			t.Fatal(err)
		}
		realFile := filepath.Join(dotfilesDir, ".greywall-test-rc")
		if err := os.WriteFile(realFile, []byte("# greywall symlink test\nexport GREYWALL_TEST=1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		symlinkConfig = filepath.Join(home, ".greywall-test-rc")
		if err := os.Symlink(realFile, symlinkConfig); err != nil {
			t.Fatalf("failed to create test symlink: %v", err)
		}
		defer os.Remove(symlinkConfig)
	}

	// Verify it's actually a symlink
	if !isSymlink(symlinkConfig) {
		t.Fatalf("expected %s to be a symlink", symlinkConfig)
	}

	// Use deny-by-default mode (where buildDenyByDefaultMounts is used)
	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DefaultDenyRead = boolPtr(true)
	cfg.Filesystem.AllowRead = []string{symlinkConfig}

	result := runUnderSandbox(t, cfg, "cat "+symlinkConfig, workspace)

	assertAllowed(t, result)
	if !strings.Contains(result.Stdout, "greywall") && !strings.Contains(result.Stdout, "export") {
		// If it's the user's real config, just check it's non-empty
		if result.Stdout == "" {
			t.Error("expected to read symlinked config content, got empty output")
		}
	}
}

// TestLinux_SymlinkedAllowReadPath verifies that user-specified allowRead paths
// that are symlinks are resolved and accessible inside the sandbox.
func TestLinux_SymlinkedAllowReadPath(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "bwrap")

	workspace := createTempWorkspace(t)

	// Create a real file and a symlink to it
	realFile := filepath.Join(workspace, "real-data.txt")
	if err := os.WriteFile(realFile, []byte("symlink-test-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(workspace, "link-data.txt")
	if err := os.Symlink(realFile, symlink); err != nil {
		t.Fatal(err)
	}

	cfg := testConfigWithWorkspace(workspace)
	cfg.Filesystem.DefaultDenyRead = boolPtr(true)
	cfg.Filesystem.AllowRead = []string{symlink}

	result := runUnderSandbox(t, cfg, "cat "+symlink, workspace)

	assertAllowed(t, result)
	assertContains(t, result.Stdout, "symlink-test-content")
}

