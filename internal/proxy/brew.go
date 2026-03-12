package proxy

import (
	"os/exec"
	"strings"
)

// IsBrewManaged returns true if the greyproxy binary at the given path
// is managed by Homebrew (i.e. lives under a Homebrew prefix).
func IsBrewManaged(binaryPath string) bool {
	if binaryPath == "" {
		return false
	}

	brewPrefix := brewPrefixPath()
	if brewPrefix == "" {
		return false
	}

	return strings.HasPrefix(binaryPath, brewPrefix)
}

// brewPrefixPath returns the Homebrew prefix (e.g. /opt/homebrew, /usr/local).
func brewPrefixPath() string {
	out, err := exec.Command("brew", "--prefix").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
