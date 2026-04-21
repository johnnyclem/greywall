//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// WrapCommandLinuxNoBwrap produces a command string for --no-bwrap mode.
//
// Instead of building a bubblewrap invocation, this path generates a small
// shell script that:
//  1. Exports GREYWALL_CONFIG_JSON so the --landlock-apply wrapper picks up
//     the same config the parent greywall process resolved.
//  2. Exports ALL_PROXY / HTTP_PROXY / HTTPS_PROXY when the config declares a
//     SOCKS5 or HTTP proxy. This is the env-var-based fallback — the wrapped
//     command has no network namespace, so well-behaved HTTP clients honor
//     the proxy env, but raw sockets will *not* be forced through it. For
//     kernel-enforced capture, combine with a pre-built netns (--netns).
//  3. Execs `greywall --landlock-apply --seccomp -- bash -c "<cmd>"`, which
//     applies Landlock + seccomp to the current process then execs the user
//     command.
//
// Intended for nested-Docker environments where bwrap cannot create user
// namespaces (uid_map write blocked by the host's LinuxKit VM).
func WrapCommandLinuxNoBwrap(cfg *config.Config, command string, debug bool) (string, error) {
	greywallExePath, err := os.Executable()
	if err != nil || greywallExePath == "" {
		return "", fmt.Errorf("no-bwrap: cannot resolve greywall executable path: %w", err)
	}

	var script strings.Builder

	if cfg != nil {
		configJSON, err := json.Marshal(cfg)
		if err == nil {
			fmt.Fprintf(&script, "export GREYWALL_CONFIG_JSON=%s\n",
				ShellQuoteSingle(string(configJSON)))
		}

		if cfg.Network.ProxyURL != "" {
			fmt.Fprintf(&script, "export ALL_PROXY=%s\n", ShellQuoteSingle(cfg.Network.ProxyURL))
			fmt.Fprintf(&script, "export HTTPS_PROXY=%s\n", ShellQuoteSingle(cfg.Network.ProxyURL))
			fmt.Fprintf(&script, "export https_proxy=%s\n", ShellQuoteSingle(cfg.Network.ProxyURL))
		}
		if cfg.Network.HTTPProxyURL != "" {
			fmt.Fprintf(&script, "export HTTP_PROXY=%s\n", ShellQuoteSingle(cfg.Network.HTTPProxyURL))
			fmt.Fprintf(&script, "export http_proxy=%s\n", ShellQuoteSingle(cfg.Network.HTTPProxyURL))
		} else if cfg.Network.ProxyURL != "" {
			fmt.Fprintf(&script, "export HTTP_PROXY=%s\n", ShellQuoteSingle(cfg.Network.ProxyURL))
			fmt.Fprintf(&script, "export http_proxy=%s\n", ShellQuoteSingle(cfg.Network.ProxyURL))
		}
	}

	wrapperArgs := []string{greywallExePath, "--landlock-apply", "--seccomp"}
	if debug {
		wrapperArgs = append(wrapperArgs, "--debug")
	}
	wrapperArgs = append(wrapperArgs, "--", "bash", "-c", command)

	fmt.Fprintf(&script, "exec %s\n", ShellQuote(wrapperArgs))

	return script.String(), nil
}
