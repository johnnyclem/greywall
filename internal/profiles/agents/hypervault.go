package agents

import (
	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/profiles"
)

func init() {
	// hypervault-mcp is an MCP server, not an agent: it runs inside the
	// sandbox of whichever agent spawned it. The profile is registered as a
	// toolchain so it composes with agent profiles (--profile claude,hypervault)
	// and is also folded in automatically when hypervault-mcp is detected in
	// the agent's MCP configuration (see profiles.DetectMCPOverlay).
	//
	// The server needs no filesystem grants of its own: it only reads the
	// Python interpreter and site-packages, which the python toolchain
	// profile covers.
	profiles.Register(profiles.AgentDef{
		Names:     []string{"hypervault", "hypervault-mcp"},
		Toolchain: true,
		Overlay: func() *config.Config {
			return profiles.HypervaultOverlay("", "")
		},
	})
}
