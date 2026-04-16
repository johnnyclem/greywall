package fuse

import (
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// Rule describes a single caller-path-op match with an action.
type Rule struct {
	Name       string   `yaml:"name"`
	CallerGlob string   `yaml:"caller"`
	PathGlob   string   `yaml:"path"`
	Ops        []string `yaml:"ops"`
	Action     Action   `yaml:"action"`
}

// Ruleset is a first-match-wins list of rules with a default action.
type Ruleset struct {
	// Default is the action applied when no rule matches. Must be one of
	// allow, deny, log.
	Default Action `yaml:"default"`
	Rules   []Rule `yaml:"rules"`
}

// Match walks the ruleset and returns the first rule whose caller, path,
// and op all match. Returns the default action when nothing matches.
//
// Matching semantics:
//   - CallerGlob "" or "*" matches any caller.
//   - PathGlob "" matches any path.
//   - Ops nil/empty matches any op.
//   - Globs use doublestar (** for recursive).
//
// A malformed glob causes the rule to be skipped (not a match), which
// keeps the hot path panic-free. Config loading is where we catch bad
// patterns.
func (rs *Ruleset) Match(caller, path string, op Op) (Action, string) {
	if rs == nil {
		return ActionAllow, ""
	}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if !matchOp(r.Ops, op) {
			continue
		}
		if !matchGlob(r.CallerGlob, caller) {
			continue
		}
		if !matchGlob(r.PathGlob, path) {
			continue
		}
		return r.Action, r.Name
	}
	if rs.Default == "" {
		return ActionAllow, ""
	}
	return rs.Default, ""
}

// Validate checks that every rule has a well-formed glob and a known
// action. It is called at config load time.
func (rs *Ruleset) Validate() error {
	if rs.Default != "" && !knownAction(rs.Default) {
		return fmt.Errorf("invalid default action %q", rs.Default)
	}
	for i, r := range rs.Rules {
		if !knownAction(r.Action) {
			return fmt.Errorf("rule %d (%q): invalid action %q", i, r.Name, r.Action)
		}
		if r.CallerGlob != "" && r.CallerGlob != "*" {
			if _, err := doublestar.Match(r.CallerGlob, ""); err != nil {
				return fmt.Errorf("rule %d (%q): bad caller glob: %w", i, r.Name, err)
			}
		}
		if r.PathGlob != "" {
			if _, err := doublestar.Match(r.PathGlob, ""); err != nil {
				return fmt.Errorf("rule %d (%q): bad path glob: %w", i, r.Name, err)
			}
		}
		for _, o := range r.Ops {
			if !knownOp(Op(o)) {
				return fmt.Errorf("rule %d (%q): unknown op %q", i, r.Name, o)
			}
		}
	}
	return nil
}

func knownAction(a Action) bool {
	switch a {
	case ActionAllow, ActionDeny, ActionLog:
		return true
	}
	return false
}

func knownOp(o Op) bool {
	switch o {
	case OpLookup, OpOpen, OpCreate, OpRead, OpWrite,
		OpUnlink, OpRmdir, OpMkdir, OpRename, OpGetattr:
		return true
	}
	return false
}

func matchOp(ops []string, op Op) bool {
	if len(ops) == 0 {
		return true
	}
	for _, o := range ops {
		if strings.EqualFold(o, string(op)) {
			return true
		}
	}
	return false
}

func matchGlob(glob, s string) bool {
	if glob == "" || glob == "*" {
		return true
	}
	ok, err := doublestar.PathMatch(glob, s)
	if err != nil {
		return false
	}
	return ok
}
