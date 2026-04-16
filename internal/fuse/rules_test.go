package fuse

import "testing"

func TestMatchSimple(t *testing.T) {
	rs := &Ruleset{
		Default: ActionAllow,
		Rules: []Rule{
			{
				Name:       "git-dotgit",
				CallerGlob: "**/git",
				PathGlob:   "**/.git/**",
				Ops:        []string{"read", "write"},
				Action:     ActionAllow,
			},
			{
				Name:       "block-ssh",
				CallerGlob: "*",
				PathGlob:   "**/.ssh/id_*",
				Action:     ActionDeny,
			},
		},
	}

	cases := []struct {
		caller string
		path   string
		op     Op
		want   Action
		rule   string
	}{
		{"/usr/bin/git", "/home/u/project/.git/HEAD", OpRead, ActionAllow, "git-dotgit"},
		{"/usr/bin/cat", "/home/u/.ssh/id_rsa", OpRead, ActionDeny, "block-ssh"},
		{"/usr/bin/cat", "/home/u/nothing", OpRead, ActionAllow, ""},
		{"/usr/bin/git", "/home/u/project/.git/config", OpGetattr, ActionAllow, ""}, // op not in list -> falls through to default
	}
	for _, c := range cases {
		got, rule := rs.Match(c.caller, c.path, c.op)
		if got != c.want || rule != c.rule {
			t.Errorf("Match(%q,%q,%s) = (%s,%s), want (%s,%s)", c.caller, c.path, c.op, got, rule, c.want, c.rule)
		}
	}
}

func TestMatchFirstWins(t *testing.T) {
	rs := &Ruleset{
		Default: ActionAllow,
		Rules: []Rule{
			{Name: "allow-git", CallerGlob: "**/git", PathGlob: "**/.git/**", Action: ActionAllow},
			{Name: "deny-all", CallerGlob: "*", PathGlob: "**/.git/**", Action: ActionDeny},
		},
	}
	got, rule := rs.Match("/usr/bin/git", "/repo/.git/config", OpRead)
	if got != ActionAllow || rule != "allow-git" {
		t.Errorf("git should hit allow rule first, got (%s,%s)", got, rule)
	}
	got, rule = rs.Match("/usr/bin/python3", "/repo/.git/config", OpRead)
	if got != ActionDeny || rule != "deny-all" {
		t.Errorf("non-git should hit deny rule, got (%s,%s)", got, rule)
	}
}

func TestMatchDefaultFallback(t *testing.T) {
	rs := &Ruleset{Default: ActionDeny}
	got, rule := rs.Match("/bin/cat", "/anything", OpRead)
	if got != ActionDeny || rule != "" {
		t.Errorf("default deny expected, got (%s,%s)", got, rule)
	}
}

func TestValidateRejectsBadAction(t *testing.T) {
	rs := &Ruleset{
		Rules: []Rule{{Name: "x", CallerGlob: "*", PathGlob: "**", Action: "maybe"}},
	}
	if err := rs.Validate(); err == nil {
		t.Error("expected validation error for unknown action")
	}
}

func TestValidateRejectsUnknownOp(t *testing.T) {
	rs := &Ruleset{
		Rules: []Rule{{Name: "x", CallerGlob: "*", PathGlob: "**", Ops: []string{"teleport"}, Action: ActionAllow}},
	}
	if err := rs.Validate(); err == nil {
		t.Error("expected validation error for unknown op")
	}
}

func TestValidateAcceptsGoodRuleset(t *testing.T) {
	rs := &Ruleset{
		Default: ActionAllow,
		Rules: []Rule{
			{Name: "x", CallerGlob: "**/git", PathGlob: "**/.git/**", Ops: []string{"read", "write"}, Action: ActionAllow},
		},
	}
	if err := rs.Validate(); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}
