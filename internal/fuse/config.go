package fuse

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadRuleset reads a YAML ruleset from path and validates it.
func LoadRuleset(path string) (*Ruleset, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	var rs Ruleset
	if err := yaml.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if err := rs.Validate(); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}
	return &rs, nil
}
