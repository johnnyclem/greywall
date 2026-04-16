//go:build !linux

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newFuseNsSetupCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "fuse-ns-setup",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("fuse-ns-setup is Linux-only")
		},
	}
}
