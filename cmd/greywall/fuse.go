package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	gwfuse "github.com/GreyhavenHQ/greywall/internal/fuse"
)

// newFuseCmd returns the `greywall fuse` cobra subcommand.
//
// This subcommand is intentionally standalone: it does NOT touch the
// bubblewrap / Landlock / seccomp pipeline used by the main `greywall`
// invocation. It exists to validate the FUSE observability approach
// independently of the main sandbox.
func newFuseCmd() *cobra.Command {
	var (
		mountPoint  string
		backing     string
		rulesPath   string
		observeOnly bool
		debug       bool
		chdirTo     string
		eventsFile  string
	)

	cmd := &cobra.Command{
		Use:   "fuse [flags] -- <command> [args...]",
		Short: "Experimental FUSE passthrough with per-caller rules",
		Long: `Experimental FUSE passthrough that intercepts filesystem operations,
resolves the caller to a binary via /proc/<pid>/exe, and emits a JSON
event stream to stdout. Optionally denies operations via per-caller,
per-path rules.

This command is independent of the normal greywall sandbox pipeline.

Example:

  greywall fuse --mount /tmp/gw --rules testdata/fuse/example-rules.yaml -- bash
`,
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFuse(fuseOptions{
				MountPoint:  mountPoint,
				Backing:     backing,
				RulesPath:   rulesPath,
				ObserveOnly: observeOnly,
				Debug:       debug,
				ChdirTo:     chdirTo,
				EventsFile:  eventsFile,
				Command:     args,
			})
		},
	}

	defaultMount := filepath.Join(os.TempDir(), fmt.Sprintf("greywall-fuse-%d", os.Getpid()))
	cmd.Flags().StringVar(&mountPoint, "mount", defaultMount, "Where to mount the FUSE filesystem")
	cmd.Flags().StringVar(&backing, "backing", "/", "Directory on the real filesystem to expose through FUSE")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "YAML rules file (if empty, default=allow and events are logged)")
	cmd.Flags().BoolVar(&observeOnly, "observe-only", false, "Never enforce deny: log everything, let everything through")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable verbose go-fuse request logging on stderr")
	cmd.Flags().StringVar(&chdirTo, "cwd", "", "chdir target for the spawned command; path is interpreted inside the FUSE mount. Defaults to the process's CWD translated into the mount.")
	cmd.Flags().StringVar(&eventsFile, "events-file", "", "Write JSON events to this file instead of stdout. File is truncated at open, then appended line-by-line.")
	return cmd
}

type fuseOptions struct {
	MountPoint  string
	Backing     string
	RulesPath   string
	ObserveOnly bool
	Debug       bool
	ChdirTo     string
	EventsFile  string
	Command     []string
}

func runFuse(opts fuseOptions) error {
	// 1. Load rules (or default-allow).
	var rules *gwfuse.Ruleset
	if opts.RulesPath != "" {
		rs, err := gwfuse.LoadRuleset(opts.RulesPath)
		if err != nil {
			return fmt.Errorf("load rules: %w", err)
		}
		rules = rs
		fmt.Fprintf(os.Stderr, "[greywall fuse] loaded %d rule(s) from %s (default=%s)\n",
			len(rs.Rules), opts.RulesPath, defaultOrAllow(rs.Default))
	} else {
		rules = &gwfuse.Ruleset{Default: gwfuse.ActionAllow}
		fmt.Fprintf(os.Stderr, "[greywall fuse] no rules file; default=allow\n")
	}

	// 2. Build hooks.
	var sinkWriter *os.File
	if opts.EventsFile != "" {
		f, err := os.Create(opts.EventsFile)
		if err != nil {
			return fmt.Errorf("open events file: %w", err)
		}
		defer f.Close()
		sinkWriter = f
		fmt.Fprintf(os.Stderr, "[greywall fuse] writing events to %s\n", opts.EventsFile)
	} else {
		sinkWriter = os.Stdout
	}
	hooks := &gwfuse.Hooks{
		Resolver:    gwfuse.NewProcResolver(1 * time.Second),
		Rules:       rules,
		Sink:        gwfuse.NewStdoutSink(sinkWriter),
		ObserveOnly: opts.ObserveOnly,
	}

	// 3. Mount.
	mnt, err := gwfuse.New(gwfuse.Config{
		Backing:    opts.Backing,
		MountPoint: opts.MountPoint,
		Hooks:      hooks,
		Debug:      opts.Debug,
	})
	if err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[greywall fuse] mounted %s -> %s\n", opts.Backing, opts.MountPoint)

	// Ensure we always clean up.
	defer func() {
		if cerr := mnt.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "[greywall fuse] unmount error: %v\n", cerr)
		}
	}()

	// 4. Signal handling: unmount on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Fprintf(os.Stderr, "[greywall fuse] received %s, unmounting\n", sig)
		_ = mnt.Close()
	}()

	// 5. Resolve chdir target inside the mount.
	cwdInMount := opts.ChdirTo
	if cwdInMount == "" {
		realCwd, err := os.Getwd()
		if err == nil && filepath.IsAbs(realCwd) {
			// Translate realCwd into the mount: if backing is / and
			// realCwd is /home/x, cwdInMount = /tmp/gw/home/x.
			rel, err := filepath.Rel(opts.Backing, realCwd)
			if err == nil {
				cwdInMount = filepath.Join(opts.MountPoint, rel)
			}
		}
	}

	// 6. Exec the child command.
	child := exec.Command(opts.Command[0], opts.Command[1:]...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = os.Environ()
	if cwdInMount != "" {
		if _, err := os.Stat(cwdInMount); err == nil {
			child.Dir = cwdInMount
		} else {
			fmt.Fprintf(os.Stderr, "[greywall fuse] warning: chdir target %q not usable (%v), falling back to inherited CWD\n", cwdInMount, err)
		}
	}

	fmt.Fprintf(os.Stderr, "[greywall fuse] exec %v (cwd=%s)\n", opts.Command, child.Dir)
	runErr := child.Run()

	// 7. Return with child's exit code.
	if runErr == nil {
		return nil
	}
	if ee, ok := runErr.(*exec.ExitError); ok {
		// Propagate the child's exit code via a cobra-friendly error.
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			os.Exit(ws.ExitStatus())
		}
	}
	return runErr
}

func defaultOrAllow(a gwfuse.Action) gwfuse.Action {
	if a == "" {
		return gwfuse.ActionAllow
	}
	return a
}
