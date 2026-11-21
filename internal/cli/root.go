// Package cli implements the CYBERM4NCER command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/lunalully/cyberm4ncer/internal/core"
	"github.com/lunalully/cyberm4ncer/internal/ui"
	"github.com/lunalully/cyberm4ncer/internal/version"
	"github.com/spf13/cobra"
)

// Streams allows tests to capture command output.
type Streams struct {
	Out io.Writer
	Err io.Writer
	In  io.Reader
}

type rootOptions struct {
	configPath string
	dataDir    string
	logLevel   string
	json       bool
	noColor    bool
	verbose    bool
	streams    Streams
}

func (o *rootOptions) printer() *ui.Printer {
	printer := ui.New(o.streams.Out, o.streams.Err, o.noColor)
	printer.JSON = o.json
	return printer
}

func (o *rootOptions) openCore(ctx context.Context) (*core.Core, error) {
	return core.Open(ctx, core.Options{
		ConfigPath: o.configPath,
		DataDir:    o.dataDir,
		LogLevel:   o.logLevel,
		Verbose:    o.verbose,
		Stderr:     o.streams.Err,
	})
}

// NewRoot builds the command tree.
func NewRoot(streams Streams) *cobra.Command {
	if streams.Out == nil {
		streams.Out = os.Stdout
	}
	if streams.Err == nil {
		streams.Err = os.Stderr
	}
	if streams.In == nil {
		streams.In = os.Stdin
	}
	opts := &rootOptions{streams: streams}

	root := &cobra.Command{
		Use:           "cyberm4ncer",
		Short:         "Modular Offensive Security Framework",
		Version:       version.Current().Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `CYBERM4NCER is a modular offensive security framework for authorized
security assessments. It centralizes tool discovery, scoped execution,
normalized results and reporting.

Authorization is mandatory: every external target must be covered by an
explicit scope file before a module can run.`,
		Example: `  cyberm4ncer doctor
  cyberm4ncer scope validate engagement.yaml
  cyberm4ncer scope check example.com --file engagement.yaml
  cyberm4ncer tools list
  cyberm4ncer tools detect nuclei`,
	}
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	root.CompletionOptions.DisableDefaultCmd = true

	flags := root.PersistentFlags()
	flags.StringVar(&opts.configPath, "config", "", "configuration file (default: XDG config path)")
	flags.StringVar(&opts.dataDir, "data-dir", "", "override the data directory")
	flags.StringVar(&opts.logLevel, "log-level", "", "override log level (debug, info, warn, error)")
	flags.BoolVar(&opts.json, "json", false, "emit machine-readable JSON")
	flags.BoolVar(&opts.noColor, "no-color", false, "disable ANSI colors")
	flags.BoolVarP(&opts.verbose, "verbose", "v", false, "enable debug logging")

	root.AddCommand(
		newVersionCmd(opts),
		newDoctorCmd(opts),
		newConfigCmd(opts),
		newScopeCmd(opts),
		newToolsCmd(opts),
	)
	return root
}

// Execute runs the CLI and returns a process exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := NewRoot(Streams{})
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	code := ExitCode(err)
	var exit *ExitError
	if !errors.As(err, &exit) || !exit.Silent {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	return code
}
