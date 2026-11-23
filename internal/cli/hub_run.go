package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/lunalully/cyberm4ncer/internal/banner"
	"github.com/lunalully/cyberm4ncer/internal/hub"
	"github.com/spf13/cobra"
)

// hubInteractive is the terminal probe the hub command consults. It is a
// variable so tests can exercise the startup path without a pseudo-terminal.
var hubInteractive = interactive

// interactive reports whether the Operations Hub can run: both streams must
// be terminals, otherwise the plain help is printed instead.
func interactive(opts *rootOptions) bool {
	in, ok := opts.streams.In.(*os.File)
	if !ok {
		return false
	}
	inInfo, err := in.Stat()
	if err != nil || inInfo.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	out, ok := opts.streams.Out.(*os.File)
	if !ok {
		return false
	}
	outInfo, err := out.Stat()
	if err != nil || outInfo.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return true
}

// hubCommand builds the top-level Operations Hub command.
func hubCommand(opts *rootOptions) *cobra.Command {
	var scopeFile, mode, file, wordlist, userList, passList, timeout string
	var level, repeat int
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "Open the interactive Operations Hub",
		Long: `Open the interactive Operations Hub.

The hub lists what the framework can really do: the reviewed aggressive engine
for every category, external tool detection, configuration and scope, and the
operation history stored in the local database.

Targets are optional: the hub asks for one (or several) inside the session and
keeps it until you reset the session. A scope file is optional too; when given
it is enforced before every command.`,
		Example: `  cyberm4ncer hub
  cyberm4ncer hub --scope engagement.yaml
  cyberm4ncer hub 10.0.0.5 --mode recon`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !hubInteractive(opts) {
				return fmt.Errorf("the Operations Hub needs a terminal; run it from an interactive shell")
			}
			options := &aggressiveOptions{
				scopeFile: scopeFile, mode: mode, level: level, repeat: repeat,
				wordlist: wordlist, userList: userList, passList: passList,
			}
			if timeout != "" {
				parsed, err := time.ParseDuration(timeout)
				if err != nil {
					return fmt.Errorf("invalid timeout %q: %w", timeout, err)
				}
				options.timeout = parsed
			}
			switch mode {
			case "", "all", "recon", "enum", "vuln":
			default:
				return fmt.Errorf("invalid mode %q (all, recon, enum, vuln)", mode)
			}
			// Targets are optional: the hub asks for them inside the session,
			// so an empty list starts the app instead of aborting the command.
			targets, err := collectTargets(args, file)
			if err != nil {
				return err
			}
			policy, scopePath, err := resolveOptionalPolicy(opts, scopeFile)
			if err != nil {
				return err
			}
			_ = policy
			service, err := newHubService(cmd.Context(), opts)
			if err != nil {
				return err
			}
			defer service.Close()
			service.scopePath = scopePath

			printer := opts.printer()
			app := &hub.App{
				UI:      hub.NewUI(os.Stdin, opts.streams.Out, printer),
				Service: service,
				Out:     opts.streams.Out,
				Options: hubOptions(options, scopePath, targets),
			}
			if printer.Color {
				app.Palette.Accent = sgrAccent
				app.Palette.Dim = sgrDim
				app.Palette.Reset = sgrReset
			}
			return app.Run(cmd.Context())
		},
	}
	flags := cmd.Flags()
	flags.StringVarP(&scopeFile, "scope", "s", "", "optional scope file (default: configured, discovered, or none)")
	flags.StringVar(&mode, "mode", "", "default tool selection: all, recon, enum, vuln")
	flags.IntVar(&level, "level", 0, "default intensity 1..5 (5 when omitted)")
	flags.IntVar(&repeat, "repeat", 0, "default repetition cap (0 keeps the reviewed values)")
	flags.StringVar(&timeout, "timeout", "", "default per-execution timeout (e.g. 45s)")
	flags.StringVarP(&file, "file", "f", "", "file with one target per line")
	flags.StringVar(&wordlist, "wordlist", "", "web wordlist")
	flags.StringVar(&userList, "userlist", "", "usernames for hydra/medusa")
	flags.StringVar(&passList, "passlist", "", "passwords for hydra/medusa")
	return cmd
}

const (
	sgrAccent = "\x1b[38;5;135m"
	sgrDim    = "\x1b[2m"
	sgrReset  = "\x1b[0m"
)

// printStartupBanner draws the header above the help of a bare invocation.
func printStartupBanner(opts *rootOptions) {
	printer := opts.printer()
	palette := banner.NeonPurple()
	if !printer.Color {
		palette = banner.Plain()
	}
	_ = banner.Render(opts.streams.Out, banner.Lines(), "", 0, palette)
	fmt.Fprintln(opts.streams.Out)
}

// attachHub opens the hub when the root command runs without a subcommand in
// an interactive terminal.
func attachHub(root *cobra.Command, opts *rootOptions) {
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("unknown command %q", args[0])
		}
		if !interactive(opts) {
			printStartupBanner(opts)
			return cmd.Help()
		}
		return runHub(cmd.Context(), opts)
	}
}

// runHub opens the interactive Operations Hub with the CLI defaults.
func runHub(ctx context.Context, opts *rootOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	service, err := newHubService(ctx, opts)
	if err != nil {
		return err
	}
	defer service.Close()
	printer := opts.printer()
	app := &hub.App{
		UI:      hub.NewUI(os.Stdin, opts.streams.Out, printer),
		Service: service,
		Out:     opts.streams.Out,
	}
	if printer.Color {
		app.Palette.Accent = sgrAccent
		app.Palette.Dim = sgrDim
		app.Palette.Reset = sgrReset
	}
	return app.Run(ctx)
}
