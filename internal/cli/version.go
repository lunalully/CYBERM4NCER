package cli

import (
	"fmt"

	"github.com/lunalully/cyberm4ncer/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Current()
			printer := opts.printer()
			if opts.json {
				return printer.JSONValue(info)
			}
			fmt.Fprintf(printer.Out, "CYBERM4NCER %s\n", info.Version)
			fmt.Fprintf(printer.Out, "Commit:   %s\n", info.Commit)
			fmt.Fprintf(printer.Out, "Built:    %s\n", info.BuildDate)
			fmt.Fprintf(printer.Out, "Go:       %s\n", info.GoVersion)
			fmt.Fprintf(printer.Out, "Platform: %s/%s\n", info.OS, info.Arch)
			return nil
		},
	}
}
