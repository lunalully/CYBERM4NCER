package cli

import (
	"fmt"
	"strings"

	"github.com/lunalully/cyberm4ncer/internal/config"
	"github.com/lunalully/cyberm4ncer/internal/scope"
	"github.com/spf13/cobra"
)

func newScopeCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Validate and enforce authorization scope",
		Long: `Scope files declare which assets are authorized for testing.

Every scope requires a project name, an explicit authorization statement and
at least one include rule. Exclusions always take precedence.`,
	}
	cmd.AddCommand(newScopeValidateCmd(opts), newScopeCheckCmd(opts))
	return cmd
}

func resolvePolicy(opts *rootOptions, explicit string) (*scope.Policy, string, error) {
	cfg, meta, err := loadConfig(opts)
	if err != nil {
		return nil, "", err
	}
	path := config.DiscoverScopeFile(explicit, cfg, meta.Paths)
	if path == "" {
		return nil, "", fmt.Errorf("no scope file found; pass a path or set scope.file in the configuration")
	}
	policy, err := scope.Load(path)
	if err != nil {
		return nil, path, err
	}
	return policy, path, nil
}

func newScopeValidateCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "validate [file]",
		Short: "Validate a scope file",
		Long: `Validate parses a scope file, compiles all rules and prints a summary.

When no file is given, the configured scope file, ./.cyberm4ncer/scope.yaml or
<data-dir>/scope.yaml is used.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			explicit := ""
			if len(args) == 1 {
				explicit = args[0]
			}
			policy, path, err := resolvePolicy(opts, explicit)
			if err != nil {
				return err
			}
			summary := policy.Summary()
			summary.SourcePath = path
			printer := opts.printer()
			if opts.json {
				return printer.JSONValue(summary)
			}
			printer.Successf("scope is valid: %s", path)
			fmt.Fprintf(printer.Out, "project:       %s\n", summary.Project)
			fmt.Fprintf(printer.Out, "authorization: %s\n", summary.Authorization)
			fmt.Fprintf(printer.Out, "includes:      %d (domains=%d, ips=%d, cidrs=%d)\n",
				summary.Includes, summary.Domains, summary.IPs, summary.CIDRs)
			fmt.Fprintf(printer.Out, "excludes:      %d\n", summary.Excludes)
			if len(summary.Ports) > 0 {
				ports := make([]string, len(summary.Ports))
				for i, port := range summary.Ports {
					ports[i] = fmt.Sprintf("%d", port)
				}
				fmt.Fprintf(printer.Out, "ports:         %s\n", strings.Join(ports, ", "))
			}
			return nil
		},
	}
}

func newScopeCheckCmd(opts *rootOptions) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "check <target>",
		Short: "Check whether a host, URL, IP or CIDR is authorized",
		Long: `Check evaluates a target against the scope file.

Exit codes: 0 allowed, 1 error, 2 denied.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, _, err := resolvePolicy(opts, file)
			if err != nil {
				return err
			}
			decision, err := policy.CheckTarget(args[0])
			if err != nil {
				return err
			}
			printer := opts.printer()
			if opts.json {
				if err := printer.JSONValue(decision); err != nil {
					return err
				}
			} else {
				state := "ALLOWED"
				if !decision.Allowed {
					state = "DENIED"
				}
				fmt.Fprintf(printer.Out, "%s  %s\n", state, decision.Target)
				fmt.Fprintf(printer.Out, "kind:   %s\n", decision.Kind)
				fmt.Fprintf(printer.Out, "reason: %s\n", decision.Reason)
				if decision.Rule != "" {
					fmt.Fprintf(printer.Out, "rule:   %s\n", decision.Rule)
				}
				if decision.Port != 0 {
					fmt.Fprintf(printer.Out, "port:   %d\n", decision.Port)
				}
			}
			if !decision.Allowed {
				return silentExit(2)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "scope file path")
	return cmd
}
