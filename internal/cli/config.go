package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lunalully/cyberm4ncer/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newConfigCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and initialize configuration",
	}
	cmd.AddCommand(
		newConfigShowCmd(opts),
		newConfigPathCmd(opts),
		newConfigInitCmd(opts),
	)
	return cmd
}

func loadConfig(opts *rootOptions) (config.Config, config.Meta, error) {
	return config.Load(config.LoadOptions{
		Path:     opts.configPath,
		DataDir:  opts.dataDir,
		LogLevel: opts.logLevel,
	})
}

func newConfigShowCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the resolved configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := loadConfig(opts)
			if err != nil {
				return err
			}
			printer := opts.printer()
			if opts.json {
				return printer.JSONValue(cfg)
			}
			encoded, err := yaml.Marshal(cfg)
			if err != nil {
				return fmt.Errorf("encode configuration: %w", err)
			}
			_, err = fmt.Fprint(printer.Out, string(encoded))
			return err
		},
	}
}

func newConfigPathCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Print resolved configuration and data paths",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, meta, err := loadConfig(opts)
			if err != nil {
				return err
			}
			printer := opts.printer()
			payload := struct {
				Config    string `json:"config"`
				Found     bool   `json:"found"`
				Data      string `json:"data_dir"`
				Database  string `json:"database"`
				Artifacts string `json:"artifacts"`
				Logs      string `json:"logs"`
				Tools     string `json:"tools"`
				LogFile   string `json:"log_file"`
			}{
				Config:    meta.ConfigPath,
				Found:     meta.ConfigFound,
				Data:      meta.Paths.DataDir,
				Database:  meta.Paths.Database,
				Artifacts: meta.Paths.Artifacts,
				Logs:      meta.Paths.Logs,
				Tools:     meta.Paths.Tools,
				LogFile:   cfg.Logging.File,
			}
			if opts.json {
				return printer.JSONValue(payload)
			}
			fmt.Fprintf(printer.Out, "config:    %s (found: %t)\n", payload.Config, payload.Found)
			fmt.Fprintf(printer.Out, "data:      %s\n", payload.Data)
			fmt.Fprintf(printer.Out, "database:  %s\n", payload.Database)
			fmt.Fprintf(printer.Out, "artifacts: %s\n", payload.Artifacts)
			fmt.Fprintf(printer.Out, "logs:      %s\n", payload.Logs)
			fmt.Fprintf(printer.Out, "log file:  %s\n", payload.LogFile)
			fmt.Fprintf(printer.Out, "tools:     %s\n", payload.Tools)
			return nil
		},
	}
}

func newConfigInitCmd(opts *rootOptions) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a default configuration file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := opts.configPath
			if path == "" {
				path = os.Getenv("CYBERM4NCER_CONFIG")
			}
			if path == "" {
				path = config.DefaultConfigPath()
			}
			expanded, err := config.ExpandPath(path)
			if err != nil {
				return err
			}
			if info, err := os.Stat(expanded); err == nil && !info.IsDir() && !force {
				return fmt.Errorf("config file %s already exists (use --force to overwrite)", expanded)
			}
			if err := os.MkdirAll(filepath.Dir(expanded), 0o700); err != nil {
				return fmt.Errorf("create config directory: %w", err)
			}
			encoded, err := yaml.Marshal(config.Defaults())
			if err != nil {
				return fmt.Errorf("encode default configuration: %w", err)
			}
			content := strings.Join([]string{
				"# CYBERM4NCER configuration.",
				"# Authorization must be declared in the scope file, not here.",
				"# Durations use Go syntax, for example 10m or 30s.",
				"",
				string(encoded),
			}, "\n")
			if err := os.WriteFile(expanded, []byte(content), 0o600); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			if err := os.Chmod(expanded, 0o600); err != nil {
				return fmt.Errorf("set config permissions: %w", err)
			}
			printer := opts.printer()
			printer.Successf("created %s", expanded)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	return cmd
}
