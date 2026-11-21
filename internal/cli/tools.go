package cli

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/lunalully/cyberm4ncer/internal/tools"
	"github.com/spf13/cobra"
)

type toolView struct {
	Manifest  tools.Manifest   `json:"manifest"`
	Detection *tools.Detection `json:"detection,omitempty"`
}

func newToolsCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Inspect supported external tools",
		Long: `List and probe external tools described by the embedded manifests.

Detection executes each tool's documented version command with a timeout.
Installation, updates and removal are introduced in Phase 3.`,
	}
	cmd.AddCommand(
		newToolsListCmd(opts),
		newToolsInfoCmd(opts),
		newToolsDetectCmd(opts),
	)
	return cmd
}

func newToolsListCmd(opts *rootOptions) *cobra.Command {
	var category string
	var detect bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List supported tools",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			registry, err := tools.LoadEmbedded()
			if err != nil {
				return err
			}
			manifests := registry.List()
			if category != "" {
				filtered := manifests[:0]
				for _, manifest := range manifests {
					if manifest.Category == category {
						filtered = append(filtered, manifest)
					}
				}
				manifests = filtered
			}
			if len(manifests) == 0 {
				return fmt.Errorf("no tools found for category %q", category)
			}

			printer := opts.printer()
			views := make([]toolView, 0, len(manifests))
			if detect {
				c, err := opts.openCore(cmd.Context())
				if err != nil {
					return err
				}
				defer c.Close()
				detections := c.Detector.DetectAll(cmd.Context(), manifests)
				for i, manifest := range manifests {
					detection := detections[i]
					views = append(views, toolView{Manifest: manifest, Detection: &detection})
				}
			} else {
				for _, manifest := range manifests {
					detection := tools.Detection{Name: manifest.Name, Status: tools.DetectionMissing}
					if path, err := exec.LookPath(manifest.Binary); err == nil {
						detection.Found = true
						detection.Path = path
						detection.Status = tools.DetectionInstalled
						detection.Compatible = true
					}
					views = append(views, toolView{Manifest: manifest, Detection: &detection})
				}
			}
			if opts.json {
				return printer.JSONValue(views)
			}
			rows := make([][]string, 0, len(views))
			for _, view := range views {
				status := view.Detection.Status
				version := view.Detection.Version
				if version == "" {
					version = "-"
				}
				rows = append(rows, []string{
					view.Manifest.Name,
					view.Manifest.Category,
					status,
					version,
					view.Manifest.Risk,
				})
			}
			printer.Table([]string{"NAME", "CATEGORY", "STATUS", "VERSION", "RISK"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&category, "category", "", "filter by category")
	cmd.Flags().BoolVar(&detect, "detect", false, "run version detection")
	return cmd
}

func newToolsInfoCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "info <tool>",
		Short: "Show a tool manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			registry, err := tools.LoadEmbedded()
			if err != nil {
				return err
			}
			manifest, ok := registry.Get(args[0])
			if !ok {
				return fmt.Errorf("unknown tool %q (run: cyberm4ncer tools list)", args[0])
			}
			printer := opts.printer()
			if opts.json {
				return printer.JSONValue(manifest)
			}
			fmt.Fprintf(printer.Out, "%s — %s\n", manifest.Name, manifest.Description)
			fmt.Fprintf(printer.Out, "category:       %s\n", manifest.Category)
			fmt.Fprintf(printer.Out, "homepage:       %s\n", manifest.Homepage)
			fmt.Fprintf(printer.Out, "documentation:  %s\n", manifest.Documentation)
			fmt.Fprintf(printer.Out, "license:        %s\n", manifest.License)
			fmt.Fprintf(printer.Out, "binary:         %s\n", manifest.Binary)
			fmt.Fprintf(printer.Out, "min version:    %s\n", emptyDash(manifest.MinVersion))
			fmt.Fprintf(printer.Out, "tested version: %s\n", emptyDash(manifest.TestedVersion))
			fmt.Fprintf(printer.Out, "risk:           %s (intrusive: %t)\n", manifest.Risk, manifest.Intrusive)
			fmt.Fprintf(printer.Out, "architectures:  %s\n", strings.Join(manifest.Architectures, ", "))
			fmt.Fprintf(printer.Out, "capabilities:   %s\n", strings.Join(manifest.Capabilities, ", "))
			fmt.Fprintf(printer.Out, "outputs:        %s\n", strings.Join(manifest.Outputs, ", "))
			fmt.Fprintf(printer.Out, "version check:  %s %s\n", manifest.Binary, strings.Join(manifest.VersionCheck.Args, " "))
			fmt.Fprintf(printer.Out, "install methods:\n")
			for _, method := range manifest.Install {
				detail := method.Package
				if detail == "" {
					detail = method.Repository
				}
				fmt.Fprintf(printer.Out, "  - %-14s %s\n", method.Method, emptyDash(detail))
			}
			if manifest.Notes != "" {
				fmt.Fprintf(printer.Out, "notes:          %s\n", manifest.Notes)
			}
			return nil
		},
	}
}

func newToolsDetectCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "detect [tool...]",
		Short: "Detect installed tools and verify versions",
		Long: `Detect resolves each binary, runs its version command with a timeout and
compares the parsed version with the manifest minimum.

Exit code is 1 when any requested tool is missing, incompatible or could not
be verified.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opts.openCore(cmd.Context())
			if err != nil {
				return err
			}
			defer c.Close()

			var manifests []tools.Manifest
			if len(args) == 0 {
				manifests = c.Tools.List()
			} else {
				for _, name := range args {
					manifest, ok := c.Tools.Get(name)
					if !ok {
						return fmt.Errorf("unknown tool %q", name)
					}
					manifests = append(manifests, manifest)
				}
			}
			detections := c.Detector.DetectAll(cmd.Context(), manifests)
			printer := opts.printer()
			if opts.json {
				return printer.JSONValue(detections)
			}
			rows := make([][]string, 0, len(detections))
			failed := 0
			for _, detection := range detections {
				version := detection.Version
				if version == "" {
					version = "-"
				}
				rows = append(rows, []string{
					detection.Name,
					detection.Status,
					version,
					emptyDash(detection.Path),
					detection.Error,
				})
				if detection.Status != tools.DetectionInstalled {
					failed++
				}
			}
			printer.Table([]string{"NAME", "STATUS", "VERSION", "PATH", "DETAIL"}, rows)
			if failed > 0 {
				printer.Warnf("%d of %d tools are not ready", failed, len(detections))
				return silentExit(1)
			}
			printer.Successf("all %d tools are ready", len(detections))
			return nil
		},
	}
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
