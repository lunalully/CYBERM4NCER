package cli

import (
	"fmt"
	"os"

	"github.com/lunalully/cyberm4ncer/internal/config"
	"github.com/lunalully/cyberm4ncer/internal/core"
	"github.com/lunalully/cyberm4ncer/internal/scope"
	"github.com/lunalully/cyberm4ncer/internal/tools"
	"github.com/lunalully/cyberm4ncer/internal/version"
	"github.com/spf13/cobra"
)

const (
	statusOK   = "OK"
	statusWarn = "WARN"
	statusFail = "FAIL"
)

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func newDoctorCmd(opts *rootOptions) *cobra.Command {
	var skipTools bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the local installation and toolchain",
		Long: `Doctor verifies configuration, data directories, database schema,
audit-chain integrity, scope validity and external tool availability.

Exit code is 1 when a critical check fails. Missing optional tools are
reported as warnings.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			checks := make([]doctorCheck, 0, 10)
			add := func(name, status, detail string) {
				checks = append(checks, doctorCheck{Name: name, Status: status, Detail: detail})
			}

			info := version.Current()
			add("platform", statusOK, fmt.Sprintf("%s/%s · toolchain %s · CYBERM4NCER %s",
				info.OS, info.Arch, info.GoVersion, info.Version))

			c, err := opts.openCore(ctx)
			if err != nil {
				add("core", statusFail, err.Error())
				return finishDoctor(opts, checks)
			}
			defer c.Close()

			if c.Meta.ConfigFound {
				add("config", statusOK, c.Meta.ConfigPath)
			} else {
				add("config", statusWarn, "not found; using defaults ("+c.Meta.ConfigPath+"); run: cyberm4ncer config init")
			}

			if err := core.Writable(c.Paths.DataDir); err != nil {
				add("data", statusFail, err.Error())
			} else {
				add("data", statusOK, c.Paths.DataDir)
			}

			schema, err := c.DB.SchemaVersion(ctx)
			if err != nil {
				add("database", statusFail, err.Error())
			} else {
				stats, statsErr := c.DB.Stats(ctx)
				if statsErr != nil {
					add("database", statusFail, statsErr.Error())
				} else {
					add("database", statusOK, fmt.Sprintf("%s · schema v%d · %d operations · %d executions",
						c.Paths.Database, schema, stats.Operations, stats.Executions))
				}
			}

			verification, err := c.DB.VerifyAudit(ctx)
			switch {
			case err != nil:
				add("audit", statusFail, err.Error())
			case !verification.Valid:
				add("audit", statusFail, fmt.Sprintf("hash chain broken at entry %d", verification.BrokenAt))
			default:
				add("audit", statusOK, fmt.Sprintf("%d entries, chain valid", verification.Entries))
			}

			scopeFile := config.DiscoverScopeFile("", c.Config, c.Paths)
			if scopeFile == "" {
				add("scope", statusWarn, "no scope file configured; external operations are blocked until one is provided")
			} else if policy, loadErr := scope.Load(scopeFile); loadErr != nil {
				add("scope", statusFail, loadErr.Error())
			} else {
				summary := policy.Summary()
				add("scope", statusOK, fmt.Sprintf("%s · project=%s · includes=%d · excludes=%d",
					scopeFile, summary.Project, summary.Includes, summary.Excludes))
			}

			if _, err := os.Stat(c.Config.Logging.File); err != nil {
				add("logging", statusFail, err.Error())
			} else {
				add("logging", statusOK, c.Config.Logging.File)
			}

			if !skipTools {
				detections := c.Detector.DetectAll(ctx, c.Tools.List())
				installed := 0
				var missing, incompatible, unverified []string
				for _, detection := range detections {
					switch detection.Status {
					case tools.DetectionInstalled:
						installed++
					case tools.DetectionMissing:
						missing = append(missing, detection.Name)
					case tools.DetectionIncompatible:
						incompatible = append(incompatible, detection.Name)
					default:
						unverified = append(unverified, detection.Name)
					}
				}
				status := statusOK
				detail := fmt.Sprintf("%d/%d ready", installed, len(detections))
				if len(missing) > 0 || len(incompatible) > 0 || len(unverified) > 0 {
					status = statusWarn
					detail = fmt.Sprintf("%d/%d ready", installed, len(detections))
					if len(missing) > 0 {
						detail += "; missing: " + joinNames(missing)
					}
					if len(incompatible) > 0 {
						detail += "; incompatible: " + joinNames(incompatible)
					}
					if len(unverified) > 0 {
						detail += "; unverified: " + joinNames(unverified)
					}
				}
				add("tools", status, detail)
			}

			return finishDoctor(opts, checks)
		},
	}
	cmd.Flags().BoolVar(&skipTools, "skip-tools", false, "skip external tool detection")
	return cmd
}

func finishDoctor(opts *rootOptions, checks []doctorCheck) error {
	printer := opts.printer()
	failures, warnings := 0, 0
	for _, check := range checks {
		switch check.Status {
		case statusFail:
			failures++
		case statusWarn:
			warnings++
		}
	}
	if opts.json {
		payload := struct {
			OK     bool          `json:"ok"`
			Checks []doctorCheck `json:"checks"`
		}{OK: failures == 0, Checks: checks}
		if err := printer.JSONValue(payload); err != nil {
			return err
		}
	} else {
		rows := make([][]string, 0, len(checks))
		for _, check := range checks {
			rows = append(rows, []string{check.Name, check.Status, check.Detail})
		}
		printer.Table([]string{"CHECK", "STATUS", "DETAIL"}, rows)
		if failures == 0 && warnings == 0 {
			printer.Successf("all checks passed")
		} else {
			fmt.Fprintf(printer.Out, "%d failure(s), %d warning(s)\n", failures, warnings)
		}
	}
	if failures > 0 {
		return silentExit(1)
	}
	return nil
}

func joinNames(names []string) string {
	if len(names) > 6 {
		return fmt.Sprintf("%d tools", len(names))
	}
	result := ""
	for i, name := range names {
		if i > 0 {
			result += ", "
		}
		result += name
	}
	return result
}
