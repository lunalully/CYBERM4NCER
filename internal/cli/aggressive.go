package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lunalully/cyberm4ncer/internal/aggressive"
	"github.com/lunalully/cyberm4ncer/internal/core"
	"github.com/lunalully/cyberm4ncer/internal/database"
	"github.com/lunalully/cyberm4ncer/internal/id"
	"github.com/lunalully/cyberm4ncer/internal/ui"
	"github.com/spf13/cobra"
)

type aggressiveOptions struct {
	scopeFile string
	mode      string
	level     int
	repeat    int
	timeout   time.Duration
	file      string
	execute   bool
	maxSteps  int
	noCreds   bool
	noIntru   bool
	wordlist  string
	userList  string
	passList  string
}

func newAggressiveCmd(opts *rootOptions) *cobra.Command {
	options := &aggressiveOptions{}
	cmd := &cobra.Command{
		Use:   "aggressive [target]",
		Short: "Plan or run an exhaustive, repeated scan against in-scope targets",
		Long: `Aggressive expands every reviewed tool invocation for a target, repeats each
one to the configured quota, chains discovered open ports into the next round
and records every execution.

The target must be inside the authorized scope. Output streams are written to
artifacts and executions are stored in the local database.

Nothing runs until --execute is given; without it the exact plan is printed.

Targets can be given as arguments or one per line with --file, including
comments (#). Use --max-steps to cap a large campaign (0 is unlimited).`,
		Example: `  cyberm4ncer aggressive 10.0.0.5 --scope engagement.yaml
  cyberm4ncer aggressive https://app.example.com --scope engagement.yaml --mode all --level 5 --execute
  cyberm4ncer aggressive 10.0.0.0/24 --scope engagement.yaml --mode enum --repeat 3 --execute
  cyberm4ncer aggressive --file targets.txt --scope engagement.yaml --execute`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAggressive(cmd.Context(), opts, options, args)
		},
	}
	flags := cmd.Flags()
	flags.StringVarP(&options.scopeFile, "scope", "s", "", "scope file (default: configured or discovered)")
	flags.StringVar(&options.mode, "mode", "all", "tool selection: all, recon, enum, vuln")
	flags.IntVar(&options.level, "level", 5, "intensity from 1 (gentle) to 5 (maximum speed args)")
	flags.IntVar(&options.repeat, "repeat", 0, "cap for repetitions (0 keeps the reviewed values)")
	flags.StringVarP(&options.file, "file", "f", "", "file with one target per line (# comments allowed)")
	flags.DurationVar(&options.timeout, "timeout", 0, "per-execution timeout (0 uses the configuration)")
	flags.BoolVar(&options.execute, "execute", false, "actually run the plan (default is plan only)")
	flags.IntVar(&options.maxSteps, "max-steps", 0, "abort after N executions (0 is unlimited)")
	flags.BoolVar(&options.noCreds, "no-credentials", false, "skip hydra/medusa credential invocations")
	flags.BoolVar(&options.noIntru, "no-intrusive", false, "skip tools flagged as intrusive")
	flags.StringVar(&options.wordlist, "wordlist", "", "web wordlist (default from configuration)")
	flags.StringVar(&options.userList, "userlist", "", "usernames for hydra/medusa")
	flags.StringVar(&options.passList, "passlist", "", "passwords for hydra/medusa")
	return cmd
}

func runAggressive(ctx context.Context, root *rootOptions, options *aggressiveOptions, args []string) error {
	if options.level < 1 || options.level > 5 {
		return fmt.Errorf("level must be between 1 and 5")
	}
	targets, err := aggressiveTargets(args, options.file)
	if err != nil {
		return err
	}
	policy, scopePath, err := resolvePolicy(root, options.scopeFile)
	if err != nil {
		return err
	}
	app, err := root.openCore(ctx)
	if err != nil {
		return err
	}
	defer app.Close()

	mode, err := aggressiveMode(options, app.Config.Execution.Wordlist)
	if err != nil {
		return err
	}
	service, err := app.NewAggressive(mode)
	if err != nil {
		return err
	}
	plans := make([]*aggressive.Plan, 0, len(targets))
	for _, target := range targets {
		plan, planErr := service.Plan(target, policy)
		if planErr != nil {
			return planErr
		}
		plans = append(plans, plan)
	}

	printer := root.printer()
	if !options.execute {
		for index, plan := range plans {
			if index > 0 {
				printer.Infof("")
			}
			if err := printAggressivePlan(printer, plan, scopePath, options); err != nil {
				return err
			}
		}
		return nil
	}
	for _, plan := range plans {
		for _, requirement := range wordlistRequirements(plan) {
			if _, err := os.Stat(requirement); err != nil {
				printer.Warnf("wordlist not found: %s (tools that need it will fail)", requirement)
			}
		}
	}

	stepTimeout := options.timeout
	if stepTimeout <= 0 {
		stepTimeout = app.Config.Execution.DefaultTimeout.Std()
	}
	run := &aggressiveRun{
		App:     app,
		Service: service,
		Mode:    mode,
		Options: options,
		Scope:   scopePath,
		Timeout: stepTimeout,
		Printer: printer,
	}
	campaign := campaignSummary{Targets: len(plans)}
	started := time.Now()
	for _, plan := range plans {
		if err := ctx.Err(); err != nil {
			campaign.Error = err.Error()
			break
		}
		summary, runErr := run.execute(ctx, plan)
		campaign.Summaries = append(campaign.Summaries, summary)
		campaign.Steps += summary.Steps
		campaign.Succeeded += summary.Succeeded
		campaign.Failed += summary.Failed
		campaign.Skipped += summary.Skipped
		campaign.Discovered += summary.Discovered
		campaign.Hosts += summary.Hosts
		campaign.Ports += summary.Ports
		campaign.Matches = append(campaign.Matches, summary.Matches...)
		campaign.Truncated = campaign.Truncated || summary.Truncated
		if runErr != nil {
			if campaign.Error == "" {
				campaign.Error = runErr.Error()
			}
			if errors.Is(runErr, context.Canceled) || campaign.Truncated {
				break
			}
		}
	}
	campaign.Elapsed = time.Since(started).Round(time.Millisecond).String()

	if printer.JSON {
		if err := printer.JSONValue(campaign); err != nil {
			return err
		}
	}
	fmt.Fprintf(root.streams.Out, "\ntargets=%d steps=%d succeeded=%d failed=%d skipped=%d discovered=%d hosts=%d ports=%d elapsed=%s\n",
		campaign.Targets, campaign.Steps, campaign.Succeeded, campaign.Failed, campaign.Skipped,
		campaign.Discovered, campaign.Hosts, campaign.Ports, campaign.Elapsed)
	if campaign.Truncated {
		fmt.Fprintln(root.streams.Out, "max-steps reached; the campaign stopped early")
	}
	if len(campaign.Matches) > 0 {
		fmt.Fprintln(root.streams.Out, "\ncredential/success matches:")
		for _, match := range campaign.Matches {
			fmt.Fprintf(root.streams.Out, "  %s\n", match)
		}
	}
	if campaign.Error != "" {
		fmt.Fprintf(root.streams.Err, "error: %s\n", campaign.Error)
	}
	if campaign.Error != "" && !campaign.Truncated {
		return errCampaignFailed
	}
	return nil
}

// errCampaignFailed reports that an execution failed; the detail is already
// on stderr and in the database.
var errCampaignFailed = errors.New("aggressive campaign finished with errors")

// campaignSummary aggregates every target of one command invocation.
type campaignSummary struct {
	Targets    int                  `json:"targets"`
	Steps      int                  `json:"steps"`
	Succeeded  int                  `json:"succeeded"`
	Failed     int                  `json:"failed"`
	Skipped    int                  `json:"skipped"`
	Discovered int                  `json:"discovered"`
	Hosts      int                  `json:"hosts"`
	Ports      int                  `json:"ports"`
	Matches    []string             `json:"matches,omitempty"`
	Truncated  bool                 `json:"truncated,omitempty"`
	Elapsed    string               `json:"elapsed"`
	Error      string               `json:"error,omitempty"`
	Summaries  []aggressive.Summary `json:"targets_detail"`
}

// aggressiveRun executes one plan at a time with its own operation record.
type aggressiveRun struct {
	App     *core.Core
	Service *core.AggressiveService
	Mode    aggressive.Mode
	Options *aggressiveOptions
	Scope   string
	Timeout time.Duration
	Printer *ui.Printer
}

func (r *aggressiveRun) execute(ctx context.Context, plan *aggressive.Plan) (aggressive.Summary, error) {
	projectID, operationID, err := r.recordPlan(ctx, plan)
	if err != nil {
		return aggressive.Summary{}, err
	}
	fmt.Fprintf(r.Printer.Out, "executing %d planned command(s) against %s (level %d, scope %s)\n",
		countSteps(plan), plan.Target, r.Mode.Level, r.Scope)
	started := time.Now()
	summary, runErr := r.Service.Run(ctx, plan, aggressive.Operation{
		ID:          operationID,
		DataDir:     r.App.Paths.DataDir,
		StepTimeout: r.Timeout,
		MaxSteps:    r.Options.maxSteps,
		Progress:    r.Printer.Out,
	})
	status := "completed"
	if runErr != nil {
		status = "failed"
	}
	finishErr := r.App.DB.FinishOperation(context.WithoutCancel(ctx), operationID, status, time.Now().UTC(), errorText(runErr))
	_ = r.App.DB.AppendAudit(context.WithoutCancel(ctx), "aggressive", "aggressive.run", plan.Target, map[string]any{
		"operation_id": operationID,
		"project_id":   projectID,
		"mode":         r.Mode.Name,
		"level":        r.Mode.Level,
		"steps":        summary.Steps,
		"succeeded":    summary.Succeeded,
		"failed":       summary.Failed,
		"skipped":      summary.Skipped,
		"hosts":        summary.Hosts,
		"ports":        summary.Ports,
		"matches":      len(summary.Matches),
		"truncated":    summary.Truncated,
		"duration":     time.Since(started).Round(time.Millisecond).String(),
	})
	if finishErr != nil {
		return summary, fmt.Errorf("record operation result: %w", finishErr)
	}
	return summary, runErr
}

// wordlistRequirements lists distinct wordlists the plan will reference.
func wordlistRequirements(plan *aggressive.Plan) []string {
	seen := map[string]bool{}
	var lists []string
	for _, step := range plan.Steps {
		for _, arg := range step.Args {
			if !strings.Contains(arg, "/") || !(strings.HasSuffix(arg, ".txt") || strings.Contains(arg, "wordlist")) {
				continue
			}
			if seen[arg] {
				continue
			}
			seen[arg] = true
			lists = append(lists, arg)
		}
	}
	return lists
}

func aggressiveMode(options *aggressiveOptions, configuredWordlist string) (aggressive.Mode, error) {
	mode := aggressive.DefaultMode()
	switch strings.ToLower(options.mode) {
	case "all", "":
		mode.Name = "all"
	case "recon", "enum", "vuln":
		mode.Name = strings.ToLower(options.mode)
	default:
		return mode, fmt.Errorf("invalid mode %q (all, recon, enum, vuln)", options.mode)
	}
	mode.Level = options.level
	if options.repeat > 0 {
		mode.RepeatQuota = options.repeat
	}
	if options.noCreds {
		mode.IncludeCredential = false
	}
	if options.noIntru {
		mode.IncludeIntrusive = false
	}
	mode.Wordlist = options.wordlist
	if mode.Wordlist == "" {
		mode.Wordlist = configuredWordlist
	}
	mode.UserList = options.userList
	mode.PassList = options.passList
	return mode, nil
}

func printAggressivePlan(printer *ui.Printer, plan *aggressive.Plan, scopePath string, options *aggressiveOptions) error {
	if printer.JSON {
		return printer.JSONValue(map[string]any{
			"target":      plan.Target,
			"scope":       scopePath,
			"mode":        plan.Mode.Name,
			"level":       plan.Mode.Level,
			"repeat":      plan.Mode.RepeatQuota,
			"tools":       plan.Tools,
			"planned":     countSteps(plan),
			"executions":  plan.Repeats,
			"steps":       plan.Steps,
			"skips":       plan.Skips,
			"needs_ports": hasExpansion(plan),
		})
	}
	printer.Infof("target: %s", plan.Target)
	printer.Infof("authorization scope: %s", scopePath)
	printer.Infof("mode: %s | level: %d | repeat quota: %d", plan.Mode.Name, plan.Mode.Level, plan.Mode.RepeatQuota)
	printer.Infof("tools (%d): %s", len(plan.Tools), strings.Join(plan.Tools, ", "))
	printer.Infof("planned invocations: %d (rounds: %d)", countSteps(plan), plan.Repeats)
	printer.Infof("")
	rows := make([][]string, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		expand := ""
		if step.Expand {
			expand = "per open port"
		}
		rows = append(rows, []string{step.Tool, step.Invocation, fmt.Sprintf("%d", step.Round), expand})
	}
	if len(rows) > 0 {
		printer.Table([]string{"TOOL", "INVOCATION", "ROUND", "EXPANSION"}, rows)
	}
	if len(plan.Skips) > 0 {
		printer.Infof("")
		printer.Infof("skipped:")
		skipRows := make([][]string, 0, len(plan.Skips))
		for _, skip := range plan.Skips {
			skipRows = append(skipRows, []string{skip.Tool, skip.Invocation, skip.Reason})
		}
		printer.Table([]string{"TOOL", "INVOCATION", "REASON"}, skipRows)
	}
	printer.Infof("")
	printer.Infof("nothing was executed; add --execute to run the plan")
	return nil
}

func countSteps(plan *aggressive.Plan) int {
	total := 0
	for _, step := range plan.Steps {
		if step.Expand {
			continue
		}
		total++
	}
	return total
}

func hasExpansion(plan *aggressive.Plan) bool {
	for _, step := range plan.Steps {
		if step.Expand {
			return true
		}
	}
	return false
}

// recordPlan creates the project if needed, opens the operation and writes the
// plan to the audit chain before any command runs.
func (r *aggressiveRun) recordPlan(ctx context.Context, plan *aggressive.Plan) (string, string, error) {
	project, err := r.App.DB.GetProjectByName(ctx, plan.Policy.Project)
	if err != nil {
		project = database.Project{
			ID:          id.New("proj"),
			Name:        plan.Policy.Project,
			Description: "authorization: " + plan.Policy.Authorization,
			CreatedAt:   time.Now().UTC(),
		}
		if createErr := r.App.DB.CreateProject(ctx, project); createErr != nil {
			return "", "", fmt.Errorf("create project: %w", createErr)
		}
	}
	operationID := id.New("op")
	operation := database.Operation{
		ID:        operationID,
		ProjectID: project.ID,
		Kind:      "aggressive",
		Target:    plan.Target,
		Profile:   fmt.Sprintf("%s/l%d", r.Mode.Name, r.Mode.Level),
		Status:    "running",
		StartedAt: time.Now().UTC(),
	}
	if err := r.App.DB.CreateOperation(ctx, operation); err != nil {
		return project.ID, "", err
	}
	if err := r.App.DB.AppendAudit(ctx, "aggressive", "aggressive.plan", plan.Target, map[string]any{
		"operation_id": operationID,
		"mode":         r.Mode.Name,
		"level":        r.Mode.Level,
		"repeat":       r.Mode.RepeatQuota,
		"invocations":  countSteps(plan),
		"tools":        plan.Tools,
		"scope":        plan.Policy.Project,
	}); err != nil {
		return project.ID, operationID, fmt.Errorf("audit plan: %w", err)
	}
	return project.ID, operationID, nil
}

// aggressiveTargets collects positional targets and --file entries.
func aggressiveTargets(args []string, file string) ([]string, error) {
	seen := map[string]bool{}
	var targets []string
	add := func(target string) {
		target = strings.TrimSpace(target)
		if target == "" || seen[target] {
			return
		}
		seen[target] = true
		targets = append(targets, target)
	}
	for _, arg := range args {
		add(arg)
	}
	if file != "" {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read target file: %w", err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			if index := strings.Index(line, "#"); index >= 0 {
				line = line[:index]
			}
			add(line)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("a target argument or --file is required")
	}
	return targets, nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
