package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lunalully/cyberm4ncer/internal/aggressive"
	"github.com/lunalully/cyberm4ncer/internal/core"
	"github.com/lunalully/cyberm4ncer/internal/hub"
	"github.com/lunalully/cyberm4ncer/internal/tools"
	"github.com/lunalully/cyberm4ncer/internal/ui"
)

// hubService adapts the core to the Operations Hub. Every call goes through
// the same planner, executor, scope resolution and database records as the
// aggressive command, so the hub never has its own execution path.
type hubService struct {
	ctx        context.Context
	opts       *rootOptions
	printer    *ui.Printer
	core       *core.Core
	service    *core.AggressiveService
	scopePath  string
	detections []tools.Detection
}

// newHubService opens the core once for the whole hub session.
func newHubService(ctx context.Context, opts *rootOptions) (*hubService, error) {
	app, err := opts.openCore(ctx)
	if err != nil {
		return nil, err
	}
	return &hubService{ctx: ctx, opts: opts, printer: opts.printer(), core: app}, nil
}

// ensureService builds the aggressive service for one mode.
func (h *hubService) ensureService(mode string, level, repeat int, wordlist, userlist, passlist string) error {
	options := &aggressiveOptions{
		scopeFile: h.scopePath,
		mode:      mode,
		level:     level,
		repeat:    repeat,
		wordlist:  wordlist,
		userList:  userlist,
		passList:  passlist,
	}
	compiled, err := aggressiveMode(options, h.core.Config.Execution.Wordlist)
	if err != nil {
		return err
	}
	h.service, err = h.core.NewAggressive(compiled)
	return err
}

// detectAll runs the real detectors once per hub session and caches them.
func (h *hubService) detectAll() ([]tools.Detection, error) {
	if h.detections != nil {
		return h.detections, nil
	}
	detections := h.core.Detector.DetectAll(h.ctx, h.core.Tools.List())
	h.detections = detections
	return detections, nil
}

// ready counts installed and version compatible tools.
func ready(detections []tools.Detection) int {
	count := 0
	for _, detection := range detections {
		if detection.Found && detection.Compatible {
			count++
		}
	}
	return count
}

// Detect returns the one-line tool summary.
func (h *hubService) Detect() (string, error) {
	detections, err := h.detectAll()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d/%d tools installed and ready", ready(detections), len(detections)), nil
}

// ToolSummary reports ready/total for the status line.
func (h *hubService) ToolSummary() (string, error) {
	detections, err := h.detectAll()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d/%d ready", ready(detections), len(detections)), nil
}

// Tools lists every manifest with its real detection state.
func (h *hubService) Tools() ([]string, error) {
	detections, err := h.detectAll()
	if err != nil {
		return nil, err
	}
	rows := make([]string, 0, len(detections))
	for _, detection := range detections {
		status := detection.Status
		if detection.Status == "" {
			status = "missing"
		}
		version := detection.Version
		if version == "" {
			version = "-"
		}
		path := detection.Path
		if path == "" {
			path = "-"
		}
		rows = append(rows, fmt.Sprintf("%s|%s|%s|%s", detection.Name, status, version, path))
	}
	return rows, nil
}

// ResolveScope returns the scope file the session uses.
func (h *hubService) ResolveScope(explicit string) (string, error) {
	return explicit, nil
}

// Plan compiles the engine plan for every target.
func (h *hubService) Plan(targets, scopeFile, mode string, level, repeat int, wordlist, userlist, passlist string) (*hub.PlanView, error) {
	h.scopePath = scopeFile
	policy, path, err := resolveOptionalPolicy(h.opts, scopeFile)
	if err != nil {
		return nil, err
	}
	h.scopePath = path
	if err := h.ensureService(mode, level, repeat, wordlist, userlist, passlist); err != nil {
		return nil, err
	}
	view := &hub.PlanView{Target: targets, Mode: mode, Level: level, Repeat: repeat}
	var plans []*aggressive.Plan
	seenTools := map[string]bool{}
	for _, target := range hub.Targets(targets) {
		plan, planErr := h.service.Plan(target, policy)
		if planErr != nil {
			return nil, planErr
		}
		plans = append(plans, plan)
		view.Steps += countSteps(plan)
		view.Skips += len(plan.Skips)
		for _, tool := range plan.Tools {
			if !seenTools[tool] {
				seenTools[tool] = true
				view.Tools = append(view.Tools, tool)
			}
		}
	}
	if len(plans) == 0 {
		return nil, fmt.Errorf("no target given")
	}
	view.Engine = plans
	return view, nil
}

// ScopePath returns the resolved scope file of a plan.
func (h *hubService) ScopePath(view *hub.PlanView) string { return h.scopePath }

// Execute runs every plan with the same records as the CLI.
func (h *hubService) Execute(options hub.Context, view *hub.PlanView, out io.Writer) (hub.SummaryView, error) {
	plans, ok := view.Engine.([]*aggressive.Plan)
	if !ok {
		return hub.SummaryView{}, fmt.Errorf("plan is not a compiled aggressive plan")
	}
	timeout := h.core.Config.Execution.DefaultTimeout.Std()
	if options.Timeout != "" && options.Timeout != "0" {
		parsed, err := time.ParseDuration(options.Timeout)
		if err != nil {
			return hub.SummaryView{}, fmt.Errorf("invalid timeout %q: %w", options.Timeout, err)
		}
		timeout = parsed
	}
	run := &aggressiveRun{
		App:     h.core,
		Service: h.service,
		Mode:    aggressive.Mode{Name: view.Mode, Level: view.Level},
		Options: &aggressiveOptions{},
		Scope:   h.scopePath,
		Timeout: timeout,
		Printer: h.printer,
	}
	campaign := campaignSummary{Targets: len(plans)}
	started := time.Now()
	for _, plan := range plans {
		if err := h.ctx.Err(); err != nil {
			campaign.Error = err.Error()
			break
		}
		fmt.Fprintf(out, "\nexecuting %d planned command(s) against %s\n", countSteps(plan), plan.Target)
		summary, runErr := run.executeTo(h.ctx, plan, out)
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
			break
		}
	}
	campaign.Elapsed = time.Since(started).Round(time.Millisecond).String()
	result := hub.SummaryView{
		Steps: campaign.Steps, Succeeded: campaign.Succeeded, Failed: campaign.Failed,
		Skipped: campaign.Skipped, Discovered: campaign.Discovered, Hosts: campaign.Hosts,
		Ports: campaign.Ports, Matches: campaign.Matches, Elapsed: campaign.Elapsed,
		Truncated:   campaign.Truncated,
		ResultsPath: h.core.Paths.DataDir + "/artifacts",
	}
	result.Notes = h.executionNotes(plans)
	if campaign.Error != "" {
		return result, errCampaignFailed
	}
	return result, nil
}

// executionNotes reports what the hub could not verify before a run, so the
// operator never reads a partial run as a complete assessment.
func (h *hubService) executionNotes(plans []*aggressive.Plan) []string {
	var notes []string
	lists := map[string]bool{}
	for _, plan := range plans {
		for _, requirement := range wordlistRequirements(plan) {
			lists[requirement] = true
		}
	}
	for list := range lists {
		if _, err := os.Stat(list); err != nil {
			notes = append(notes, fmt.Sprintf("wordlist not found: %s (tools that need it failed or were skipped)", list))
		}
	}
	if detections, err := h.detectAll(); err == nil {
		missing := 0
		for _, detection := range detections {
			if !detection.Found || !detection.Compatible {
				missing++
			}
		}
		if missing > 0 {
			notes = append(notes, fmt.Sprintf("%d of %d detected tools are missing or incompatible", missing, len(detections)))
		}
	}
	return notes
}

// History lists the recent operations recorded in the database.
func (h *hubService) History(limit int) ([]string, error) {
	operations, err := h.core.DB.ListOperations(h.ctx, limit)
	if err != nil {
		return nil, err
	}
	rows := make([]string, 0, len(operations))
	for _, operation := range operations {
		rows = append(rows, strings.Join([]string{
			operation.StartedAt.Local().Format("2006-01-02 15:04"),
			operation.Kind,
			operation.Target,
			operation.Profile,
			operation.Status,
		}, "|"))
	}
	return rows, nil
}

// Close releases the core when the hub ends.
func (h *hubService) Close() error {
	if h.core == nil {
		return nil
	}
	return h.core.Close()
}

// hubOptions maps the CLI flags onto the hub session.
func hubOptions(options *aggressiveOptions, scopePath string, targets []string) hub.Options {
	timeout := ""
	if options.timeout > 0 {
		timeout = options.timeout.String()
	}
	return hub.Options{
		Targets:  targets,
		Scope:    scopePath,
		Mode:     options.mode,
		Level:    options.level,
		Repeat:   options.repeat,
		Timeout:  timeout,
		Wordlist: options.wordlist,
		UserList: options.userList,
		PassList: options.passList,
	}
}
