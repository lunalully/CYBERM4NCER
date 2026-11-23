package hub

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Options a session carries between screens.
type Options struct {
	Targets  []string
	Scope    string
	Mode     string
	Level    int
	Repeat   int
	Timeout  string
	Wordlist string
	UserList string
	PassList string
}

// App drives the Operations Hub.
type App struct {
	UI      *UI
	Service Service
	Out     io.Writer
	Options Options
	// Palette paints frames and hints.
	Palette struct{ Accent, Dim, Reset string }
}

// Run opens the hub and returns when the operator leaves.
func (a *App) Run(ctx context.Context) error {
	if a.Options.Mode == "" {
		a.Options.Mode = "all"
	}
	if a.Options.Level == 0 {
		a.Options.Level = 5
	}
	a.printHome()
	for {
		item, err := a.UI.Choose(a.mainMenu())
		if err == io.EOF {
			fmt.Fprintln(a.Out)
			return nil
		}
		if err != nil {
			return err
		}
		if item.Key == "0" {
			fmt.Fprintln(a.Out, a.paint("session closed"))
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		again, err := a.open(ctx, item.Key)
		if err != nil {
			a.UI.Printer.Errorf("%v", err)
			continue
		}
		if !again {
			return nil
		}
		a.printHome()
	}
}

// printHome redraws the header screen.
func (a *App) printHome() {
	status := a.statusLines()
	a.UI.ContextLines = a.contextLines()
	a.UI.Home(Palette{Accent: a.Palette.Accent, Dim: a.Palette.Dim, Reset: a.Palette.Reset}, status, a.mainMenu())
}

// mainMenu lists the real categories plus the shared commands.
func (a *App) mainMenu() Menu {
	items := append([]Item(nil), KnownCategories...)
	items = append(items,
		Item{Key: "?", Label: "HELP", Detail: "type a number, 'b' back, 'q' quit"},
		Item{Key: "0", Label: "EXIT"},
	)
	return Menu{Title: a.paint("OPERATIONS HUB"), Subtitle: "select an operation:", Items: items}
}

// contextLines is the session panel shown above every menu.
func (a *App) contextLines() []string {
	target := "none"
	if len(a.Options.Targets) > 0 {
		target = strings.Join(a.Options.Targets, ", ")
	}
	scope := "none (targets are used as given)"
	if a.Options.Scope != "" {
		scope = a.Options.Scope
	}
	mode := a.Options.Mode
	if a.Options.Repeat > 0 {
		mode += fmt.Sprintf(" repeat=%d", a.Options.Repeat)
	}
	if a.Options.Level > 0 {
		mode += fmt.Sprintf(" level=%d", a.Options.Level)
	}
	return []string{
		fmt.Sprintf("%s %s", a.paint("target:"), target),
		fmt.Sprintf("%s %s", a.paint("scope:"), scope),
		fmt.Sprintf("%s %s", a.paint("mode:"), mode),
	}
}

// statusLines reports what the core really found, or says it failed.
func (a *App) statusLines() []string {
	detected := "unknown"
	if summary, err := a.Service.ToolSummary(); err == nil && summary != "" {
		detected = summary
	} else if err != nil {
		detected = "unavailable (" + err.Error() + ")"
	}
	return []string{
		fmt.Sprintf("  %s   %s", a.paint("[ SYSTEM ONLINE ]"), a.paint("[ TOOLS "+detected+" ]")),
		fmt.Sprintf("  %s", a.dim("v0.2.0-dev  terminal readline interface  Ctrl+C cancels a running operation")),
	}
}

// open dispatches one category. It returns false when the operator wants to
// leave the hub.
func (a *App) open(ctx context.Context, key string) (bool, error) {
	switch key {
	case "1":
		return a.runMode(ctx, "recon", "RECONNAISSANCE")
	case "2":
		return a.runMode(ctx, "enum", "NETWORK OPERATIONS")
	case "3":
		return a.runWebMenu(ctx)
	case "4":
		return a.runMode(ctx, "vuln", "VULNERABILITY ASSESSMENT")
	case "5":
		return a.runCredentials(ctx)
	case "6":
		return a.runMode(ctx, "all", "FULL AGGRESSIVE RUN")
	case "7":
		return a.toolsMenu(ctx)
	case "8":
		return a.configMenu(ctx)
	case "9":
		return a.historyMenu(ctx)
	}
	a.UI.Printer.Warnf("category %s is not implemented", key)
	return true, nil
}

// runMode runs one aggressive mode after the operator configures it.
func (a *App) runMode(ctx context.Context, mode, title string) (bool, error) {
	if err := a.askTarget(); err != nil {
		return true, err
	}
	if len(a.Options.Targets) == 0 {
		return true, nil
	}
	a.Options.Mode = mode
	if err := a.askExecution(title); err != nil {
		// Back from the settings or end of input: nothing runs.
		if err == io.EOF {
			return true, nil
		}
		return true, err
	}
	return a.execute(ctx, title)
}

// runWebMenu offers the web-focused parts of the same engine.
func (a *App) runWebMenu(ctx context.Context) (bool, error) {
	for {
		menu := Menu{
			Title:    a.paint("WEB AND API SECURITY"),
			Subtitle: "web work runs through the reviewed web tools (ffuf, gobuster, wafw00f, whatweb, httpx, nuclei, dalfox, sqlmap, TLS tools)",
			Items: []Item{
				{Key: "1", Label: "web enumeration", Detail: "mode: enum"},
				{Key: "2", Label: "recon only", Detail: "mode: recon"},
				{Key: "3", Label: "vulnerability assessment", Detail: "mode: vuln"},
				{Key: "4", Label: "full run", Detail: "mode: all"},
				{Key: "0", Label: "back"},
			},
		}
		item, err := a.UI.Choose(menu)
		if err == io.EOF || item.Key == "" || item.Key == "0" {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		modes := map[string]string{"1": "enum", "2": "recon", "3": "vuln", "4": "all"}
		return a.runMode(ctx, modes[item.Key], "WEB AND API SECURITY")
	}
}

// runCredentials configures the credential tools, which need both lists.
func (a *App) runCredentials(ctx context.Context) (bool, error) {
	if err := a.askTarget(); err != nil {
		return true, err
	}
	if len(a.Options.Targets) == 0 {
		return true, nil
	}
	a.Options.Mode = "vuln"
	a.UI.Printer.Warnf("credential testing only runs with --userlist and --passlist; without them hydra and medusa are skipped")
	if err := a.askExecution("CREDENTIAL TESTING"); err != nil {
		return true, err
	}
	if a.Options.UserList == "" || a.Options.PassList == "" {
		a.UI.Printer.Warnf("userlist or passlist missing: hydra/medusa stay disabled")
	}
	return a.execute(ctx, "CREDENTIAL TESTING")
}

// askTarget asks for the target when the session has none.
func (a *App) askTarget() error {
	current := strings.Join(a.Options.Targets, " ")
	answer, err := a.UI.Prompt("target (host, IP, CIDR or http(s) URL; comma separated)", current)
	if err != nil || answer.Back || answer.Quit {
		return err
	}
	if answer.Value == "" {
		return nil
	}
	targets := Targets(answer.Value)
	for _, target := range targets {
		if !validTarget(target) {
			a.UI.Printer.Warnf("invalid target %q", target)
			return nil
		}
	}
	a.Options.Targets = targets
	a.UI.ContextLines = a.contextLines()
	return nil
}

// askExecution walks the shared execution settings.
func (a *App) askExecution(title string) error {
	for {
		menu := Menu{
			Title:    a.paint(title + " — EXECUTION SETTINGS"),
			Subtitle: "defaults come from the configuration; empty answers keep the current value",
			Items: []Item{
				{Key: "1", Label: "run with the current configuration", Detail: a.describe()},
				{Key: "2", Label: "change level", Detail: fmt.Sprintf("level %d", a.Options.Level)},
				{Key: "3", Label: "change repetition cap", Detail: a.repeatText()},
				{Key: "4", Label: "change per-step timeout", Detail: a.timeoutText()},
				{Key: "5", Label: "change wordlist", Detail: a.orNone(a.Options.Wordlist)},
				{Key: "6", Label: "change credential lists", Detail: a.credentialText()},
				{Key: "7", Label: "change scope file", Detail: a.orNone(a.Options.Scope)},
				{Key: "0", Label: "back"},
			},
		}
		item, err := a.UI.Choose(menu)
		if err == io.EOF || item.Key == "0" || item.Key == "" {
			return io.EOF
		}
		if err != nil {
			return err
		}
		switch item.Key {
		case "1":
			return nil
		case "2":
			a.askLevel()
		case "3":
			a.askRepeat()
		case "4":
			a.askTimeout()
		case "5":
			a.askField("web wordlist path", &a.Options.Wordlist)
		case "6":
			a.askCredentialLists()
		case "7":
			a.askScope()
		}
	}
}

func (a *App) askLevel() {
	answer, err := a.UI.Prompt("level 1 (gentle) to 5 (maximum)", strconv.Itoa(a.Options.Level))
	if err != nil || answer.Back || answer.Quit {
		return
	}
	if level, ok := Number(answer.Value, a.Options.Level); ok && level >= 1 && level <= 5 {
		a.Options.Level = level
		return
	}
	a.UI.Printer.Warnf("level must be between 1 and 5")
}

func (a *App) askRepeat() {
	answer, err := a.UI.Prompt("repetition cap (0 keeps the reviewed values)", strconv.Itoa(a.Options.Repeat))
	if err != nil || answer.Back || answer.Quit {
		return
	}
	if repeat, ok := Number(answer.Value, a.Options.Repeat); ok && repeat >= 0 {
		a.Options.Repeat = repeat
		return
	}
	a.UI.Printer.Warnf("repetition must be zero or a positive number")
}

func (a *App) askTimeout() {
	answer, err := a.UI.Prompt("per-step timeout (e.g. 45s, 2m; 0 uses the configuration)", a.Options.Timeout)
	if err != nil || answer.Back || answer.Quit {
		return
	}
	a.Options.Timeout = answer.Value
}

func (a *App) askField(question string, field *string) {
	answer, err := a.UI.Prompt(question, *field)
	if err != nil || answer.Back || answer.Quit {
		return
	}
	*field = answer.Value
}

func (a *App) askCredentialLists() {
	a.askField("userlist path", &a.Options.UserList)
	a.askField("passlist path", &a.Options.PassList)
}

func (a *App) askScope() {
	answer, err := a.UI.Prompt("scope file (empty clears it)", a.Options.Scope)
	if err != nil || answer.Back || answer.Quit {
		return
	}
	a.Options.Scope = answer.Value
}

func (a *App) describe() string {
	return fmt.Sprintf("mode=%s level=%d repeat=%d timeout=%s", a.Options.Mode, a.Options.Level, a.Options.Repeat, a.orNone(a.Options.Timeout))
}

func (a *App) repeatText() string {
	if a.Options.Repeat == 0 {
		return "reviewed values"
	}
	return strconv.Itoa(a.Options.Repeat) + " per invocation"
}

func (a *App) timeoutText() string {
	if a.Options.Timeout == "" {
		return "configuration default"
	}
	return a.Options.Timeout
}

func (a *App) credentialText() string {
	if a.Options.UserList == "" || a.Options.PassList == "" {
		return "disabled (no lists)"
	}
	return "enabled"
}

func (a *App) orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

// execute builds the plan, confirms it and runs it.
func (a *App) execute(ctx context.Context, title string) (bool, error) {
	view, err := a.Service.Plan(
		strings.Join(a.Options.Targets, " "),
		a.Options.Scope, a.Options.Mode, a.Options.Level, a.Options.Repeat,
		a.Options.Wordlist, a.Options.UserList, a.Options.PassList,
	)
	if err != nil {
		return true, err
	}
	scope := a.Service.ScopePath(view)
	if scope == "" {
		scope = "none (targets are used as given)"
	}
	fmt.Fprintln(a.Out)
	fmt.Fprintln(a.Out, a.paint(title))
	fmt.Fprintf(a.Out, "  module:  aggressive engine (mode %s, level %d)\n", view.Mode, view.Level)
	fmt.Fprintf(a.Out, "  target:  %s\n", view.Target)
	fmt.Fprintf(a.Out, "  scope:   %s\n", scope)
	fmt.Fprintf(a.Out, "  tools:   %s\n", strings.Join(view.Tools, ", "))
	fmt.Fprintf(a.Out, "  planned: %d invocations, %d skipped\n", view.Steps, view.Skips)
	ok, err := a.UI.Confirm("run this operation now?")
	if err != nil || !ok {
		return true, err
	}
	summary, runErr := a.Service.Execute(Context{
		Mode: a.Options.Mode, Level: a.Options.Level, Repeat: a.Options.Repeat,
		Timeout: a.Options.Timeout, Wordlist: a.Options.Wordlist,
		UserList: a.Options.UserList, PassList: a.Options.PassList,
	}, view, a.Out)
	a.finish(title, summary, runErr)
	if runErr != nil && ctx.Err() == nil {
		a.UI.Printer.Errorf("%v", runErr)
	}
	for {
		menu := Menu{
			Title: a.paint("OPERATION FINISHED"),
			Items: []Item{
				{Key: "1", Label: "run another module"},
				{Key: "2", Label: "return to the Operations Hub"},
				{Key: "3", Label: "exit"},
			},
		}
		item, err := a.UI.Choose(menu)
		if err == io.EOF || item.Key == "" || item.Key == "2" {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		if item.Key == "1" {
			return true, nil
		}
		if item.Key == "3" {
			return false, nil
		}
	}
}

// finish prints the real summary of the operation.
func (a *App) finish(title string, summary SummaryView, runErr error) {
	fmt.Fprintln(a.Out)
	status := "COMPLETED"
	if runErr != nil {
		status = "FINISHED WITH ERRORS"
	}
	if summary.Truncated {
		status = "STOPPED EARLY (max steps)"
	}
	fmt.Fprintf(a.Out, "  %s %s\n", a.paint("status:"), status)
	fmt.Fprintf(a.Out, "  steps=%d succeeded=%d failed=%d skipped=%d discovered=%d hosts=%d ports=%d elapsed=%s\n",
		summary.Steps, summary.Succeeded, summary.Failed, summary.Skipped,
		summary.Discovered, summary.Hosts, summary.Ports, summary.Elapsed)
	if len(summary.Matches) > 0 {
		fmt.Fprintln(a.Out, "  matches:")
		for _, match := range summary.Matches {
			fmt.Fprintf(a.Out, "    %s\n", match)
		}
	}
	if summary.ResultsPath != "" {
		fmt.Fprintf(a.Out, "  results: %s\n", summary.ResultsPath)
	}
	for _, note := range summary.Notes {
		fmt.Fprintf(a.Out, "  %s\n", note)
	}
	if runErr != nil {
		fmt.Fprintf(a.Out, "  error: %v\n", runErr)
	}
}

func (a *App) paint(text string) string {
	if a.Palette.Accent == "" {
		return text
	}
	return a.Palette.Accent + text + a.Palette.Reset
}

func (a *App) dim(text string) string {
	if a.Palette.Dim == "" {
		return text
	}
	return a.Palette.Dim + text + a.Palette.Reset
}
