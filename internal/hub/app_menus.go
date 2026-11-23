package hub

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// toolsMenu lists the external tools the core really detected.
func (a *App) toolsMenu(ctx context.Context) (bool, error) {
	rows, err := a.Service.Tools()
	if err != nil {
		return true, err
	}
	fmt.Fprintln(a.Out)
	fmt.Fprintln(a.Out, a.paint("EXTERNAL TOOLS"))
	table := make([][]string, 0, len(rows))
	for _, row := range rows {
		table = append(table, strings.SplitN(row, "|", 4))
	}
	a.UI.Printer.Table([]string{"TOOL", "STATUS", "VERSION", "PATH"}, table)
	detect, detectErr := a.Service.Detect()
	fmt.Fprintln(a.Out)
	if detectErr != nil {
		fmt.Fprintf(a.Out, "  detect: %v\n", detectErr)
	} else {
		fmt.Fprintf(a.Out, "  detect: %s\n", detect)
	}
	return true, nil
}

// configMenu shows the resolved configuration, the scope in use and lets the
// operator change the shared session options.
func (a *App) configMenu(ctx context.Context) (bool, error) {
	for {
		menu := Menu{
			Title:    a.paint("CONFIGURATION AND SCOPE"),
			Subtitle: "the session keeps these values for every module",
			Items: []Item{
				{Key: "1", Label: "scope file", Detail: a.scopeText()},
				{Key: "2", Label: "targets", Detail: a.targetText()},
				{Key: "3", Label: "reset session", Detail: "clear target, scope and settings"},
				{Key: "4", Label: "clear targets"},
				{Key: "0", Label: "back"},
			},
		}
		item, err := a.UI.Choose(menu)
		if err == io.EOF || item.Key == "0" || item.Key == "" {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		switch item.Key {
		case "1":
			a.askScope()
		case "2":
			_ = a.askTarget()
		case "3":
			ok, err := a.UI.Confirm("reset the session context?")
			if err != nil {
				return true, err
			}
			if ok {
				a.Options = Options{Mode: "all", Level: 5}
			}
		case "4":
			a.Options.Targets = nil
		}
		a.UI.ContextLines = a.contextLines()
	}
}

// historyMenu lists the operations recorded in the database.
func (a *App) historyMenu(ctx context.Context) (bool, error) {
	rows, err := a.Service.History(25)
	if err != nil {
		return true, err
	}
	fmt.Fprintln(a.Out)
	fmt.Fprintln(a.Out, a.paint("HISTORY"))
	if len(rows) == 0 {
		fmt.Fprintln(a.Out, "  no operations recorded yet")
		return true, nil
	}
	table := make([][]string, 0, len(rows))
	for _, row := range rows {
		table = append(table, strings.SplitN(row, "|", 5))
	}
	a.UI.Printer.Table([]string{"STARTED", "KIND", "TARGET", "PROFILE", "STATUS"}, table)
	return true, nil
}

func (a *App) scopeText() string {
	if a.Options.Scope == "" {
		return "none (targets are used as given)"
	}
	return a.Options.Scope
}

func (a *App) targetText() string {
	if len(a.Options.Targets) == 0 {
		return "none"
	}
	return strings.Join(a.Options.Targets, ", ")
}
