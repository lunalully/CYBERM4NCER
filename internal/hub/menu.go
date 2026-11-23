// Package hub implements the interactive Operations Hub: a small, dependency
// free terminal interface opened when cyberm4ncer runs without a command.
package hub

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Item is one entry of a menu.
type Item struct {
	// Key is the numeric code the operator types ("1", "0", ...); it is
	// rendered as [01].
	Key string
	// Label is the menu text.
	Label string
	// Detail is an optional note shown to the right (status, hint).
	Detail string
	// Disabled marks an entry that exists but cannot run yet.
	Disabled bool
}

// Menu is a titled list of items.
type Menu struct {
	Title    string
	Subtitle string
	Items    []Item
}

// Printer is the small color surface the hub needs; ui.Printer implements it.
type Printer interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Successf(format string, args ...any)
	Errorf(format string, args ...any)
	// Paint colors a token with the interface accent.
	Paint(token string) string
	// Table writes an aligned table.
	Table(headers []string, rows [][]string)
	// Reset restores the default text style.
	Reset(text string) string
}

// UI owns the terminal streams and the display context shown on every screen.
type UI struct {
	In      *bufio.Reader
	Out     io.Writer
	Printer Printer
	// ContextLines are printed under the header (session, target, scope).
	ContextLines []string
}

// SetContext replaces the session panel shown above every menu.
func (u *UI) SetContext(lines []string) { u.ContextLines = lines }

// Choose shows a menu and returns the selected item. An empty item with a nil
// error means the operator asked to go back.
func (u *UI) Choose(menu Menu) (Item, error) {
	return u.choose(menu, true)
}

// ChooseDrawn is Choose for a menu the caller already rendered, such as the
// home screen printed by Home. It reads input without drawing the menu again.
func (u *UI) ChooseDrawn(menu Menu) (Item, error) {
	return u.choose(menu, false)
}

func (u *UI) choose(menu Menu, drawFirst bool) (Item, error) {
	if drawFirst {
		u.draw(menu)
	}
	for {
		fmt.Fprint(u.Out, u.Printer.Paint("› "))
		line, err := u.readLine()
		if err != nil {
			return Item{}, err
		}
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "":
			continue
		case "b", "back", "voltar", "..":
			return Item{}, nil
		case "q", "quit", "exit", "sair":
			return Item{Key: "0"}, nil
		case "?":
			u.draw(menu)
			continue
		}
		item, ok := menu.Lookup(line)
		if !ok {
			u.Printer.Warnf("invalid selection %q", line)
			u.draw(menu)
			continue
		}
		if item.Disabled {
			u.Printer.Warnf("%s is not available yet", item.Label)
			u.draw(menu)
			continue
		}
		return item, nil
	}
}

// draw renders one screen with the session context on top.
func (u *UI) draw(menu Menu) {
	fmt.Fprintln(u.Out)
	for _, line := range u.ContextLines {
		fmt.Fprintln(u.Out, line)
	}
	if len(u.ContextLines) > 0 {
		fmt.Fprintln(u.Out)
	}
	if menu.Title != "" {
		fmt.Fprintln(u.Out, u.Printer.Paint(menu.Title))
	}
	if menu.Subtitle != "" {
		fmt.Fprintln(u.Out, menu.Subtitle)
	}
	for _, item := range menu.Items {
		line := "  " + u.Printer.Paint(code(item.Key)) + " " + item.Label
		if item.Detail != "" {
			line += "  " + item.Detail
		}
		fmt.Fprintln(u.Out, line)
	}
	fmt.Fprintln(u.Out)
}

// Lookup resolves what the operator typed: the numeric key (with or without
// zero padding) or the exact label.
func (m Menu) Lookup(input string) (Item, bool) {
	input = strings.TrimSpace(input)
	for _, item := range m.Items {
		if input == item.Key || strings.TrimLeft(input, "0") == strings.TrimLeft(item.Key, "0") {
			return item, true
		}
	}
	upper := strings.ToUpper(input)
	for _, item := range m.Items {
		if strings.ToUpper(item.Label) == upper {
			return item, true
		}
	}
	return Item{}, false
}

// readLine reads one line, treating EOF as a request to leave.
func (u *UI) readLine() (string, error) {
	line, err := u.In.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return line, nil
}

// code renders an item key as [01]; non-numeric keys keep their symbol.
func code(key string) string {
	if key == "" {
		return "[  ]"
	}
	if key[0] < '0' || key[0] > '9' {
		return "[" + key + "]"
	}
	if len(key) >= 2 {
		return "[" + key + "]"
	}
	return "[0" + key + "]"
}
