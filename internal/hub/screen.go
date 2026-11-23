package hub

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/lunalully/cyberm4ncer/internal/banner"
)

// Palette mirrors banner.Palette for the frame around the header.
type Palette struct {
	Accent string
	Dim    string
	Reset  string
}

// Home draws the full startup screen: frame, header, system status, session
// context and the operations menu.
func (u *UI) Home(palette Palette, status []string, menu Menu) {
	width := terminalWidth(u.Out)
	fmt.Fprintln(u.Out)
	_ = banner.Render(u.Out, banner.Lines(), "  R E D   T E A M   O P E R A T I O N S   F R A M E W O R K", width, banner.NeonPurple())
	fmt.Fprintln(u.Out)
	for _, row := range status {
		fmt.Fprintln(u.Out, row)
	}
	fmt.Fprintln(u.Out)
	u.draw(menu)
}

// Ask prompts for one value. An empty answer keeps the current value; the
// operator may type back or quit.
type Answer struct {
	Value string
	Back  bool
	Quit  bool
}

// Prompt asks a question and reads one answer.
func (u *UI) Prompt(question, current string) (Answer, error) {
	fmt.Fprintf(u.Out, "%s", question)
	if current != "" {
		fmt.Fprintf(u.Out, " [%s]", u.Printer.Reset(current))
	}
	fmt.Fprint(u.Out, ": ")
	line, err := u.readLine()
	if err != nil {
		return Answer{}, err
	}
	line = strings.TrimSpace(line)
	switch strings.ToLower(line) {
	case "b", "back", "voltar":
		return Answer{Back: true}, nil
	case "q", "quit", "exit", "sair":
		return Answer{Quit: true}, nil
	case "":
		return Answer{Value: current}, nil
	}
	return Answer{Value: line}, nil
}

// Confirm asks a yes/no question; anything but an explicit yes is a no.
func (u *UI) Confirm(question string) (bool, error) {
	fmt.Fprintf(u.Out, "%s [y/N]: ", question)
	line, err := u.readLine()
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "s", "sim":
		return true, nil
	}
	return false, nil
}

// Paragraph prints one wrapped block of text.
func (u *UI) Paragraph(text string) {
	for _, line := range strings.Split(text, "\n") {
		fmt.Fprintln(u.Out, line)
	}
}

// Number parses a whole number answer, returning def for an empty answer.
func Number(answer string, def int) (int, bool) {
	answer = strings.TrimSpace(answer)
	if answer == "" {
		return def, true
	}
	value, err := strconv.Atoi(answer)
	if err != nil {
		return 0, false
	}
	return value, true
}

// terminalWidth returns the terminal width in columns, or 0 when unknown.
func terminalWidth(out io.Writer) int {
	file, ok := out.(*os.File)
	if !ok {
		return 0
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return 0
	}
	return widths(os.Getenv("COLUMNS"))
}

// widths parses a column count from the environment.
func widths(text string) int {
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value <= 0 {
		return 0
	}
	return value
}

// NewUI wires a hub interface to the given streams.
func NewUI(in io.Reader, out io.Writer, printer Printer) *UI {
	return &UI{In: bufio.NewReader(in), Out: out, Printer: printer}
}
