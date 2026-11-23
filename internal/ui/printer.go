// Package ui provides consistent terminal output without pulling a TUI
// dependency into the core.
package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	colorReset  = "\x1b[0m"
	colorBold   = "\x1b[1m"
	colorDim    = "\x1b[2m"
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorCyan   = "\x1b[36m"
	// colorAccent and colorViolet give the interface its neon purple
	// identity (256-color SGR, widely supported by Linux terminals).
	colorAccent = "\x1b[38;5;135m"
	colorViolet = "\x1b[38;5;165m"
)

// Printer writes human or JSON output. It never writes colored output when
// the destination is not a terminal or when colors are disabled.
type Printer struct {
	Out   io.Writer
	Err   io.Writer
	Color bool
	JSON  bool
}

// New returns a printer configured for the given streams.
func New(out, err io.Writer, noColor bool) *Printer {
	if out == nil {
		out = os.Stdout
	}
	if err == nil {
		err = os.Stderr
	}
	return &Printer{Out: out, Err: err, Color: ColorEnabled(out, noColor)}
}

// ColorEnabled reports whether ANSI color should be used.
func ColorEnabled(w io.Writer, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func (p *Printer) paint(code, value string) string {
	if !p.Color {
		return value
	}
	return code + value + colorReset
}

// Paint colors a token with the interface accent (neon purple).
func (p *Printer) Paint(token string) string {
	return p.paint(colorAccent+colorBold, token)
}

// Reset re-emits the default style so a value inside a painted prompt is not
// shown in the accent color.
func (p *Printer) Reset(text string) string {
	return p.paint("", text)
}

// Violet paints a string with the bright neon purple accent.
func (p *Printer) Violet(text string) string {
	return p.paint(colorViolet+colorBold, text)
}

// DimText paints a string with the muted color.
func (p *Printer) DimText(text string) string {
	return p.paint(colorDim, text)
}

// Title prints a section title.
func (p *Printer) Title(text string) {
	fmt.Fprintln(p.Out, p.paint(colorBold+colorCyan, text))
}

// Infof prints an informational message to stdout.
func (p *Printer) Infof(format string, args ...any) {
	fmt.Fprintf(p.Out, format+"\n", args...)
}

// Successf prints a success message to stdout.
func (p *Printer) Successf(format string, args ...any) {
	fmt.Fprintln(p.Out, p.paint(colorGreen, fmt.Sprintf(format, args...)))
}

// Warnf prints a warning to stderr.
func (p *Printer) Warnf(format string, args ...any) {
	fmt.Fprintln(p.Err, p.paint(colorYellow, "warning: "+fmt.Sprintf(format, args...)))
}

// Errorf prints an error to stderr.
func (p *Printer) Errorf(format string, args ...any) {
	fmt.Fprintln(p.Err, p.paint(colorRed, "error: "+fmt.Sprintf(format, args...)))
}

// Dim prints a muted line to stdout.
func (p *Printer) Dim(format string, args ...any) {
	fmt.Fprintln(p.Out, p.paint(colorDim, fmt.Sprintf(format, args...)))
}

// Table prints a simple aligned table.
func (p *Printer) Table(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = utf8.RuneCountInString(header)
	}
	for _, row := range rows {
		for i := 0; i < len(row) && i < len(widths); i++ {
			if n := utf8.RuneCountInString(row[i]); n > widths[i] {
				widths[i] = n
			}
		}
	}

	var headerParts []string
	for i, header := range headers {
		headerParts = append(headerParts, pad(header, widths[i]))
	}
	fmt.Fprintln(p.Out, p.paint(colorBold, strings.Join(headerParts, "  ")))

	for _, row := range rows {
		var parts []string
		for i := range headers {
			value := ""
			if i < len(row) {
				value = row[i]
			}
			parts = append(parts, pad(value, widths[i]))
		}
		fmt.Fprintln(p.Out, strings.TrimRight(strings.Join(parts, "  "), " "))
	}
}

// JSONValue writes indented JSON to stdout.
func (p *Printer) JSONValue(value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON output: %w", err)
	}
	_, err = fmt.Fprintln(p.Out, string(encoded))
	return err
}

func pad(value string, width int) string {
	length := utf8.RuneCountInString(value)
	if length >= width {
		return value
	}
	return value + strings.Repeat(" ", width-length)
}
