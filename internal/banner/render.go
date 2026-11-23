package banner

import (
	"fmt"
	"io"
	"strings"
)

// Palette holds the ANSI colors of the header. Empty fields mean plain text.
type Palette struct {
	// Deep is the darkest shade of the block letters (the ░ cells).
	Deep string
	// Mid is the middle shade (▒).
	Mid string
	// Core is the brightest shade (█).
	Core string
	// Frame is used for the double rules above and below the header.
	Frame string
	// Reset closes a colored run.
	Reset string
}

// NeonPurple is the default CYBERM4NCER identity: a neon violet gradient.
func NeonPurple() Palette {
	return Palette{
		Deep:  "\x1b[38;5;56m",
		Mid:   "\x1b[38;5;129m",
		Core:  "\x1b[38;5;165m",
		Frame: "\x1b[38;5;135m",
		Reset: "\x1b[0m",
	}
}

// Plain returns a palette without colors, used for files and dumb terminals.
func Plain() Palette { return Palette{} }

// Enabled reports whether the palette paints anything.
func (p Palette) Enabled() bool { return p.Reset != "" }

// Render draws the header: a frame line, the art (one shade per cell density)
// and a dim subtitle, all vertically centered to width when width is positive.
func Render(w io.Writer, art []string, subtitle string, width int, p Palette) error {
	if artWidth := maxLine(art); width > 0 && artWidth < width {
		left := (width - artWidth) / 2
		art = indent(art, left)
		subtitle = strings.Repeat(" ", left) + subtitle
	}
	var b strings.Builder
	frame := strings.Repeat("─", maxLine(art)+2)
	if p.Enabled() {
		fmt.Fprintf(&b, "%s╞%s╡%s\n", p.Frame, frame, p.Reset)
	} else {
		fmt.Fprintf(&b, "|%s|\n", frame)
	}
	for _, line := range art {
		b.WriteString(paintLine(line, p))
		b.WriteByte('\n')
	}
	if p.Enabled() {
		fmt.Fprintf(&b, "%s╞%s╡%s\n", p.Frame, frame, p.Reset)
	} else {
		fmt.Fprintf(&b, "|%s|\n", frame)
	}
	if subtitle != "" {
		b.WriteString(subtitle)
		b.WriteByte('\n')
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// paintLine colors each rune of one art line by its shade.
func paintLine(line string, p Palette) string {
	if !p.Enabled() {
		return line
	}
	var b strings.Builder
	current := ""
	for _, r := range line {
		shade := p.Core
		switch r {
		case '░':
			shade = p.Deep
		case '▒':
			shade = p.Mid
		}
		if shade != current {
			if current != "" {
				b.WriteString(p.Reset)
			}
			b.WriteString(shade)
			current = shade
		}
		b.WriteRune(r)
	}
	if current != "" {
		b.WriteString(p.Reset)
	}
	return b.String()
}

// indent adds spaces before each non-empty line.
func indent(lines []string, spaces int) []string {
	if spaces <= 0 {
		return lines
	}
	pad := strings.Repeat(" ", spaces)
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = pad + line
	}
	return out
}

func maxLine(lines []string) int {
	width := 0
	for _, line := range lines {
		if n := len([]rune(line)); n > width {
			width = n
		}
	}
	return width
}
