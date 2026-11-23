package banner

import (
	"strings"
	"testing"
)

func TestArtHasSevenAlignedLines(t *testing.T) {
	lines := Lines()
	if len(lines) != 7 {
		t.Fatalf("lines = %d, want 7", len(lines))
	}
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			t.Fatalf("line %d is empty", i)
		}
		for _, r := range line {
			if r != '░' && r != '▒' && r != '▓' && r != '█' && r != ' ' {
				t.Fatalf("line %d contains %q, outside the block-shade alphabet", i, r)
			}
		}
	}
	if width := Width(); width < 140 || width > 160 {
		t.Fatalf("width = %d, not the expected block-letter width", width)
	}
}

func TestRenderPlainHasNoEscapes(t *testing.T) {
	var out strings.Builder
	if err := Render(&out, Lines(), "SUBTITLE", 0, Plain()); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.Contains(text, "\x1b") {
		t.Fatal("plain render contains ANSI escapes")
	}
	if !strings.Contains(text, "SUBTITLE") {
		t.Fatal("subtitle missing")
	}
	if !strings.Contains(text, strings.TrimSpace(Lines()[0])) {
		t.Fatal("art missing")
	}
}

func TestRenderColorsByShade(t *testing.T) {
	var out strings.Builder
	palette := NeonPurple()
	if err := Render(&out, Lines(), "", 0, palette); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, shade := range []string{palette.Deep, palette.Mid, palette.Core, palette.Frame} {
		if !strings.Contains(text, shade) {
			t.Fatalf("render is missing shade %q", shade)
		}
	}
	if strings.Count(text, palette.Reset) < 7 {
		t.Fatal("each line must reset its color")
	}
}

func TestRenderCentersWhenWideTerminal(t *testing.T) {
	var out strings.Builder
	art := []string{"ab", "cd"}
	if err := Render(&out, art, "", 10, Plain()); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	for _, line := range lines[1:3] {
		if !strings.HasPrefix(strings.TrimSpace(line), "ab") && !strings.HasPrefix(strings.TrimSpace(line), "cd") {
			t.Fatalf("line %q is not centered", line)
		}
		if leading := len(line) - len(strings.TrimLeft(line, " ")); leading != 4 {
			t.Fatalf("line %q is not centered (leading spaces %d)", line, leading)
		}
	}
}
