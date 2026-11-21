package ui

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestTableAlignment(t *testing.T) {
	var out bytes.Buffer
	printer := New(&out, &out, true)
	printer.Table([]string{"NAME", "VALUE"}, [][]string{{"a", "1"}, {"longer", "2"}})
	content := out.String()
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d: %q", len(lines), content)
	}
	if !strings.Contains(lines[0], "NAME") || !strings.Contains(lines[0], "VALUE") {
		t.Fatalf("header = %q", lines[0])
	}
	if !strings.HasPrefix(lines[2], "longer") {
		t.Fatalf("row = %q", lines[2])
	}
}

func TestJSONValue(t *testing.T) {
	var out bytes.Buffer
	printer := New(&out, &out, true)
	if err := printer.JSONValue(map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded["ok"] != true {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestColorDisabledForBuffer(t *testing.T) {
	var out bytes.Buffer
	printer := New(&out, &out, false)
	if printer.Color {
		t.Fatal("colors must be disabled for non-file writers")
	}
	printer.Successf("ok")
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("ANSI escape leaked")
	}
}
