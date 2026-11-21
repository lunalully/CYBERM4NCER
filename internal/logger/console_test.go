package logger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsoleDefaultsToWarningsWhenFileConfigured(t *testing.T) {
	var stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "app.log")
	log, err := New(Options{Level: "info", Format: "text", File: path, Stderr: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	log.Info("file-only-message")
	log.Warn("console-warning")
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "file-only-message") {
		t.Fatalf("info leaked to console: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "console-warning") {
		t.Fatalf("warning missing from console: %s", stderr.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "file-only-message") {
		t.Fatal("info missing from file")
	}
}
