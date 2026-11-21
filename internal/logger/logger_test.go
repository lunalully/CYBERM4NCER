package logger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewRejectsInvalidLevel(t *testing.T) {
	if _, err := New(Options{Level: "trace", Format: "text"}); err == nil {
		t.Fatal("expected invalid level error")
	}
}

func TestLoggerWritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "test.log")
	var stderr bytes.Buffer
	log, err := New(Options{Level: "debug", Format: "text", File: path, Stderr: &stderr, ConsoleLevel: "debug"})
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hello", "key", "value")
	log.Debug("detailed")
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "hello") || !strings.Contains(content, "key=value") {
		t.Fatalf("file content = %q", content)
	}
	if !strings.Contains(content, "detailed") {
		t.Fatal("debug line missing at debug level")
	}
	if !strings.Contains(stderr.String(), "hello") {
		t.Fatal("stderr did not receive logs")
	}
}

func TestJSONLogger(t *testing.T) {
	var stderr bytes.Buffer
	log, err := New(Options{Level: "info", Format: "json", Stderr: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	log.Info("json message")
	if !strings.Contains(stderr.String(), `"msg":"json message"`) {
		t.Fatalf("json output = %s", stderr.String())
	}
}

func TestParseLevel(t *testing.T) {
	for value, want := range map[string]string{
		"debug": "DEBUG", "info": "INFO", "warn": "WARN", "warning": "WARN", "error": "ERROR",
	} {
		level, err := ParseLevel(value)
		if err != nil {
			t.Fatal(err)
		}
		if level.String() != want {
			t.Fatalf("%s: got %s, want %s", value, level, want)
		}
	}
}
