package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func cleanEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"CYBERM4NCER_CONFIG", "CYBERM4NCER_DATA_DIR", "CYBERM4NCER_LOG_LEVEL",
		"CYBERM4NCER_LOG_FORMAT", "CYBERM4NCER_SCOPE_FILE", "CYBERM4NCER_WORKERS",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadUsesDefaultsWhenFileIsAbsent(t *testing.T) {
	cleanEnvironment(t)
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))

	cfg, meta, err := Load(LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if meta.ConfigFound {
		t.Fatal("expected no config file")
	}
	if cfg.Execution.Workers != 4 {
		t.Fatalf("workers = %d, want 4", cfg.Execution.Workers)
	}
	if cfg.Execution.DefaultTimeout.Std() != 10*time.Minute {
		t.Fatalf("default timeout = %s", cfg.Execution.DefaultTimeout)
	}
	wantData := filepath.Join(root, "data", "cyberm4ncer")
	if cfg.DataDir != wantData {
		t.Fatalf("data dir = %q, want %q", cfg.DataDir, wantData)
	}
	if meta.Paths.Database != filepath.Join(wantData, "cyberm4ncer.db") {
		t.Fatalf("database path = %q", meta.Paths.Database)
	}
	if !strings.HasSuffix(cfg.Logging.File, filepath.Join("logs", "cyberm4ncer.log")) {
		t.Fatalf("log file = %q", cfg.Logging.File)
	}
}

func TestLoadFileAndPrecedence(t *testing.T) {
	cleanEnvironment(t)
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	dataDir := filepath.Join(root, "data")
	content := `
version: 1
data_dir: ` + dataDir + `
execution:
  workers: 2
  default_timeout: 2m
  max_output_bytes: 2097152
  preview_bytes: 1048576
logging:
  level: warn
  format: json
tools:
  version_timeout: 3s
  detect_concurrency: 2
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CYBERM4NCER_WORKERS", "7")
	t.Setenv("CYBERM4NCER_LOG_LEVEL", "error")

	cfg, meta, err := Load(LoadOptions{Path: configPath, LogLevel: "debug", DataDir: filepath.Join(root, "override")})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !meta.ConfigFound {
		t.Fatal("config should be found")
	}
	if cfg.Execution.Workers != 7 {
		t.Fatalf("workers = %d, want env value 7", cfg.Execution.Workers)
	}
	if cfg.Logging.Level != "debug" {
		t.Fatalf("log level = %q, want CLI override debug", cfg.Logging.Level)
	}
	if cfg.Execution.DefaultTimeout.Std() != 2*time.Minute {
		t.Fatalf("timeout = %s", cfg.Execution.DefaultTimeout)
	}
	if cfg.Logging.Format != "json" {
		t.Fatalf("format = %q", cfg.Logging.Format)
	}
	if cfg.DataDir != filepath.Join(root, "override") {
		t.Fatalf("data dir = %q", cfg.DataDir)
	}
	if cfg.Database.Path != filepath.Join(root, "override", "cyberm4ncer.db") {
		t.Fatalf("database path = %q", cfg.Database.Path)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	cleanEnvironment(t)
	root := t.TempDir()
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nworkers_typo: 4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(LoadOptions{Path: path}); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestLoadExplicitMissingFileFails(t *testing.T) {
	cleanEnvironment(t)
	if _, _, err := Load(LoadOptions{Path: filepath.Join(t.TempDir(), "missing.yaml")}); err == nil {
		t.Fatal("expected error for explicit missing config")
	}
}

func TestValidateRejectsInvalidWorkers(t *testing.T) {
	cfg := Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Execution.Workers = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateRejectsPreviewLargerThanOutput(t *testing.T) {
	cfg := Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Execution.PreviewBytes = cfg.Execution.MaxOutputBytes + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDurationUnmarshalErrors(t *testing.T) {
	var duration Duration
	if err := duration.UnmarshalYAML(&yaml.Node{Kind: yaml.ScalarNode, Value: "not-a-duration"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestDiscoverScopeFileOrder(t *testing.T) {
	root := t.TempDir()
	cfg := Defaults()
	paths := Paths{DataDir: root}
	global := filepath.Join(root, "scope.yaml")
	if err := os.WriteFile(global, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := DiscoverScopeFile("", cfg, paths); got != global {
		t.Fatalf("discover = %q, want %q", got, global)
	}
	explicit := filepath.Join(root, "explicit.yaml")
	if got := DiscoverScopeFile(explicit, cfg, paths); got != explicit {
		t.Fatalf("explicit = %q", got)
	}
}

func TestExpandPathHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := ExpandPath("~/data")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(home, "data") {
		t.Fatalf("expanded = %q", got)
	}
}
