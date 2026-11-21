package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root := NewRoot(Streams{Out: &stdout, Err: &stderr})
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func writeTestConfig(t *testing.T) (configPath, dataDir string) {
	t.Helper()
	root := t.TempDir()
	dataDir = filepath.Join(root, "data")
	configPath = filepath.Join(root, "config.yaml")
	content := "version: 1\ndata_dir: " + dataDir + "\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, dataDir
}

func writeTestScope(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const cliScope = `
version: 1
project: cli-test
authorization: "authorized for CLI tests"
includes:
  - domain: example.com
    subdomains: true
`

func TestVersionCommand(t *testing.T) {
	stdout, _, err := runCLI(t, "version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "CYBERM4NCER") || !strings.Contains(stdout, "Platform:") {
		t.Fatalf("output = %q", stdout)
	}
}

func TestScopeValidateCommand(t *testing.T) {
	configPath, _ := writeTestConfig(t)
	scopePath := writeTestScope(t, cliScope)
	stdout, _, err := runCLI(t, "--config", configPath, "scope", "validate", scopePath)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !strings.Contains(stdout, "scope is valid") || !strings.Contains(stdout, "cli-test") {
		t.Fatalf("output = %q", stdout)
	}
}

func TestScopeCheckDeniedExitsTwo(t *testing.T) {
	configPath, _ := writeTestConfig(t)
	scopePath := writeTestScope(t, cliScope)
	stdout, _, err := runCLI(t, "--config", configPath, "scope", "check", "evil.example.net", "--file", scopePath)
	if err == nil {
		t.Fatal("expected denied exit")
	}
	if code := ExitCode(err); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stdout, "DENIED") {
		t.Fatalf("output = %q", stdout)
	}
}

func TestScopeCheckAllowed(t *testing.T) {
	configPath, _ := writeTestConfig(t)
	scopePath := writeTestScope(t, cliScope)
	stdout, _, err := runCLI(t, "--config", configPath, "scope", "check", "https://app.example.com/login", "--file", scopePath)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !strings.Contains(stdout, "ALLOWED") {
		t.Fatalf("output = %q", stdout)
	}
}

func TestConfigInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")
	_, _, err := runCLI(t, "--config", path, "config", "init")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "version: 1") {
		t.Fatalf("config = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
	if _, _, err := runCLI(t, "--config", path, "config", "init"); err == nil {
		t.Fatal("expected existing-file error")
	}
	if _, _, err := runCLI(t, "--config", path, "config", "init", "--force"); err != nil {
		t.Fatalf("force init: %v", err)
	}
}

func TestDoctorSkipTools(t *testing.T) {
	configPath, dataDir := writeTestConfig(t)
	stdout, _, err := runCLI(t, "--config", configPath, "doctor", "--skip-tools")
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if !strings.Contains(stdout, "database") || !strings.Contains(stdout, "audit") {
		t.Fatalf("output = %q", stdout)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "cyberm4ncer.db")); err != nil {
		t.Fatalf("database was not created: %v", err)
	}
}

func TestToolsList(t *testing.T) {
	stdout, _, err := runCLI(t, "tools", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "subfinder") || !strings.Contains(stdout, "nuclei") {
		t.Fatalf("output = %q", stdout)
	}
}

func TestToolsInfoUnknown(t *testing.T) {
	_, _, err := runCLI(t, "tools", "info", "does-not-exist")
	if err == nil {
		t.Fatal("expected unknown tool error")
	}
}

func TestJSONOutput(t *testing.T) {
	stdout, _, err := runCLI(t, "--json", "version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout), "{") {
		t.Fatalf("expected JSON, got %q", stdout)
	}
}
