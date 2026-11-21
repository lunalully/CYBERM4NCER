package core

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lunalully/cyberm4ncer/internal/execution"
	"github.com/lunalully/cyberm4ncer/internal/scope"
)

func TestExecuteScopedEnforcesPolicyAndAudits(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{
		"CYBERM4NCER_CONFIG", "CYBERM4NCER_DATA_DIR", "CYBERM4NCER_LOG_LEVEL",
		"CYBERM4NCER_LOG_FORMAT", "CYBERM4NCER_SCOPE_FILE", "CYBERM4NCER_WORKERS",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "xdg-data"))

	var logs bytes.Buffer
	app, err := Open(context.Background(), Options{DataDir: filepath.Join(root, "data"), Stderr: &logs})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	policy, err := scope.Parse([]byte(`
version: 1
project: core-test
authorization: "core test authorization"
includes:
  - domain: example.com
    subdomains: true
`))
	if err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(root, "must-not-exist")
	_, err = app.ExecuteScoped(context.Background(), policy, execution.Request{
		Tool:   "sh",
		Args:   []string{"-c", "touch " + marker},
		Target: "evil.example.net",
	})
	var denied *ScopeDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("error = %v, want ScopeDeniedError", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("denied target executed: %v", statErr)
	}

	result, err := app.ExecuteScoped(context.Background(), policy, execution.Request{
		Tool:   "sh",
		Args:   []string{"-c", "true"},
		Target: "https://app.example.com/login",
	})
	if err != nil {
		t.Fatalf("allowed execution: %v", err)
	}
	if result.Status != execution.StatusSuccess {
		t.Fatalf("status = %s (%s)", result.Status, result.Error)
	}

	if _, err := app.ExecuteScoped(context.Background(), nil, execution.Request{
		Tool: "sh", Target: "example.com",
	}); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("nil policy error = %v", err)
	}
	if _, err := app.ExecuteScoped(context.Background(), policy, execution.Request{
		Tool: "sh", Target: "   ",
	}); !errors.Is(err, ErrTargetRequired) {
		t.Fatalf("empty target error = %v", err)
	}

	verification, err := app.DB.VerifyAudit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Valid || verification.Entries != 2 {
		t.Fatalf("audit = %+v, want 2 valid entries", verification)
	}
	stats, err := app.DB.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Executions != 1 {
		t.Fatalf("executions = %d, want 1", stats.Executions)
	}
}
