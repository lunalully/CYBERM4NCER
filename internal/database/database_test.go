package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return store, path
}

func TestMigrateIsIdempotent(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	version, err := store.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("schema version = %d, want 1", version)
	}
}

func TestProjectOperationsAndStats(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	if err := store.CreateProject(ctx, Project{
		ID: "prj_1", Name: "acme", Description: "test project", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	project, err := store.GetProjectByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if project.ID != "prj_1" || project.Description != "test project" {
		t.Fatalf("project = %+v", project)
	}

	operation := Operation{
		ID: "op_1", ProjectID: project.ID, Kind: "recon", Target: "example.com",
		Profile: "conservative", Status: "running", StartedAt: now,
	}
	if err := store.CreateOperation(ctx, operation); err != nil {
		t.Fatal(err)
	}
	finished := now.Add(time.Minute)
	if err := store.FinishOperation(ctx, "op_1", "success", finished, ""); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.GetOperation(ctx, "op_1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != "success" || loaded.FinishedAt == nil {
		t.Fatalf("operation = %+v", loaded)
	}
	if !loaded.FinishedAt.Equal(finished) {
		t.Fatalf("finished = %s, want %s", loaded.FinishedAt, finished)
	}

	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Projects != 1 || stats.Operations != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestExecutionLifecycle(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	execution := Execution{
		ID:        "exec_1",
		Tool:      "subfinder",
		Target:    "example.com",
		Argv:      []string{"-d", "example.com"},
		Status:    "running",
		ExitCode:  -1,
		StartedAt: now,
		TimeoutMS: 30000,
	}
	if err := store.CreateExecution(ctx, execution); err != nil {
		t.Fatal(err)
	}
	finished := now.Add(2 * time.Second)
	execution.Status = "success"
	execution.ExitCode = 0
	execution.FinishedAt = &finished
	execution.StdoutPath = "exec_1/stdout.log"
	execution.StderrPath = "exec_1/stderr.log"
	execution.StdoutPreview = "found 3 subdomains"
	if err := store.FinishExecution(ctx, execution); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.GetExecution(ctx, "exec_1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != "success" || loaded.ExitCode != 0 || loaded.StdoutPreview == "" {
		t.Fatalf("execution = %+v", loaded)
	}
	if len(loaded.Argv) != 2 || loaded.Argv[1] != "example.com" {
		t.Fatalf("argv = %+v", loaded.Argv)
	}
	if loaded.FinishedAt == nil || !loaded.FinishedAt.Equal(finished) {
		t.Fatalf("finished at = %v", loaded.FinishedAt)
	}

	list, err := store.ListExecutions(ctx, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %d, %v", len(list), err)
	}
}

func TestExecutionRejectsMissingOperation(t *testing.T) {
	store, _ := newTestStore(t)
	err := store.CreateExecution(context.Background(), Execution{
		ID: "exec_orphan", OperationID: "op_missing", Tool: "nmap",
		Status: "running", StartedAt: time.Now(), ExitCode: -1,
	})
	if err == nil {
		t.Fatal("expected foreign key error")
	}
}

func TestAuditChainAndTamperDetection(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := store.AppendAudit(ctx, "operator", "scope.check", "example.com", map[string]any{"allowed": true, "index": i}); err != nil {
			t.Fatal(err)
		}
	}
	verification, err := store.VerifyAudit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Valid || verification.Entries != 3 {
		t.Fatalf("verification = %+v", verification)
	}

	if _, err := store.db.ExecContext(ctx, `UPDATE audit_log SET detail_json = '{"allowed":false}' WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	verification, err = store.VerifyAudit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Valid || verification.BrokenAt != 2 {
		t.Fatalf("tamper not detected: %+v", verification)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	store, path := newTestStore(t)
	ctx := context.Background()
	if err := store.CreateProject(ctx, Project{
		ID: "prj_persist", Name: "persist", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	project, err := reopened.GetProjectByName(ctx, "persist")
	if err != nil {
		t.Fatal(err)
	}
	if project.ID != "prj_persist" {
		t.Fatalf("project = %+v", project)
	}
}

func TestFinishUnknownExecution(t *testing.T) {
	store, _ := newTestStore(t)
	err := store.FinishExecution(context.Background(), Execution{
		ID: "exec_missing", Status: "success",
	})
	if err == nil {
		t.Fatal("expected not-found error")
	}
}
