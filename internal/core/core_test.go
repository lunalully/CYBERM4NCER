package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenInitializesAndCloses(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{
		"CYBERM4NCER_CONFIG", "CYBERM4NCER_DATA_DIR", "CYBERM4NCER_LOG_LEVEL",
		"CYBERM4NCER_LOG_FORMAT", "CYBERM4NCER_SCOPE_FILE", "CYBERM4NCER_WORKERS",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "xdg-data"))

	dataDir := filepath.Join(root, "data")
	var logs bytes.Buffer
	app, err := Open(context.Background(), Options{
		DataDir: dataDir,
		Stderr:  &logs,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if app.DB == nil || app.Tools == nil || app.Detector == nil || app.runner == nil {
		t.Fatal("core services are not initialized")
	}
	version, err := app.DB.SchemaVersion(context.Background())
	if err != nil || version != 1 {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "cyberm4ncer.db")); err != nil {
		t.Fatalf("database missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "logs", "cyberm4ncer.log")); err != nil {
		t.Fatalf("log missing: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestWritable(t *testing.T) {
	if err := Writable(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := Writable(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for missing directory")
	}
}
