package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultConfigFileMatchesSchema(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "defaults.yaml")
	cfg, meta, err := Load(LoadOptions{Path: path})
	if err != nil {
		t.Fatalf("defaults.yaml does not match the config schema: %v", err)
	}
	if !meta.ConfigFound {
		t.Fatal("config file not loaded")
	}
	if cfg.Execution.Workers != 4 || cfg.Tools.DetectConcurrency != 4 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}
