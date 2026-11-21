package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Paths are the resolved filesystem locations used by the framework.
type Paths struct {
	DataDir   string `json:"data_dir"`
	Database  string `json:"database"`
	Artifacts string `json:"artifacts"`
	Logs      string `json:"logs"`
	Tools     string `json:"tools"`
}

// Meta describes how the configuration was resolved.
type Meta struct {
	ConfigPath  string `json:"config_path"`
	ConfigFound bool   `json:"config_found"`
	Paths       Paths  `json:"paths"`
	ScopeFile   string `json:"scope_file,omitempty"`
}

// DefaultDataDir returns the XDG data directory for CYBERM4NCER.
func DefaultDataDir() string {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" && filepath.IsAbs(dir) {
		return filepath.Join(dir, "cyberm4ncer")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".cyberm4ncer")
	}
	return filepath.Join(home, ".local", "share", "cyberm4ncer")
}

// DefaultConfigPath returns the XDG configuration file path.
func DefaultConfigPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" && filepath.IsAbs(dir) {
		return filepath.Join(dir, "cyberm4ncer", "config.yaml")
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(".", ".cyberm4ncer", "config.yaml")
	}
	return filepath.Join(dir, "cyberm4ncer", "config.yaml")
}

// ExpandPath expands a leading "~" and converts the result to an absolute
// path. Environment variables are intentionally not expanded so that a
// configuration file cannot silently depend on ambient secrets.
func ExpandPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	return filepath.Clean(abs), nil
}

// DiscoverScopeFile returns the first scope file that exists, in priority
// order: explicit override, configured path, project-local file, global file.
// An explicit path that does not exist is returned as-is so callers can
// produce a precise error.
func DiscoverScopeFile(explicit string, cfg Config, paths Paths) string {
	if explicit != "" {
		if abs, err := ExpandPath(explicit); err == nil {
			return abs
		}
		return explicit
	}
	if cfg.Scope.File != "" {
		return cfg.Scope.File
	}
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, ".cyberm4ncer", "scope.yaml")
		if fileExists(candidate) {
			return candidate
		}
	}
	candidate := filepath.Join(paths.DataDir, "scope.yaml")
	if fileExists(candidate) {
		return candidate
	}
	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
