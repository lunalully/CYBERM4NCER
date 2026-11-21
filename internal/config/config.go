// Package config loads and validates CYBERM4NCER configuration.
//
// Precedence, from lowest to highest:
//
//  1. built-in defaults
//  2. the YAML configuration file
//  3. CYBERM4NCER_* environment variables
//  4. command-line overrides
package config

import "time"

// Config is the complete runtime configuration.
type Config struct {
	Version   int             `yaml:"version" json:"version"`
	DataDir   string          `yaml:"data_dir" json:"data_dir"`
	Database  DatabaseConfig  `yaml:"database" json:"database"`
	Execution ExecutionConfig `yaml:"execution" json:"execution"`
	Logging   LoggingConfig   `yaml:"logging" json:"logging"`
	Scope     ScopeConfig     `yaml:"scope" json:"scope"`
	Tools     ToolsConfig     `yaml:"tools" json:"tools"`
}

// DatabaseConfig controls the local SQLite store.
type DatabaseConfig struct {
	Path string `yaml:"path" json:"path"`
}

// ExecutionConfig controls external process execution.
type ExecutionConfig struct {
	Workers        int      `yaml:"workers" json:"workers"`
	DefaultTimeout Duration `yaml:"default_timeout" json:"default_timeout"`
	MaxOutputBytes int64    `yaml:"max_output_bytes" json:"max_output_bytes"`
	PreviewBytes   int64    `yaml:"preview_bytes" json:"preview_bytes"`
	// Wordlist is the default web wordlist used by aggressive runs.
	Wordlist string `yaml:"wordlist" json:"wordlist"`
}

// LoggingConfig controls structured logging.
type LoggingConfig struct {
	Level  string `yaml:"level" json:"level"`
	Format string `yaml:"format" json:"format"`
	File   string `yaml:"file" json:"file"`
}

// ScopeConfig controls scope enforcement.
type ScopeConfig struct {
	File string `yaml:"file" json:"file"`
}

// ToolsConfig controls tool detection and the managed tool directory.
type ToolsConfig struct {
	Dir               string   `yaml:"dir" json:"dir"`
	VersionTimeout    Duration `yaml:"version_timeout" json:"version_timeout"`
	DetectConcurrency int      `yaml:"detect_concurrency" json:"detect_concurrency"`
}

// Defaults returns the conservative built-in configuration.
func Defaults() Config {
	return Config{
		Version: 1,
		Execution: ExecutionConfig{
			Workers:        4,
			DefaultTimeout: Duration(10 * time.Minute),
			MaxOutputBytes: 32 << 20, // 32 MiB per stream
			PreviewBytes:   64 << 10, // 64 KiB kept in memory/database
			Wordlist:       "/usr/share/wordlists/dirb/common.txt",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		Scope: ScopeConfig{},
		Tools: ToolsConfig{
			VersionTimeout:    Duration(5 * time.Second),
			DetectConcurrency: 4,
		},
	}
}
