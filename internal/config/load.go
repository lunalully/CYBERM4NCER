package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// LoadOptions carries command-line overrides.
type LoadOptions struct {
	// Path is an explicit configuration file. When empty, the default
	// location or CYBERM4NCER_CONFIG is used.
	Path string
	// DataDir overrides the configured data directory.
	DataDir string
	// LogLevel overrides the configured log level.
	LogLevel string
}

// Load resolves, parses, validates and materializes the configuration.
// It does not create directories; core.Open performs that with restrictive
// permissions.
func Load(opts LoadOptions) (Config, Meta, error) {
	cfg := Defaults()
	meta := Meta{}

	configPath := strings.TrimSpace(opts.Path)
	explicit := configPath != ""
	if configPath == "" {
		configPath = strings.TrimSpace(os.Getenv("CYBERM4NCER_CONFIG"))
		explicit = configPath != ""
	}
	if configPath == "" {
		configPath = DefaultConfigPath()
	}
	if abs, err := ExpandPath(configPath); err == nil {
		configPath = abs
	}
	meta.ConfigPath = configPath

	data, err := os.ReadFile(configPath)
	switch {
	case err == nil:
		meta.ConfigFound = true
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
			return Config{}, meta, fmt.Errorf("parse config %s: %w", configPath, err)
		}
	case explicit:
		return Config{}, meta, fmt.Errorf("config file %s: %w", configPath, err)
	case errors.Is(err, fs.ErrNotExist):
		// Defaults are valid; doctor reports that the file is absent.
	default:
		return Config{}, meta, fmt.Errorf("read config %s: %w", configPath, err)
	}

	if err := applyEnv(&cfg); err != nil {
		return Config{}, meta, err
	}
	if opts.DataDir != "" {
		cfg.DataDir = opts.DataDir
	}
	if opts.LogLevel != "" {
		cfg.Logging.Level = opts.LogLevel
	}

	paths, err := resolvePaths(cfg)
	if err != nil {
		return Config{}, meta, err
	}
	cfg.DataDir = paths.DataDir
	cfg.Database.Path = paths.Database
	logFile := firstNonEmpty(cfg.Logging.File, filepath.Join(paths.Logs, "cyberm4ncer.log"))
	cfg.Logging.File, err = ExpandPath(logFile)
	if err != nil {
		return Config{}, meta, fmt.Errorf("logging.file: %w", err)
	}
	cfg.Tools.Dir = paths.Tools
	meta.Paths = paths

	if cfg.Scope.File != "" {
		scopePath, err := ExpandPath(cfg.Scope.File)
		if err != nil {
			return Config{}, meta, fmt.Errorf("scope.file: %w", err)
		}
		cfg.Scope.File = scopePath
		meta.ScopeFile = scopePath
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, meta, err
	}
	return cfg, meta, nil
}

func resolvePaths(cfg Config) (Paths, error) {
	dataDir := strings.TrimSpace(cfg.DataDir)
	if dataDir == "" {
		dataDir = DefaultDataDir()
	}
	expanded, err := ExpandPath(dataDir)
	if err != nil {
		return Paths{}, fmt.Errorf("data_dir: %w", err)
	}
	paths := Paths{
		DataDir:   expanded,
		Database:  filepath.Join(expanded, "cyberm4ncer.db"),
		Artifacts: filepath.Join(expanded, "artifacts"),
		Logs:      filepath.Join(expanded, "logs"),
		Tools:     filepath.Join(expanded, "tools"),
	}
	if cfg.Database.Path != "" {
		paths.Database, err = ExpandPath(cfg.Database.Path)
		if err != nil {
			return Paths{}, fmt.Errorf("database.path: %w", err)
		}
	}
	if cfg.Tools.Dir != "" {
		paths.Tools, err = ExpandPath(cfg.Tools.Dir)
		if err != nil {
			return Paths{}, fmt.Errorf("tools.dir: %w", err)
		}
	}
	return paths, nil
}

func applyEnv(cfg *Config) error {
	if v := strings.TrimSpace(os.Getenv("CYBERM4NCER_DATA_DIR")); v != "" {
		cfg.DataDir = v
	}
	if v := strings.TrimSpace(os.Getenv("CYBERM4NCER_LOG_LEVEL")); v != "" {
		cfg.Logging.Level = v
	}
	if v := strings.TrimSpace(os.Getenv("CYBERM4NCER_LOG_FORMAT")); v != "" {
		cfg.Logging.Format = v
	}
	if v := strings.TrimSpace(os.Getenv("CYBERM4NCER_SCOPE_FILE")); v != "" {
		cfg.Scope.File = v
	}
	if v := strings.TrimSpace(os.Getenv("CYBERM4NCER_WORDLIST")); v != "" {
		cfg.Execution.Wordlist = v
	}
	if v := strings.TrimSpace(os.Getenv("CYBERM4NCER_WORKERS")); v != "" {
		workers, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("CYBERM4NCER_WORKERS: %w", err)
		}
		cfg.Execution.Workers = workers
	}
	return nil
}

// Validate checks semantic constraints and returns all failures at once.
func (c Config) Validate() error {
	var errs []error
	if c.Version != 1 {
		errs = append(errs, fmt.Errorf("unsupported config version %d (expected 1)", c.Version))
	}
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir must not be empty"))
	}
	if c.Execution.Workers < 1 || c.Execution.Workers > 256 {
		errs = append(errs, fmt.Errorf("execution.workers must be between 1 and 256, got %d", c.Execution.Workers))
	}
	if c.Execution.DefaultTimeout.Std() < time.Second {
		errs = append(errs, errors.New("execution.default_timeout must be at least 1s"))
	}
	if c.Execution.DefaultTimeout.Std() > 24*time.Hour {
		errs = append(errs, errors.New("execution.default_timeout must be at most 24h"))
	}
	if c.Execution.MaxOutputBytes < 1<<20 || c.Execution.MaxOutputBytes > 1<<30 {
		errs = append(errs, errors.New("execution.max_output_bytes must be between 1MiB and 1GiB"))
	}
	if c.Execution.PreviewBytes < 1<<10 || c.Execution.PreviewBytes > 16<<20 {
		errs = append(errs, errors.New("execution.preview_bytes must be between 1KiB and 16MiB"))
	}
	if c.Execution.PreviewBytes > c.Execution.MaxOutputBytes {
		errs = append(errs, errors.New("execution.preview_bytes cannot exceed execution.max_output_bytes"))
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("logging.level must be debug, info, warn or error, got %q", c.Logging.Level))
	}
	switch c.Logging.Format {
	case "text", "json":
	default:
		errs = append(errs, fmt.Errorf("logging.format must be text or json, got %q", c.Logging.Format))
	}
	if c.Tools.VersionTimeout.Std() < time.Second || c.Tools.VersionTimeout.Std() > 2*time.Minute {
		errs = append(errs, errors.New("tools.version_timeout must be between 1s and 2m"))
	}
	if c.Tools.DetectConcurrency < 1 || c.Tools.DetectConcurrency > 64 {
		errs = append(errs, errors.New("tools.detect_concurrency must be between 1 and 64"))
	}
	return errors.Join(errs...)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
