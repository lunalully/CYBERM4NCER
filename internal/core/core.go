// Package core is the composition root: configuration, logging, database,
// tool registry and execution engine are initialized once and shared.
package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/lunalully/cyberm4ncer/internal/config"
	"github.com/lunalully/cyberm4ncer/internal/database"
	"github.com/lunalully/cyberm4ncer/internal/execution"
	"github.com/lunalully/cyberm4ncer/internal/logger"
	"github.com/lunalully/cyberm4ncer/internal/tools"
)

// Options controls core startup.
type Options struct {
	ConfigPath string
	DataDir    string
	LogLevel   string
	Verbose    bool
	Stderr     io.Writer
}

// Core owns the shared services.
type Core struct {
	Config   config.Config
	Meta     config.Meta
	Paths    config.Paths
	Logger   *logger.Logger
	DB       *database.Store
	Tools    *tools.Registry
	Detector *tools.Detector
	runner   *execution.Runner
}

// Open initializes the framework. Partial initialization is rolled back.
func Open(ctx context.Context, opts Options) (*Core, error) {
	cfg, meta, err := config.Load(config.LoadOptions{
		Path:     opts.ConfigPath,
		DataDir:  opts.DataDir,
		LogLevel: opts.LogLevel,
	})
	if err != nil {
		return nil, err
	}
	if opts.Verbose {
		cfg.Logging.Level = "debug"
	}

	paths := meta.Paths
	for _, dir := range []string{paths.DataDir, paths.Artifacts, paths.Logs, paths.Tools} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create data directory %s: %w", dir, err)
		}
	}

	consoleLevel := "warn"
	if opts.Verbose {
		consoleLevel = "debug"
	}
	log, err := logger.New(logger.Options{
		Level:        cfg.Logging.Level,
		Format:       cfg.Logging.Format,
		File:         cfg.Logging.File,
		Stderr:       opts.Stderr,
		ConsoleLevel: consoleLevel,
	})
	if err != nil {
		return nil, err
	}
	cleanupLog := func() { _ = log.Close() }

	store, err := database.Open(ctx, cfg.Database.Path)
	if err != nil {
		cleanupLog()
		return nil, err
	}
	cleanupDB := func() { _ = store.Close() }

	if err := store.Migrate(ctx); err != nil {
		cleanupDB()
		cleanupLog()
		return nil, err
	}

	registry, err := tools.LoadEmbedded()
	if err != nil {
		cleanupDB()
		cleanupLog()
		return nil, err
	}

	runner, err := execution.New(execution.Options{
		Workers:        cfg.Execution.Workers,
		DefaultTimeout: cfg.Execution.DefaultTimeout.Std(),
		MaxOutputBytes: cfg.Execution.MaxOutputBytes,
		PreviewBytes:   cfg.Execution.PreviewBytes,
		Artifacts:      execution.DirArtifacts{Root: paths.Artifacts},
		Recorder:       &databaseRecorder{store: store},
		Logger:         log.Logger,
	})
	if err != nil {
		cleanupDB()
		cleanupLog()
		return nil, err
	}

	detector, err := tools.NewDetector(runner, cfg.Tools.VersionTimeout.Std(), cfg.Tools.DetectConcurrency)
	if err != nil {
		cleanupDB()
		cleanupLog()
		return nil, err
	}

	core := &Core{
		Config:   cfg,
		Meta:     meta,
		Paths:    paths,
		Logger:   log,
		DB:       store,
		Tools:    registry,
		Detector: detector,
		runner:   runner,
	}
	core.Logger.Debug("core initialized", "data_dir", paths.DataDir, "database", paths.Database, "config", meta.ConfigPath)
	return core, nil
}

// Close releases resources, returning all failures.
func (c *Core) Close() error {
	if c == nil {
		return nil
	}
	var errs []error
	if c.DB != nil {
		errs = append(errs, c.DB.Close())
	}
	if c.Logger != nil {
		errs = append(errs, c.Logger.Close())
	}
	return errors.Join(errs...)
}

// databaseRecorder persists execution lifecycle events.
type databaseRecorder struct {
	store *database.Store
}

func (r *databaseRecorder) Start(ctx context.Context, record execution.Record) error {
	return r.store.CreateExecution(ctx, database.Execution{
		ID:          record.ID,
		OperationID: record.OperationID,
		Tool:        record.Tool,
		Target:      record.Target,
		Argv:        record.Argv,
		Status:      string(record.Status),
		ExitCode:    record.ExitCode,
		StartedAt:   record.StartedAt,
		TimeoutMS:   record.Timeout.Milliseconds(),
	})
}

func (r *databaseRecorder) Finish(ctx context.Context, record execution.Record) error {
	return r.store.FinishExecution(ctx, database.Execution{
		ID:            record.ID,
		OperationID:   record.OperationID,
		Tool:          record.Tool,
		Target:        record.Target,
		Argv:          record.Argv,
		Status:        string(record.Status),
		ExitCode:      record.ExitCode,
		StartedAt:     record.StartedAt,
		FinishedAt:    record.FinishedAt,
		TimeoutMS:     record.Timeout.Milliseconds(),
		StdoutPath:    record.StdoutPath,
		StderrPath:    record.StderrPath,
		StdoutPreview: record.StdoutPreview,
		StderrPreview: record.StderrPreview,
		Error:         record.Error,
	})
}

// Writable verifies that a directory accepts files, used by doctor.
func Writable(dir string) error {
	probe, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Remove(name); err != nil {
		return err
	}
	return nil
}
