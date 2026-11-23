// Package execution runs external tools safely and records every execution.
package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/lunalully/cyberm4ncer/internal/id"
)

// ErrToolNotFound indicates that the executable is not available.
var ErrToolNotFound = errors.New("tool executable not found")

// Request describes one external process invocation.
type Request struct {
	// Tool is the display name used in logs and records.
	Tool string
	// Path is the executable. When empty, Tool is resolved via PATH.
	Path string
	// Args are passed as separate argv entries; no shell is involved.
	Args []string
	// Target is the audited asset associated with the execution.
	Target string
	// OperationID links the execution to an operation, when present.
	OperationID string
	// Timeout overrides the runner default.
	Timeout time.Duration
	// Env entries are appended to the current process environment.
	Env []string
	// WorkDir is the process working directory.
	WorkDir string
	// ExpectedExitCodes lists exit codes that mean "completed normally".
	// Some tools print their usage or report "nothing found" with a non-zero
	// code. When set, those codes produce StatusSuccess; anything else still
	// fails.
	ExpectedExitCodes []int
	// Stream, when set, receives the process stdout and stderr as they are
	// produced, in addition to the artifact files and preview buffers.
	Stream io.Writer
}

// Result is the outcome of an execution.
type Result struct {
	ID                     string        `json:"id"`
	Tool                   string        `json:"tool"`
	Target                 string        `json:"target,omitempty"`
	Args                   []string      `json:"args"`
	Status                 Status        `json:"status"`
	ExitCode               int           `json:"exit_code"`
	StartedAt              time.Time     `json:"started_at"`
	FinishedAt             time.Time     `json:"finished_at"`
	Duration               time.Duration `json:"duration"`
	Timeout                time.Duration `json:"timeout"`
	StdoutPath             string        `json:"stdout_path,omitempty"`
	StderrPath             string        `json:"stderr_path,omitempty"`
	StdoutPreview          string        `json:"stdout_preview,omitempty"`
	StderrPreview          string        `json:"stderr_preview,omitempty"`
	StdoutTruncated        bool          `json:"stdout_truncated,omitempty"`
	StderrTruncated        bool          `json:"stderr_truncated,omitempty"`
	StdoutPreviewTruncated bool          `json:"stdout_preview_truncated,omitempty"`
	StderrPreviewTruncated bool          `json:"stderr_preview_truncated,omitempty"`
	Error                  string        `json:"error,omitempty"`
	Warnings               []string      `json:"warnings,omitempty"`
}

// Record is the persisted execution state passed to a Recorder.
type Record struct {
	ID            string
	OperationID   string
	Tool          string
	Target        string
	Argv          []string
	Status        Status
	ExitCode      int
	StartedAt     time.Time
	FinishedAt    *time.Time
	Timeout       time.Duration
	StdoutPath    string
	StderrPath    string
	StdoutPreview string
	StderrPreview string
	Error         string
}

// Recorder persists execution lifecycle events. A start failure aborts the
// execution so that nothing runs without a trace.
type Recorder interface {
	Start(ctx context.Context, record Record) error
	Finish(ctx context.Context, record Record) error
}

// NoopRecorder is used for ephemeral probes.
type NoopRecorder struct{}

// Start implements Recorder.
func (NoopRecorder) Start(context.Context, Record) error { return nil }

// Finish implements Recorder.
func (NoopRecorder) Finish(context.Context, Record) error { return nil }

// Options controls the runner.
type Options struct {
	Workers        int
	DefaultTimeout time.Duration
	MaxOutputBytes int64
	PreviewBytes   int64
	Artifacts      Artifacts
	Recorder       Recorder
	Logger         *slog.Logger
}

// Runner enforces concurrency and lifecycle rules for external processes.
type Runner struct {
	sem            chan struct{}
	artifacts      Artifacts
	recorder       Recorder
	logger         *slog.Logger
	defaultTimeout time.Duration
	maxOutput      int64
	preview        int64
}

// New validates options and builds a runner.
func New(opts Options) (*Runner, error) {
	workers := opts.Workers
	if workers == 0 {
		workers = 4
	}
	if workers < 1 || workers > 256 {
		return nil, fmt.Errorf("execution workers must be between 1 and 256")
	}
	defaultTimeout := opts.DefaultTimeout
	if defaultTimeout == 0 {
		defaultTimeout = 10 * time.Minute
	}
	if defaultTimeout < 0 {
		return nil, fmt.Errorf("default timeout cannot be negative")
	}
	maxOutput := opts.MaxOutputBytes
	if maxOutput == 0 {
		maxOutput = 32 << 20
	}
	if maxOutput < 0 {
		return nil, fmt.Errorf("max output bytes cannot be negative")
	}
	preview := opts.PreviewBytes
	if preview == 0 {
		preview = 64 << 10
	}
	if preview < 0 || preview > maxOutput {
		return nil, fmt.Errorf("preview bytes must be between 0 and max output bytes")
	}
	artifacts := opts.Artifacts
	if artifacts == nil {
		artifacts = DiscardArtifacts{}
	}
	recorder := opts.Recorder
	if recorder == nil {
		recorder = NoopRecorder{}
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Runner{
		sem:            make(chan struct{}, workers),
		artifacts:      artifacts,
		recorder:       recorder,
		logger:         log,
		defaultTimeout: defaultTimeout,
		maxOutput:      maxOutput,
		preview:        preview,
	}, nil
}

// Run executes a process. Process exit failures, timeouts and cancellations
// are reported through Result.Status; the returned error is reserved for
// engine-level failures (setup, tracing, start failure).
func (r *Runner) Run(ctx context.Context, req Request) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result := Result{
		ID:       id.New("exec"),
		Tool:     strings.TrimSpace(req.Tool),
		Target:   req.Target,
		Args:     RedactArgs(req.Args),
		Status:   StatusError,
		ExitCode: -1,
	}
	if result.Tool == "" {
		return Result{}, fmt.Errorf("tool is required")
	}
	if req.Timeout < 0 {
		return result, fmt.Errorf("timeout cannot be negative")
	}
	timeout := req.Timeout
	if timeout == 0 {
		timeout = r.defaultTimeout
	}
	result.Timeout = timeout

	if err := ctx.Err(); err != nil {
		result.Status = StatusCanceled
		result.Error = err.Error()
		return result, nil
	}

	path := req.Path
	if path == "" {
		resolved, err := exec.LookPath(result.Tool)
		if err != nil {
			result.Error = err.Error()
			return result, fmt.Errorf("%w: %s", ErrToolNotFound, result.Tool)
		}
		path = resolved
	}

	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		result.Status = StatusCanceled
		result.Error = ctx.Err().Error()
		return result, nil
	}

	stdoutWriter, stdoutPath, err := r.artifacts.Create(result.ID, "stdout")
	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("create stdout artifact: %w", err)
	}
	stderrWriter, stderrPath, err := r.artifacts.Create(result.ID, "stderr")
	if err != nil {
		_ = stdoutWriter.Close()
		result.Error = err.Error()
		return result, fmt.Errorf("create stderr artifact: %w", err)
	}
	result.StdoutPath = stdoutPath
	result.StderrPath = stderrPath

	stdoutFile := newLimitWriter(stdoutWriter, r.maxOutput)
	stderrFile := newLimitWriter(stderrWriter, r.maxOutput)
	stdoutBuffer := &bytes.Buffer{}
	stderrBuffer := &bytes.Buffer{}
	stdoutPreview := newLimitWriter(stdoutBuffer, r.preview)
	stderrPreview := newLimitWriter(stderrBuffer, r.preview)

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdoutTargets := []io.Writer{stdoutFile, stdoutPreview}
	stderrTargets := []io.Writer{stderrFile, stderrPreview}
	if req.Stream != nil {
		// stdout and stderr are copied by separate goroutines; one mutex keeps
		// the live stream readable and a broken terminal never fails the run.
		live := &liveWriter{dst: req.Stream}
		stdoutTargets = append(stdoutTargets, live)
		stderrTargets = append(stderrTargets, live)
	}

	cmd := exec.CommandContext(runCtx, path, req.Args...)
	cmd.Env = append(os.Environ(), req.Env...)
	cmd.Dir = req.WorkDir
	cmd.Stdout = io.MultiWriter(stdoutTargets...)
	cmd.Stderr = io.MultiWriter(stderrTargets...)
	configureProcess(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd.Process) }
	cmd.WaitDelay = 3 * time.Second

	record := Record{
		ID:          result.ID,
		OperationID: req.OperationID,
		Tool:        result.Tool,
		Target:      req.Target,
		Argv:        result.Args,
		Status:      StatusRunning,
		ExitCode:    -1,
		StartedAt:   time.Now().UTC(),
		Timeout:     timeout,
	}
	result.StartedAt = record.StartedAt
	if err := r.recorder.Start(ctx, record); err != nil {
		closeStreams(stdoutWriter, stderrWriter)
		result.Error = err.Error()
		return result, fmt.Errorf("record execution start: %w", err)
	}
	r.logger.Info("execution started",
		"execution_id", result.ID, "tool", result.Tool, "target", req.Target,
		"timeout", timeout, "argv", result.Args,
	)

	startErr := cmd.Start()
	if startErr != nil {
		finished := time.Now().UTC()
		result.FinishedAt = finished
		result.Duration = finished.Sub(result.StartedAt)
		result.Status = StatusError
		result.Error = startErr.Error()
		warnings := closeStreams(stdoutWriter, stderrWriter)
		result.Warnings = append(result.Warnings, warnings...)
		record.Status = StatusError
		record.FinishedAt = &finished
		record.Error = joinMessages(result.Error, warnings)
		persistErr := r.persistFinish(ctx, record)
		r.logger.Error("execution failed to start", "execution_id", result.ID, "tool", result.Tool, "error", startErr)
		return result, errors.Join(fmt.Errorf("start %s: %w", result.Tool, startErr), persistErr)
	}

	waitErr := cmd.Wait()
	finished := time.Now().UTC()
	result.FinishedAt = finished
	result.Duration = finished.Sub(result.StartedAt)
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	switch {
	case cmd.ProcessState != nil && cmd.ProcessState.Success():
		result.Status = StatusSuccess
	case cmd.ProcessState != nil && containsCode(req.ExpectedExitCodes, result.ExitCode):
		result.Status = StatusSuccess
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		result.Status = StatusTimeout
		result.Error = fmt.Sprintf("timed out after %s", timeout)
	case errors.Is(runCtx.Err(), context.Canceled):
		result.Status = StatusCanceled
		result.Error = "canceled"
	case waitErr != nil:
		result.Status = StatusFailed
		result.Error = waitErr.Error()
	default:
		result.Status = StatusFailed
		result.Error = fmt.Sprintf("process exited with code %d", result.ExitCode)
	}

	result.StdoutPreview = stdoutBuffer.String()
	result.StderrPreview = stderrBuffer.String()
	result.StdoutTruncated = stdoutFile.truncated
	result.StderrTruncated = stderrFile.truncated
	result.StdoutPreviewTruncated = stdoutPreview.truncated
	result.StderrPreviewTruncated = stderrPreview.truncated

	if stdoutFile.err != nil {
		result.Warnings = append(result.Warnings, "stdout capture: "+stdoutFile.err.Error())
	}
	if stderrFile.err != nil {
		result.Warnings = append(result.Warnings, "stderr capture: "+stderrFile.err.Error())
	}
	closeWarnings := closeStreams(stdoutWriter, stderrWriter)
	result.Warnings = append(result.Warnings, closeWarnings...)

	record.Status = result.Status
	record.ExitCode = result.ExitCode
	record.FinishedAt = &finished
	record.StdoutPath = result.StdoutPath
	record.StderrPath = result.StderrPath
	record.StdoutPreview = result.StdoutPreview
	record.StderrPreview = result.StderrPreview
	record.Error = joinMessages(result.Error, result.Warnings)

	persistErr := r.persistFinish(ctx, record)

	level := slog.LevelInfo
	if result.Status != StatusSuccess {
		level = slog.LevelWarn
	}
	r.logger.Log(ctx, level, "execution finished",
		"execution_id", result.ID, "tool", result.Tool, "target", req.Target,
		"status", result.Status, "exit_code", result.ExitCode,
		"duration", result.Duration, "error", result.Error,
	)
	if persistErr != nil {
		return result, persistErr
	}
	return result, nil
}

func containsCode(codes []int, code int) bool {
	for _, candidate := range codes {
		if candidate == code {
			return true
		}
	}
	return false
}

func (r *Runner) persistFinish(ctx context.Context, record Record) error {
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := r.recorder.Finish(persistCtx, record); err != nil {
		return fmt.Errorf("record execution finish: %w", err)
	}
	return nil
}

func closeStreams(writers ...io.WriteCloser) []string {
	var warnings []string
	for _, writer := range writers {
		if err := writer.Close(); err != nil {
			warnings = append(warnings, "close artifact: "+err.Error())
		}
	}
	return warnings
}

func joinMessages(message string, warnings []string) string {
	parts := make([]string, 0, len(warnings)+1)
	if strings.TrimSpace(message) != "" {
		parts = append(parts, message)
	}
	parts = append(parts, warnings...)
	return strings.Join(parts, "; ")
}
