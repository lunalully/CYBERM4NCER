// Package logger builds the structured logger used by the framework.
package logger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Options controls logger construction.
type Options struct {
	Level        string
	Format       string
	File         string
	Stderr       io.Writer
	ConsoleLevel string
}

// Logger owns the optional log file and the structured logger.
type Logger struct {
	*slog.Logger
	file *os.File
}

// New creates a logger that writes to stderr and, when configured, to a file.
// A file write failure is returned instead of being silently discarded.
//
// When a file is configured, the file receives the configured level while
// the console receives ConsoleLevel (default warn) to keep CLI output clean.
func New(opts Options) (*Logger, error) {
	level, err := ParseLevel(opts.Level)
	if err != nil {
		return nil, err
	}
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		return nil, fmt.Errorf("unsupported log format %q", opts.Format)
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	var file *os.File
	if strings.TrimSpace(opts.File) != "" {
		if err := os.MkdirAll(filepath.Dir(opts.File), 0o700); err != nil {
			return nil, fmt.Errorf("create log directory: %w", err)
		}
		file, err = os.OpenFile(opts.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open log file %s: %w", opts.File, err)
		}
	}

	var handler slog.Handler
	if file == nil {
		handler = newHandler(format, stderr, level)
	} else {
		consoleLevel, err := ParseLevel(defaultString(opts.ConsoleLevel, "warn"))
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("console log level: %w", err)
		}
		handler = multiHandler{handlers: []slog.Handler{
			newHandler(format, file, level),
			newHandler(format, stderr, consoleLevel),
		}}
	}
	return &Logger{Logger: slog.New(handler), file: file}, nil
}

// Close closes the log file, if any.
func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

func newHandler(format string, writer io.Writer, level slog.Level) slog.Handler {
	options := &slog.HandlerOptions{Level: level}
	if format == "json" {
		return slog.NewJSONHandler(writer, options)
	}
	return slog.NewTextHandler(writer, options)
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// ParseLevel maps a configuration string to a slog level.
func ParseLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (use debug, info, warn or error)", value)
	}
}

// multiHandler fans a record out to several handlers with distinct levels.
type multiHandler struct {
	handlers []slog.Handler
}

func (m multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range m.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m multiHandler) Handle(ctx context.Context, record slog.Record) error {
	var errs []error
	for _, handler := range m.handlers {
		if handler.Enabled(ctx, record.Level) {
			if err := handler.Handle(ctx, record.Clone()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, handler := range m.handlers {
		handlers[i] = handler.WithAttrs(attrs)
	}
	return multiHandler{handlers: handlers}
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, handler := range m.handlers {
		handlers[i] = handler.WithGroup(name)
	}
	return multiHandler{handlers: handlers}
}
