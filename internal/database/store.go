// Package database owns the local SQLite store. SQL lives here; domain
// packages never build queries.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store is a local SQLite database handle.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens the database, applies restrictive permissions and verifies
// connectivity. Migrate must be called before using the store.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("database path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String() +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if err := os.Chmod(abs, 0o600); err != nil && !os.IsNotExist(err) {
		_ = db.Close()
		return nil, fmt.Errorf("set database permissions: %w", err)
	}
	return &Store{db: db, path: abs}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the absolute database path.
func (s *Store) Path() string { return s.path }

// Ping checks connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Migrate applies all pending schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	var current int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d)", current, len(migrations))
	}
	for version := current; version < len(migrations); version++ {
		statement := migrations[version]
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", version+1, err)
		}
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", version+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version+1)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", version+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", version+1, err)
		}
	}
	return nil
}

// SchemaVersion returns the current migration version.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

// Stats summarizes stored records.
type Stats struct {
	Projects   int `json:"projects"`
	Operations int `json:"operations"`
	Executions int `json:"executions"`
	Results    int `json:"results"`
	Audit      int `json:"audit"`
}

// Stats counts rows in the main tables.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var stats Stats
	tables := []struct {
		name string
		dst  *int
	}{
		{"projects", &stats.Projects},
		{"operations", &stats.Operations},
		{"executions", &stats.Executions},
		{"results", &stats.Results},
		{"audit_log", &stats.Audit},
	}
	for _, table := range tables {
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table.name).Scan(table.dst); err != nil {
			return Stats{}, fmt.Errorf("count %s: %w", table.name, err)
		}
	}
	return stats, nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp %q: %w", value, err)
	}
	return parsed, nil
}
