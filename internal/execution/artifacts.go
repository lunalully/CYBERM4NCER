package execution

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var artifactComponent = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Artifacts stores full stdout/stderr streams. Returned paths are relative
// to the artifact root so the data directory can be moved.
type Artifacts interface {
	Create(executionID, stream string) (writer io.WriteCloser, path string, err error)
}

// DirArtifacts writes artifacts beneath a root directory.
type DirArtifacts struct {
	Root string
}

// Create implements Artifacts.
func (d DirArtifacts) Create(executionID, stream string) (io.WriteCloser, string, error) {
	if d.Root == "" {
		return nil, "", fmt.Errorf("artifact root is empty")
	}
	if !artifactComponent.MatchString(executionID) {
		return nil, "", fmt.Errorf("invalid execution id %q", executionID)
	}
	if !artifactComponent.MatchString(stream) {
		return nil, "", fmt.Errorf("invalid artifact stream %q", stream)
	}
	dir := filepath.Join(d.Root, executionID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", fmt.Errorf("create artifact directory: %w", err)
	}
	path := filepath.Join(dir, stream+".log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("create artifact %s: %w", path, err)
	}
	relative, err := filepath.Rel(d.Root, path)
	if err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("relative artifact path: %w", err)
	}
	return file, filepath.ToSlash(relative), nil
}

// DiscardArtifacts is used for version probes and tests that do not need
// on-disk evidence.
type DiscardArtifacts struct{}

// Create implements Artifacts.
func (DiscardArtifacts) Create(string, string) (io.WriteCloser, string, error) {
	return nopWriteCloser{Writer: io.Discard}, "", nil
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
