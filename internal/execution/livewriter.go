package execution

import (
	"io"
	"sync"
)

// liveWriter serializes stdout and stderr when both are copied to the same
// live stream and swallows write failures so a closed terminal never aborts
// the process or its artifact capture.
type liveWriter struct {
	mu  sync.Mutex
	dst io.Writer
}

// Write implements io.Writer.
func (w *liveWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Discard the error on purpose: the artifact files are the source of
	// truth and already received the same bytes.
	_, _ = w.dst.Write(p)
	return len(p), nil
}
