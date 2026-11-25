package aggressive

import (
	"io"
	"sync"
)

// syncWriter serializes writes from parallel workers so progress lines never
// interleave in the middle of a line.
type syncWriter struct {
	mu  sync.Mutex
	dst io.Writer
}

// Write implements io.Writer.
func (w *syncWriter) Write(p []byte) (int, error) {
	if w.dst == nil {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dst.Write(p)
}
