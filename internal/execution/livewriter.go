package execution

import (
	"io"
	"strings"
	"sync"
)

// prefixLocks guards the per-destination mutexes used by liveWriter. Parallel
// executions write to the same terminal, so the mutex must be shared by every
// writer targeting that destination; a per-execution mutex would let lines
// from different processes interleave.
var prefixLocks sync.Map // io.Writer -> *sync.Mutex

func lockFor(dst io.Writer) *sync.Mutex {
	if mu, ok := prefixLocks.Load(dst); ok {
		return mu.(*sync.Mutex)
	}
	mu, _ := prefixLocks.LoadOrStore(dst, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// liveWriter serializes stdout and stderr when both are copied to the same
// live stream and swallows write failures so a closed terminal never aborts
// the process or its artifact capture.
//
// When prefix is set, every line is tagged with it so parallel executions
// remain attributable in the terminal.
type liveWriter struct {
	mu     *sync.Mutex
	dst    io.Writer
	prefix string
	// pending holds a partial line between Write calls so a prefix lands at
	// the start of each line even when the process writes in fragments.
	pending string
}

// newLiveWriter builds a writer whose lock is shared with every other writer
// targeting the same destination.
func newLiveWriter(dst io.Writer, prefix string) *liveWriter {
	return &liveWriter{mu: lockFor(dst), dst: dst, prefix: prefix}
}

// Write implements io.Writer.
func (w *liveWriter) Write(p []byte) (int, error) {
	if w.dst == nil {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	// Discard the error on purpose: the artifact files are the source of
	// truth and already received the same bytes.
	if w.prefix == "" {
		_, _ = w.dst.Write(p)
		return len(p), nil
	}
	text := w.pending + string(p)
	lines := strings.Split(text, "\n")
	// The last element is either "" (the write ended on a newline) or a
	// partial line kept for the next write.
	w.pending = lines[len(lines)-1]
	if len(lines) == 1 {
		return len(p), nil
	}
	var out strings.Builder
	for _, line := range lines[:len(lines)-1] {
		out.WriteString(w.prefix)
		out.WriteString(line)
		out.WriteString("\n")
	}
	_, _ = io.WriteString(w.dst, out.String())
	return len(p), nil
}

// Flush writes a trailing partial line, if any. The runner calls it when the
// process exits so the last unterminated line is not lost.
func (w *liveWriter) Flush() {
	if w == nil || w.dst == nil || w.prefix == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending == "" {
		return
	}
	_, _ = io.WriteString(w.dst, w.prefix+w.pending+"\n")
	w.pending = ""
}
