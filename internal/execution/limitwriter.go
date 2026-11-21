package execution

import (
	"io"
)

// limitWriter forwards at most remaining bytes to dst. It always reports
// the full input length so a truncated stream does not abort the process
// pipe; the truncation and any write failure are recorded for the caller.
type limitWriter struct {
	dst       io.Writer
	remaining int64
	truncated bool
	err       error
}

func newLimitWriter(dst io.Writer, limit int64) *limitWriter {
	return &limitWriter{dst: dst, remaining: limit}
}

func (w *limitWriter) Write(p []byte) (int, error) {
	total := len(p)
	if w.err != nil {
		return total, nil
	}
	if w.remaining <= 0 {
		w.truncated = true
		return total, nil
	}
	chunk := p
	if int64(len(chunk)) > w.remaining {
		chunk = chunk[:w.remaining]
		w.truncated = true
	}
	written, err := w.dst.Write(chunk)
	if err != nil {
		w.err = err
		return total, nil
	}
	if written != len(chunk) {
		w.err = io.ErrShortWrite
		return total, nil
	}
	w.remaining -= int64(written)
	if written < total {
		w.truncated = true
	}
	return total, nil
}
