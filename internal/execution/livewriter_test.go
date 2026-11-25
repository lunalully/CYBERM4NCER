package execution

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// TestLiveWriterPrefixesEveryLine checks each streamed line is attributable.
func TestLiveWriterPrefixesEveryLine(t *testing.T) {
	var dst bytes.Buffer
	writer := newLiveWriter(&dst, "[3 nmap] ")
	if _, err := writer.Write([]byte("first\nsecond\n")); err != nil {
		t.Fatal(err)
	}
	want := "[3 nmap] first\n[3 nmap] second\n"
	if dst.String() != want {
		t.Fatalf("stream = %q, want %q", dst.String(), want)
	}
}

// TestLiveWriterKeepsPartialLines covers a process that writes a line in
// fragments: the prefix must appear once, at the start of the line.
func TestLiveWriterKeepsPartialLines(t *testing.T) {
	var dst bytes.Buffer
	writer := newLiveWriter(&dst, "[1 ffuf] ")
	for _, fragment := range []string{"par", "tial", " line", "\n"} {
		if _, err := writer.Write([]byte(fragment)); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := dst.String(), "[1 ffuf] partial line\n"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
}

// TestLiveWriterFlushesTrailingLine proves an unterminated last line is not
// lost when the process exits.
func TestLiveWriterFlushesTrailingLine(t *testing.T) {
	var dst bytes.Buffer
	writer := newLiveWriter(&dst, "[2 httpx] ")
	writer.Write([]byte("no newline here"))
	if dst.String() != "" {
		t.Fatalf("partial line written before flush: %q", dst.String())
	}
	writer.Flush()
	if got, want := dst.String(), "[2 httpx] no newline here\n"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
	// Flushing twice must not duplicate the line.
	writer.Flush()
	if strings.Count(dst.String(), "no newline here") != 1 {
		t.Fatalf("flush duplicated the line: %q", dst.String())
	}
}

// TestLiveWriterSharesLockAcrossExecutions is the regression test for the
// per-execution mutex: two writers on the same destination must serialize,
// otherwise parallel processes interleave their output.
func TestLiveWriterSharesLockAcrossExecutions(t *testing.T) {
	var dst bytes.Buffer
	first := newLiveWriter(&dst, "[a] ")
	second := newLiveWriter(&dst, "[b] ")
	if first.mu != second.mu {
		t.Fatal("writers targeting the same destination do not share a mutex")
	}
}

// TestLiveWriterConcurrentLinesStayWhole proves lines never tear under
// concurrent writes from many pseudo-processes.
func TestLiveWriterConcurrentLinesStayWhole(t *testing.T) {
	var dst bytes.Buffer
	const writers, lines = 8, 50
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			writer := newLiveWriter(&dst, "["+itoaForTest(id)+"] ")
			for i := 0; i < lines; i++ {
				// Two fragments per line widen the interleaving window.
				writer.Write([]byte("line-" + itoaForTest(i) + "-"))
				writer.Write([]byte("payload\n"))
			}
			writer.Flush()
		}(w)
	}
	wg.Wait()
	output := dst.String()
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		// Every line must be a whole record: prefix, "line-N-payload".
		if !strings.HasPrefix(line, "[") || !strings.Contains(line, "] line-") || !strings.HasSuffix(line, "-payload") {
			t.Fatalf("torn line: %q", line)
		}
	}
	if got := strings.Count(output, "-payload"); got != writers*lines {
		t.Fatalf("payload lines = %d, want %d", got, writers*lines)
	}
}

func itoaForTest(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
