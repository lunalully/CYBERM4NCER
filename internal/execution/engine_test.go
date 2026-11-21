package execution

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryRecorder struct {
	mu       sync.Mutex
	starts   []Record
	finishes []Record
	fail     error
}

func (m *memoryRecorder) Start(_ context.Context, record Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	m.starts = append(m.starts, record)
	return nil
}

func (m *memoryRecorder) Finish(_ context.Context, record Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.finishes = append(m.finishes, record)
	return nil
}

func newTestRunner(t *testing.T, recorder Recorder, mutate func(*Options)) (*Runner, string) {
	t.Helper()
	root := t.TempDir()
	opts := Options{
		Workers:        2,
		DefaultTimeout: 2 * time.Second,
		MaxOutputBytes: 1 << 20,
		PreviewBytes:   1 << 16,
		Artifacts:      DirArtifacts{Root: root},
		Recorder:       recorder,
	}
	if mutate != nil {
		mutate(&opts)
	}
	runner, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return runner, root
}

func TestRunSuccessCapturesStreams(t *testing.T) {
	recorder := &memoryRecorder{}
	runner, root := newTestRunner(t, recorder, nil)
	result, err := runner.Run(context.Background(), Request{
		Tool: "sh",
		Args: []string{"-c", "printf 'hello'; printf 'oops' >&2"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusSuccess || result.ExitCode != 0 {
		t.Fatalf("status=%s exit=%d error=%s", result.Status, result.ExitCode, result.Error)
	}
	if result.StdoutPreview != "hello" || result.StderrPreview != "oops" {
		t.Fatalf("stdout=%q stderr=%q", result.StdoutPreview, result.StderrPreview)
	}
	stdout, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(result.StdoutPath)))
	if err != nil {
		t.Fatalf("read stdout artifact: %v", err)
	}
	if string(stdout) != "hello" {
		t.Fatalf("artifact = %q", stdout)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.starts) != 1 || len(recorder.finishes) != 1 {
		t.Fatalf("recorder starts=%d finishes=%d", len(recorder.starts), len(recorder.finishes))
	}
	if recorder.starts[0].Status != StatusRunning || recorder.finishes[0].Status != StatusSuccess {
		t.Fatalf("recorder statuses = %s / %s", recorder.starts[0].Status, recorder.finishes[0].Status)
	}
}

func TestRunNonZeroExit(t *testing.T) {
	runner, _ := newTestRunner(t, nil, nil)
	result, err := runner.Run(context.Background(), Request{
		Tool: "sh",
		Args: []string{"-c", "echo bad >&2; exit 3"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusFailed || result.ExitCode != 3 {
		t.Fatalf("status=%s exit=%d", result.Status, result.ExitCode)
	}
	if result.Error == "" || !strings.Contains(result.StderrPreview, "bad") {
		t.Fatalf("error=%q stderr=%q", result.Error, result.StderrPreview)
	}
}

func TestRunTimeout(t *testing.T) {
	recorder := &memoryRecorder{}
	runner, _ := newTestRunner(t, recorder, nil)
	start := time.Now()
	result, err := runner.Run(context.Background(), Request{
		Tool:    "sh",
		Args:    []string{"-c", "sleep 5"},
		Timeout: 150 * time.Millisecond,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusTimeout {
		t.Fatalf("status = %s, want timeout (error=%s)", result.Status, result.Error)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("timeout took too long: %s", elapsed)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.finishes) != 1 || recorder.finishes[0].Status != StatusTimeout {
		t.Fatalf("timeout was not recorded: %+v", recorder.finishes)
	}
}

func TestRunCancellation(t *testing.T) {
	runner, _ := newTestRunner(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	result, err := runner.Run(ctx, Request{
		Tool:    "sh",
		Args:    []string{"-c", "sleep 5"},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusCanceled {
		t.Fatalf("status = %s, want canceled (%s)", result.Status, result.Error)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("cancellation did not stop the process promptly")
	}
}

func TestRunMissingTool(t *testing.T) {
	runner, _ := newTestRunner(t, nil, nil)
	_, err := runner.Run(context.Background(), Request{Tool: "cyberm4ncer-tool-that-does-not-exist"})
	if !errors.Is(err, ErrToolNotFound) {
		t.Fatalf("error = %v, want ErrToolNotFound", err)
	}
}

func TestRunStartFailureIsRecorded(t *testing.T) {
	recorder := &memoryRecorder{}
	runner, _ := newTestRunner(t, recorder, nil)
	result, err := runner.Run(context.Background(), Request{
		Tool: "broken",
		Path: filepath.Join(t.TempDir(), "missing-binary"),
	})
	if err == nil {
		t.Fatal("expected start error")
	}
	if result.Status != StatusError {
		t.Fatalf("status = %s", result.Status)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.starts) != 1 || len(recorder.finishes) != 1 {
		t.Fatalf("start failure was not recorded: %+v", recorder)
	}
}

func TestRecorderStartFailureAbortsExecution(t *testing.T) {
	recorder := &memoryRecorder{fail: errors.New("database offline")}
	runner, _ := newTestRunner(t, recorder, nil)
	marker := filepath.Join(t.TempDir(), "should-not-exist")
	result, err := runner.Run(context.Background(), Request{
		Tool: "sh",
		Args: []string{"-c", "touch " + marker},
	})
	if err == nil {
		t.Fatal("expected recorder error")
	}
	if result.Status != StatusError {
		t.Fatalf("status = %s", result.Status)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("command ran despite recorder failure: %v", statErr)
	}
}

func TestOutputTruncation(t *testing.T) {
	runner, root := newTestRunner(t, nil, func(opts *Options) {
		opts.MaxOutputBytes = 10
		opts.PreviewBytes = 5
	})
	result, err := runner.Run(context.Background(), Request{
		Tool: "sh",
		Args: []string{"-c", "printf '0123456789ABCDEF'"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.StdoutPreview != "01234" {
		t.Fatalf("preview = %q", result.StdoutPreview)
	}
	if !result.StdoutTruncated || !result.StdoutPreviewTruncated {
		t.Fatalf("truncation flags = %t/%t", result.StdoutTruncated, result.StdoutPreviewTruncated)
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(result.StdoutPath)))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 10 {
		t.Fatalf("artifact length = %d, want 10", len(data))
	}
}

func TestRedactArgs(t *testing.T) {
	input := []string{
		"--token", "abc123",
		"--password=hunter2",
		"-H", "Authorization: Bearer topsecret",
		"http://user:pass@example.com/",
		"--normal", "value",
	}
	redacted := RedactArgs(input)
	joined := strings.Join(redacted, " ")
	for _, secret := range []string{"abc123", "hunter2", "topsecret", "pass@"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("redacted output leaked %q: %s", secret, joined)
		}
	}
	if input[0] != "--token" || input[1] != "abc123" {
		t.Fatal("RedactArgs mutated its input")
	}
	if !strings.Contains(joined, "--normal value") {
		t.Fatalf("non-sensitive args changed: %s", joined)
	}
}

func TestEngineRedactsStoredArgv(t *testing.T) {
	recorder := &memoryRecorder{}
	runner, _ := newTestRunner(t, recorder, nil)
	result, err := runner.Run(context.Background(), Request{
		Tool: "sh",
		Args: []string{"-c", "true", "--api-key", "secret-value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range result.Args {
		if arg == "secret-value" {
			t.Fatalf("result leaked secret: %v", result.Args)
		}
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	for _, arg := range recorder.starts[0].Argv {
		if arg == "secret-value" {
			t.Fatalf("recorder leaked secret: %v", recorder.starts[0].Argv)
		}
	}
}

func TestLimitWriter(t *testing.T) {
	var builder strings.Builder
	writer := newLimitWriter(&builder, 4)
	if n, err := writer.Write([]byte("abcdef")); err != nil || n != 6 {
		t.Fatalf("write = %d, %v", n, err)
	}
	if builder.String() != "abcd" || !writer.truncated {
		t.Fatalf("output = %q truncated=%t", builder.String(), writer.truncated)
	}
}

func TestKillProcessGroupHandlesNil(t *testing.T) {
	if err := killProcessGroup(nil); err != nil {
		t.Fatal(err)
	}
}
