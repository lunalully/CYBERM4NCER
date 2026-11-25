package aggressive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lunalully/cyberm4ncer/internal/execution"
)

// concurrencyProbe records how many executions overlapped and the peak.
type concurrencyProbe struct {
	running atomic.Int32
	peak    atomic.Int32
	// delay is how long each fake execution pretends to work.
	delay time.Duration
}

func (p *concurrencyProbe) run(_ context.Context, req execution.Request) (execution.Result, error) {
	current := p.running.Add(1)
	defer p.running.Add(-1)
	for {
		peak := p.peak.Load()
		if current <= peak || p.peak.CompareAndSwap(peak, current) {
			break
		}
	}
	time.Sleep(p.delay)
	return execution.Result{ID: "exec_probe", Tool: req.Tool, Status: execution.StatusSuccess}, nil
}

// planWithSteps builds a plan whose steps are independent, so they can run in
// parallel without any capture in between.
func planWithSteps(t *testing.T, count int) *Plan {
	t.Helper()
	plan := &Plan{Target: "203.0.113.9", Mode: Mode{Name: "recon", Level: 1}}
	for i := 0; i < count; i++ {
		plan.Steps = append(plan.Steps, Step{
			Tool:       fmt.Sprintf("tool%02d", i),
			Invocation: "scan",
			Round:      1,
			Args:       []string{"scan"},
		})
	}
	return plan
}

// TestRunHonoursWorkers is the regression test for execution.workers being
// accepted by the configuration but never used: before this change the peak
// concurrency was always 1.
func TestRunHonoursWorkers(t *testing.T) {
	probe := &concurrencyProbe{delay: 60 * time.Millisecond}
	executor := &Executor{Execute: probe.run}
	plan := planWithSteps(t, 8)

	started := time.Now()
	summary, err := executor.Run(context.Background(), plan, Operation{Workers: 4, Progress: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if summary.Steps != 8 {
		t.Fatalf("steps = %d, want 8", summary.Steps)
	}
	if got := probe.peak.Load(); got < 2 {
		t.Fatalf("peak concurrency = %d, workers were not used", got)
	}
	if got := probe.peak.Load(); got > 4 {
		t.Fatalf("peak concurrency = %d, exceeded the workers limit of 4", got)
	}
	// Eight 60ms steps with four workers must beat the sequential 480ms.
	if elapsed > 400*time.Millisecond {
		t.Fatalf("run took %s; parallelism did not shorten the wall time", elapsed)
	}
	if summary.Workers != 4 {
		t.Fatalf("summary.workers = %d, want 4", summary.Workers)
	}
	if summary.Busy <= 0 || summary.Wall <= 0 {
		t.Fatalf("busy/wall not measured: busy=%s wall=%s", summary.Busy, summary.Wall)
	}
}

// TestRunWorkersOneStaysSequential locks the safe default: without workers the
// executor keeps the historical one-at-a-time behaviour.
func TestRunWorkersOneStaysSequential(t *testing.T) {
	probe := &concurrencyProbe{delay: 20 * time.Millisecond}
	executor := &Executor{Execute: probe.run}
	plan := planWithSteps(t, 4)
	if _, err := executor.Run(context.Background(), plan, Operation{Progress: io.Discard}); err != nil {
		t.Fatal(err)
	}
	if got := probe.peak.Load(); got != 1 {
		t.Fatalf("peak concurrency = %d, want 1 (sequential)", got)
	}
}

// TestRunMaxStepsIsNotOvershotByWorkers checks the campaign cap still holds
// when several steps start at once.
func TestRunMaxStepsIsNotOvershotByWorkers(t *testing.T) {
	probe := &concurrencyProbe{delay: 10 * time.Millisecond}
	executor := &Executor{Execute: probe.run}
	plan := planWithSteps(t, 20)
	summary, err := executor.Run(context.Background(), plan, Operation{Workers: 8, MaxSteps: 5, Progress: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Steps != 5 {
		t.Fatalf("steps = %d, want exactly 5 with max-steps 5", summary.Steps)
	}
	if !summary.Truncated {
		t.Fatal("summary did not report truncation")
	}
}

// TestRunPreservesResultOrder keeps the report stable regardless of finish
// order: results are stored by schedule order, not completion order.
func TestRunPreservesResultOrder(t *testing.T) {
	executor := &Executor{Execute: func(_ context.Context, req execution.Request) (execution.Result, error) {
		// The first step finishes last, so completion order is reversed.
		if req.Tool == "tool00" {
			time.Sleep(40 * time.Millisecond)
		}
		return execution.Result{ID: req.Tool, Tool: req.Tool, Status: execution.StatusSuccess}, nil
	}}
	plan := planWithSteps(t, 6)
	summary, err := executor.Run(context.Background(), plan, Operation{Workers: 6, Progress: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Results) != 6 {
		t.Fatalf("results = %d, want 6", len(summary.Results))
	}
	for i, result := range summary.Results {
		want := fmt.Sprintf("tool%02d", i)
		if result.Step.Tool != want {
			t.Fatalf("result %d = %s, want %s (order not preserved)", i, result.Step.Tool, want)
		}
	}
}

// TestCapturesAreThreadSafe proves the capture set survives concurrent writes
// from many workers; run with -race to catch the data race.
func TestCapturesAreThreadSafe(t *testing.T) {
	captures := NewCaptures()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 12; j++ {
				host := fmt.Sprintf("host%d.lab.internal", n)
				captures.AddHost(host)
				captures.AddPort(host, 8000+j)
				captures.AddURL(fmt.Sprintf("http://%s/%d", host, j))
				_ = captures.HostCount()
				_ = captures.PortCount()
				_ = captures.OpenHostPorts()
				_ = captures.URLList()
			}
		}(i)
	}
	wg.Wait()
	if got := captures.HostCount(); got != 16 {
		t.Fatalf("hosts = %d, want 16", got)
	}
	if got := captures.PortCount(); got != 16*12 {
		t.Fatalf("ports = %d, want %d", got, 16*12)
	}
}

// TestStreamIsPrefixedPerTool checks the live output of parallel steps stays
// attributable: every streamed line carries the attempt and tool.
func TestStreamIsPrefixedPerTool(t *testing.T) {
	registry := fakeRegistry(t, map[string]string{"scanner": "echo hello-from-scanner"}, nil)
	performer := &fakePerformer{}
	performer.allowAll = true
	executor := &Executor{Execute: performer.run, Registry: registry}
	planner := &Planner{Registry: registry, Mode: Mode{Name: "all", Level: 5, RepeatQuota: 1, IncludeIntrusive: true}}
	plan, err := planner.Plan("203.0.113.9", nil)
	if err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	streaming := func(ctx context.Context, req execution.Request) (execution.Result, error) {
		// Mirror the runner: the prefix belongs to the live stream, not to the
		// artifact, and goes in front of each line.
		if req.Stream != nil {
			for _, line := range []string{"hello-from-scanner", "second-line"} {
				io.WriteString(req.Stream, req.StreamPrefix+line+"\n")
			}
		}
		return performer.run(ctx, req)
	}
	executor.Execute = streaming
	if _, err := executor.Run(context.Background(), plan, Operation{Progress: io.Discard, Stream: &stream, Workers: 4}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(stream.String()), "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "[") || !strings.Contains(line, "scanner] ") {
			t.Fatalf("streamed line is not tagged with its tool: %q", line)
		}
	}
	if !strings.Contains(stream.String(), "hello-from-scanner") {
		t.Fatalf("stream missing tool output:\n%s", stream.String())
	}
}

// TestParallelRunKeepsEveryStepExecuted guards against dropped work when many
// steps run at once.
func TestParallelRunKeepsEveryStepExecuted(t *testing.T) {
	probe := &concurrencyProbe{delay: time.Millisecond}
	executor := &Executor{Execute: probe.run}
	plan := planWithSteps(t, 40)
	summary, err := executor.Run(context.Background(), plan, Operation{Workers: 7, Progress: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Steps != 40 || summary.Succeeded != 40 {
		t.Fatalf("summary = %d steps, %d ok; want 40/40", summary.Steps, summary.Succeeded)
	}
	seen := map[string]bool{}
	for _, result := range summary.Results {
		seen[result.Step.Tool] = true
	}
	if len(seen) != 40 {
		t.Fatalf("distinct tools = %d, want 40", len(seen))
	}
}
