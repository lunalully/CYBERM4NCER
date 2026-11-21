package aggressive

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lunalully/cyberm4ncer/internal/execution"
	"github.com/lunalully/cyberm4ncer/internal/tools"
)

// fakeScripts maps a tool name to the shell snippet its fake binary runs.
var fakeScripts = map[string]string{}

// fakePerformer executes planned argv in a temp directory and counts calls. It
// stands in for core.ExecuteScoped in hermetic tests and enforces the same
// scope rule for the test targets.
type fakePerformer struct {
	calls atomic.Int32
	mu    sync.Mutex
	seen  []execution.Request
}

func (f *fakePerformer) requests() []execution.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]execution.Request(nil), f.seen...)
}

func (f *fakePerformer) run(ctx context.Context, req execution.Request) (execution.Result, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.seen = append(f.seen, req)
	f.mu.Unlock()
	result := execution.Result{ID: "exec_test", Tool: req.Tool, Status: execution.StatusSuccess}
	if req.Target != "" && !fakeScoped(req.Target) {
		return result, &scopeDeniedError{message: "scope denied: " + req.Target}
	}
	if len(req.Args) == 0 {
		return result, nil
	}
	// The reviewed argv starts with the tool name; run the fake script instead.
	argv := append([]string{"-c", fakeScripts[req.Tool]}, req.Args...)
	cmd := exec.CommandContext(ctx, "sh", argv...)
	output, err := cmd.CombinedOutput()
	result.StdoutPreview = string(output)
	if err != nil {
		result.Status = execution.StatusFailed
		result.Error = err.Error()
	}
	return result, nil
}

func fakeScoped(target string) bool {
	host := target
	if index := strings.LastIndex(target, ":"); index > 0 && !strings.HasSuffix(target, "]") {
		host = target[:index]
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "app.example.com" || strings.HasSuffix(host, ".example.com")
}

// fakeRegistry writes minimal manifests for shell stand-ins.
func fakeRegistry(t *testing.T, scripts map[string]string, extra map[string]string) *tools.Registry {
	t.Helper()
	dir := t.TempDir()
	for name, script := range scripts {
		if name == "scanner" {
			fakeScripts[name] = script
		} else {
			// Helpers other than the scanner still print something.
			fakeScripts[name] = "echo fake"
		}
		content := fmt.Sprintf(`name: %s
description: Fake tool for tests
category: network
homepage: https://example.com
documentation: https://example.com
license: MIT
binary: %s
min_version: 1.0.0
tested_version: 1.0.0
architectures: [any]
risk: medium
intrusive: false
capabilities: [test]
outputs: [text]
version_check:
  args: ["-c", "printf 'fake 1.0.0'"]
  regex: 'fake ([0-9.]+)'
install:
  - method: manual
notes: exported for tests
usage:
  target_mode: hostport
invocations:
  - name: scan
    mode: recon
    args: ["-c", %q, "fake", "{{target}}"]
    repeat: 2
  - name: banner
    mode: enum
    uses_captured_ports: true
    repeat: 2
`, name, name, script)
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	registry, err := tools.LoadFS(osDirFS(dir), ".")
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestExecutorLearnsPortsAndExpandsSteps(t *testing.T) {
	registry := fakeRegistry(t, map[string]string{
		"scanner": `for a in "$@"; do case "$a" in banner) echo "banner for $*"; return 0;; esac; done; echo "Discovered open port 22/tcp on 127.0.0.1"; echo "Discovered open port 8080/tcp on 127.0.0.1"; true`,
	}, nil)
	performer := &fakePerformer{}
	executor := &Executor{Execute: performer.run, Registry: registry}
	planner := &Planner{Registry: registry, Mode: Mode{Name: "all", Level: 5, RepeatQuota: 5, IncludeIntrusive: true}}
	plan, err := planner.Plan("127.0.0.1", mustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	var progress strings.Builder
	summary, err := executor.Run(context.Background(), plan, Operation{ID: "op_test", DataDir: t.TempDir(), MaxReadBytes: 4096, Progress: &progress})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Ports != 2 {
		t.Fatalf("ports = %d\n%s", summary.Ports, progress.String())
	}
	// Two scanner rounds plus two banner rounds against two ports each.
	if summary.Steps != 6 {
		t.Fatalf("steps = %d, want 6\n%s", summary.Steps, progress.String())
	}
	if !strings.Contains(progress.String(), "banner on 127.0.0.1:8080 -> ") || !strings.Contains(progress.String(), "banner for") {
		t.Fatalf("banner did not expand per port:\n%s", progress.String())
	}
	if !strings.Contains(progress.String(), "+ port 127.0.0.1:8080") {
		t.Fatalf("missing discovery log:\n%s", progress.String())
	}
	if performer.calls.Load() != 6 {
		t.Fatalf("executed %d commands, want 6", performer.calls.Load())
	}
}

func TestExecutorRefusesDeniedTarget(t *testing.T) {
	registry, err := tools.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	performer := &fakePerformer{}
	executor := &Executor{Execute: performer.run, Registry: registry}
	planner := &Planner{Registry: registry, Mode: DefaultMode()}
	plan, err := planner.Plan("https://app.example.com", mustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an asset captured outside the scope during a run.
	plan.Steps = []Step{{
		Tool:       "nmap",
		Invocation: "version-probe",
		Round:      1,
		Target:     "evil.invalid:22",
		Args:       []string{"-c", "true"},
	}}
	var progress strings.Builder
	summary, err := executor.Run(context.Background(), plan, Operation{Progress: &progress})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Skipped != 1 || summary.Succeeded != 0 || summary.Results[0].Error == "" {
		t.Fatalf("summary = %+v", summary)
	}
	// The scope check happens before the process starts.
	if performer.calls.Load() != 0 {
		t.Fatalf("executed %d commands for an out-of-scope asset", performer.calls.Load())
	}
	if !strings.Contains(progress.String(), "refused, no matching include rule") {
		t.Fatalf("refusal not reported:\n%s", progress.String())
	}
}

func osDirFS(dir string) fs.FS { return os.DirFS(dir) }

func TestExecutorHonoursMaxSteps(t *testing.T) {
	performer := &fakePerformer{}
	registry, err := tools.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	executor := &Executor{Execute: performer.run, Registry: registry}
	planner := &Planner{Registry: registry, Mode: DefaultMode()}
	plan, err := planner.Plan("https://app.example.com", mustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	var progress bytes.Buffer
	summary, err := executor.Run(context.Background(), plan, Operation{Progress: &progress, MaxSteps: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Truncated {
		t.Fatalf("summary not marked truncated: %+v", summary)
	}
	if summary.Steps != 2 || performer.calls.Load() != 2 {
		t.Fatalf("steps=%d calls=%d", summary.Steps, performer.calls.Load())
	}
	if !strings.Contains(progress.String(), "max-steps 2 reached") {
		t.Fatalf("progress missing limit notice:\n%s", progress.String())
	}
}

func TestURLToolsReceiveTargetFlag(t *testing.T) {
	registry, err := tools.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	planner := &Planner{Registry: registry, Mode: DefaultMode()}
	plan, err := planner.Plan("127.0.0.1", mustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	var httpxStep *Step
	for index := range plan.Steps {
		if plan.Steps[index].Tool == "httpx" {
			httpxStep = &plan.Steps[index]
			break
		}
	}
	if httpxStep == nil {
		t.Fatal("httpx is missing from the plan")
	}
	values := StepContext(*httpxStep, "")
	values.Target = httpxStep.Target
	values.Options[KeyTarget] = buildURL(values.Host, values.Port)
	values.Out = "/tmp/report"
	args := buildArgs(*httpxStep, values)
	found := false
	for index, arg := range args {
		if arg == "-u" && index+1 < len(args) && args[index+1] == "http://127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("httpx args lack -u URL: %v", args)
	}
	if strings.Contains(strings.Join(args, " "), "{{") {
		t.Fatalf("unresolved placeholder in args: %v", args)
	}
}

func TestBuildArgsUsesReviewedOptionValues(t *testing.T) {
	step := Step{
		Args:         []string{"-mc", "200"},
		OptionFlags:  map[string]string{"hostheader": "-H", "target": "-u", "wordlist": "-w"},
		OptionValues: map[string]string{"hostheader": "Host: FUZZ"},
	}
	values := Context{
		Host:    "127.0.0.1",
		Options: map[string]string{"target": "http://127.0.0.1/", "wordlist": "/tmp/w.txt"},
	}
	args := buildArgs(step, values)
	joined := strings.Join(args, "\x00")
	for _, want := range []string{"-H\x00Host: FUZZ", "-u\x00http://127.0.0.1/", "-w\x00/tmp/w.txt"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args lack %q: %v", want, args)
		}
	}
}

func TestMain(m *testing.M) {
	if mode := os.Getenv("FAKE_ARGV_MODE"); mode != "" {
		if log := os.Getenv("FAKE_ARGV_LOG"); log != "" {
			_ = os.WriteFile(log, []byte(strings.Join(os.Args[1:], " ")), 0o600)
		}
		fmt.Println("[22][ssh] host: 127.0.0.1 login: root password: toor")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestRunStepTargetFlagIsNotDuplicated(t *testing.T) {
	registry, err := tools.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	planner := &Planner{Registry: registry, Mode: DefaultMode()}
	plan, err := planner.Plan("127.0.0.1", mustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	performer := &fakePerformer{}
	executor := &Executor{Execute: performer.run, Registry: registry}
	for _, step := range plan.Steps {
		if step.Round != 1 {
			continue
		}
		one := *plan
		one.Steps = []Step{step}
		if _, err := executor.Run(context.Background(), &one, Operation{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, req := range performer.requests() {
		// The target appears exactly once, either alone or inside the
		// reviewed service URI (ssh://127.0.0.1:22), never twice.
		count := 0
		for _, arg := range req.Args {
			if strings.Contains(arg, "127.0.0.1") {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s: target appears %d times in %q", req.Tool, count, req.Args)
		}
		if strings.Contains(strings.Join(req.Args, " "), "{{") {
			t.Fatalf("%s: unresolved template in %q", req.Tool, req.Args)
		}
	}
}

func TestExecutorOnlyExpandsProvenOpenPorts(t *testing.T) {
	// A comment mentions a closed port; only the scanner line proves 8080.
	registry := fakeRegistry(t, map[string]string{
		"scanner": `for a in "$@"; do case "$a" in banner) echo "banner for $*"; return 0;; esac; done; echo "connecting to 127.0.0.1:9999"; echo "127.0.0.1:9999 closed"; echo "Discovered open port 8080/tcp on 127.0.0.1"; true`,
	}, nil)
	performer := &fakePerformer{}
	executor := &Executor{Execute: performer.run, Registry: registry}
	planner := &Planner{Registry: registry, Mode: Mode{Name: "all", Level: 5, RepeatQuota: 5, IncludeIntrusive: true}}
	plan, err := planner.Plan("127.0.0.1", mustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	var progress strings.Builder
	if _, err := executor.Run(context.Background(), plan, Operation{Progress: &progress}); err != nil {
		t.Fatal(err)
	}
	for _, req := range performer.requests() {
		if strings.HasSuffix(req.Target, ":9999") {
			t.Fatalf("closed port was contacted: %s\n%s", req.Target, progress.String())
		}
	}
	if !strings.Contains(progress.String(), "banner on 127.0.0.1:8080") {
		t.Fatalf("open port was not expanded:\n%s", progress.String())
	}
}
