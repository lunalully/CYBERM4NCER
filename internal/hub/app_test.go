package hub

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// fakeService is a test double for the Service contract: it records what the
// hub asked for and returns canned results. Production code never uses it.
type fakeService struct {
	planned   []string
	executed  int
	history   []string
	planError error
}

func (f *fakeService) Detect() (string, error) { return "1/1 tools installed and ready", nil }
func (f *fakeService) ToolSummary() (string, error) {
	return "1/1 ready", nil
}
func (f *fakeService) Tools() ([]string, error) {
	return []string{"nmap|installed|7.95|/usr/bin/nmap"}, nil
}
func (f *fakeService) ResolveScope(explicit string) (string, error) { return explicit, nil }
func (f *fakeService) ScopePath(view *PlanView) string              { return "" }
func (f *fakeService) History(limit int) ([]string, error)          { return f.history, nil }
func (f *fakeService) Plan(targets, scope, mode string, level, repeat int, wordlist, userlist, passlist string) (*PlanView, error) {
	if f.planError != nil {
		return nil, f.planError
	}
	f.planned = append(f.planned, targets+"|"+mode)
	return &PlanView{Target: targets, Mode: mode, Level: level, Tools: []string{"nmap"}, Steps: 2}, nil
}
func (f *fakeService) Execute(options Context, view *PlanView, out io.Writer) (SummaryView, error) {
	f.executed++
	return SummaryView{Steps: 2, Succeeded: 2, Elapsed: "1s", Notes: []string{"note"}}, nil
}

// fakePrinter records what the interface prints, never emitting colors.
type fakePrinter struct{ out io.Writer }

func (p fakePrinter) Infof(format string, args ...any) {
	_, _ = fmt.Fprintf(p.out, format+"\n", args...)
}
func (p fakePrinter) Warnf(format string, args ...any) {
	_, _ = fmt.Fprintf(p.out, "warning: "+format+"\n", args...)
}
func (p fakePrinter) Successf(format string, args ...any) {
	_, _ = fmt.Fprintf(p.out, format+"\n", args...)
}
func (p fakePrinter) Errorf(format string, args ...any) {
	_, _ = fmt.Fprintf(p.out, "error: "+format+"\n", args...)
}
func (p fakePrinter) Paint(token string) string { return token }
func (p fakePrinter) Reset(text string) string  { return text }
func (p fakePrinter) Table(headers []string, rows [][]string) {
	_, _ = fmt.Fprintln(p.out, strings.Join(headers, " "))
	for _, row := range rows {
		_, _ = fmt.Fprintln(p.out, strings.Join(row, " "))
	}
}

func newTestApp(t *testing.T, input string, service Service) (*App, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	ui := &UI{In: newReader(input), Out: out, Printer: fakePrinter{out: out}}
	app := &App{UI: ui, Service: service, Out: ui.Out}
	return app, out
}

func TestAppExitOnZero(t *testing.T) {
	app, out := newTestApp(t, "0\n", &fakeService{})
	if err := app.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "OPERATIONS HUB") || !strings.Contains(out.String(), "session closed") {
		t.Fatalf("unexpected screen:\n%s", out.String())
	}
}

func TestAppInvalidSelectionIsReportedAndSurvives(t *testing.T) {
	app, out := newTestApp(t, "zzz\n0\n", &fakeService{})
	if err := app.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `invalid selection "zzz"`) {
		t.Fatalf("invalid selection not reported:\n%s", out.String())
	}
}

func TestAppBackReturnsToHub(t *testing.T) {
	app, out := newTestApp(t, "3\nb\n0\n", &fakeService{})
	if err := app.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "WEB AND API SECURITY") {
		t.Fatal("web menu not shown")
	}
	if strings.Count(text, "OPERATIONS HUB") < 2 {
		t.Fatal("hub was not redrawn after back")
	}
}

func TestAppReconConfiguredAndDeclined(t *testing.T) {
	service := &fakeService{}
	app, out := newTestApp(t, "1\n127.0.0.1\n4\n30s\n1\nn\n2\n0\n", service)
	if err := app.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(service.planned) != 1 || service.planned[0] != "127.0.0.1|recon" {
		t.Fatalf("planned = %v", service.planned)
	}
	if service.executed != 0 {
		t.Fatal("a declined operation was executed")
	}
	text := out.String()
	if !strings.Contains(text, "planned: 2 invocations") {
		t.Fatalf("plan summary missing:\n%s", text)
	}
	if !strings.Contains(text, "timeout=30s") {
		t.Fatal("configured timeout not shown")
	}
}

func TestAppRunsAndReportsTruthfulSummary(t *testing.T) {
	service := &fakeService{}
	app, out := newTestApp(t, "1\n10.0.0.5\n1\ny\n2\n0\n", service)
	if err := app.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if service.executed != 1 {
		t.Fatalf("executed = %d", service.executed)
	}
	text := out.String()
	for _, want := range []string{"OPERATION FINISHED", "status: COMPLETED", "steps=2 succeeded=2", "note"} {
		if !strings.Contains(text, want) {
			t.Fatalf("summary misses %q:\n%s", want, text)
		}
	}
}

func TestAppPlanErrorIsShownNotFatal(t *testing.T) {
	service := &fakeService{planError: errInvalid}
	app, out := newTestApp(t, "1\n10.0.0.5\n1\nb\n0\n", service)
	if err := app.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "invalid target") {
		t.Fatalf("plan error not shown:\n%s", out.String())
	}
	if service.executed != 0 {
		t.Fatal("executed a plan that failed to build")
	}
}

func TestAppToolsAndHistoryMenus(t *testing.T) {
	service := &fakeService{history: []string{"2026-11-23 08:00|aggressive|10.0.0.5|all/l5|completed"}}
	app, out := newTestApp(t, "7\n9\n0\n", service)
	if err := app.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "nmap") || !strings.Contains(text, "completed") {
		t.Fatalf("tools/history output missing:\n%s", text)
	}
}

func TestMenuLookup(t *testing.T) {
	menu := Menu{Items: []Item{{Key: "1", Label: "ONE"}, {Key: "0", Label: "EXIT"}}}
	for _, input := range []string{"1", "01", "one"} {
		if item, ok := menu.Lookup(input); !ok || item.Label != "ONE" {
			t.Fatalf("%q not resolved", input)
		}
	}
	if _, ok := menu.Lookup("9"); ok {
		t.Fatal("unknown key resolved")
	}
}

func TestChooseEOFEndsTheHub(t *testing.T) {
	app, _ := newTestApp(t, "", &fakeService{})
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("EOF ended with %v", err)
	}
}

// newReader wraps a scripted answer as the input of the interface.
func newReader(input string) *bufio.Reader { return bufio.NewReader(strings.NewReader(input)) }

// errInvalid is the plan error used by the failure test.
var errInvalid = errors.New("invalid target")
