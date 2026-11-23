package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestBareInvocationWithoutTerminalPrintsBannerAndHelp(t *testing.T) {
	stdout, _, err := runCLI(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "░▒▓██████▓") {
		t.Fatalf("startup banner missing:\n%s", stdout)
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Fatal("banner printed ANSI escapes to a non-terminal stream")
	}
	if !strings.Contains(stdout, "Available Commands:") || !strings.Contains(stdout, "aggressive") || !strings.Contains(stdout, "hub") {
		t.Fatalf("help text missing:\n%s", stdout)
	}
}

func TestUnknownArgumentIsReported(t *testing.T) {
	_, _, err := runCLI(t, "definitely-not-a-command")
	if err == nil {
		t.Fatal("expected an error for an unknown command")
	}
}

func TestHubCommandRefusesNonTerminal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := NewRoot(Streams{Out: &stdout, Err: &stderr})
	root.SetArgs([]string{"hub"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("hub without a terminal = %v", err)
	}
}

func TestHubCommandIsRegistered(t *testing.T) {
	root := NewRoot(Streams{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}})
	found := false
	for _, cmd := range root.Commands() {
		if cmd.Name() == "hub" {
			found = true
		}
	}
	if !found {
		t.Fatal("hub command is not registered")
	}
	if root.RunE == nil {
		t.Fatal("bare invocation has no interactive entry point")
	}
}
