package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// requireTerminal makes the hub believe it runs on an interactive shell so the
// target resolution path is reached without a real PTY. The returned func
// restores the previous probe.
func requireTerminal(t *testing.T) {
	t.Helper()
	previous := hubInteractive
	hubInteractive = func(*rootOptions) bool { return true }
	t.Cleanup(func() { hubInteractive = previous })
}

// hubTargetError runs "hub" with args on a non-interactive app and returns the
// error raised before any menu is drawn.
func hubTargetError(t *testing.T, args ...string) error {
	t.Helper()
	requireTerminal(t)
	var stdout, stderr bytes.Buffer
	root := NewRoot(Streams{Out: &stdout, Err: &stderr})
	root.SetArgs(append([]string{"hub"}, args...))
	return root.Execute()
}

// TestHubStartsWithoutTarget is the regression test for the hub being unable
// to open when no target is given, even though it asks for one in the session.
// The pre-fix command aborted here with "a target argument or --file is
// required"; after the fix it reaches the app, which exits cleanly on EOF.
func TestHubStartsWithoutTarget(t *testing.T) {
	err := hubTargetError(t)
	if err != nil && strings.Contains(err.Error(), "target") {
		t.Fatalf("hub refused to start without a target: %v", err)
	}
}

// TestHubReportsMissingTargetFileOnly covers real errors from --file: a
// missing file must still fail, while an empty one waits for the session.
func TestHubReportsMissingTargetFileOnly(t *testing.T) {
	requireTerminal(t)
	missing := filepath.Join(t.TempDir(), "absent.txt")
	var stdout, stderr bytes.Buffer
	root := NewRoot(Streams{Out: &stdout, Err: &stderr})
	root.SetArgs([]string{"hub", "--file", missing})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "read target file") {
		t.Fatalf("hub with a missing target file = %v", err)
	}
}

// TestHubAcceptsEmptyTargetFile checks that an existing but empty target file
// starts the session instead of aborting it.
func TestHubAcceptsEmptyTargetFile(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("# only comments\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := hubTargetError(t, "--file", empty)
	if err != nil && strings.Contains(err.Error(), "target") {
		t.Fatalf("hub refused an empty target file: %v", err)
	}
}

// TestAggressiveStillRequiresATarget locks the aggressive command contract:
// unlike the hub, it cannot run without a target.
func TestAggressiveStillRequiresATarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := NewRoot(Streams{Out: &stdout, Err: &stderr})
	root.SetArgs([]string{"aggressive"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("aggressive without a target = %v", err)
	}
}

// TestAggressiveTargetsCollects checks the collector used by both commands.
func TestAggressiveTargetsCollects(t *testing.T) {
	list := filepath.Join(t.TempDir(), "targets.txt")
	content := "10.0.0.5\n\n# comment line\napp.example.com # trailing\n10.0.0.5\n"
	if err := os.WriteFile(list, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := aggressiveTargets([]string{"first.example.com"}, list)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"first.example.com", "10.0.0.5", "app.example.com"}
	if len(targets) != len(want) {
		t.Fatalf("targets = %v, want %v", targets, want)
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("targets = %v, want %v", targets, want)
		}
	}
}

// TestHubCommandFlagsKeepContract keeps the documented hub flags working.
func TestHubCommandFlagsKeepContract(t *testing.T) {
	root := NewRoot(Streams{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}})
	var hub *cobra.Command
	for _, cmd := range root.Commands() {
		if cmd.Name() == "hub" {
			hub = cmd
		}
	}
	if hub == nil {
		t.Fatal("hub command is not registered")
	}
	for _, name := range []string{"scope", "mode", "level", "repeat", "timeout", "file", "wordlist", "userlist", "passlist"} {
		if hub.Flags().Lookup(name) == nil {
			t.Fatalf("hub flag --%s is missing", name)
		}
	}
}
