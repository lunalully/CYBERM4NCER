package hub

import (
	"io"
	"strings"
)

// Service is what the hub can run. The CLI implements it on top of the core
// so the hub never touches the execution engine directly.
type Service interface {
	// Detect returns a one-line summary of installed tools.
	Detect() (string, error)
	// ToolSummary returns "installed/total" plus a one-line note.
	ToolSummary() (string, error)
	// Tools returns one row per tool: name, status, version, path.
	Tools() ([]string, error)
	// ResolveScope returns the scope file in use ("" when none).
	ResolveScope(explicit string) (string, error)
	// Plan builds the command plan for one target and mode.
	Plan(target, scopeFile, mode string, level, repeat int, wordlist, userlist, passlist string) (*PlanView, error)
	// Execute runs a plan, streaming its real progress to out.
	Execute(ctx Context, view *PlanView, out io.Writer) (SummaryView, error)
	// ScopePath returns the scope file a plan was built with.
	ScopePath(view *PlanView) string
	// History lists the most recent operations: one "|"-separated row each.
	History(limit int) ([]string, error)
}

// Context carries the execution options the operator chose.
type Context struct {
	Mode     string
	Level    int
	Repeat   int
	Timeout  string
	Wordlist string
	UserList string
	PassList string
}

// PlanView summarizes a built plan for the screens.
type PlanView struct {
	Target string
	Mode   string
	Level  int
	Repeat int
	Tools  []string
	Steps  int
	Skips  int
	// Engine is the underlying plan, owned by the CLI adapter.
	Engine any
}

// SummaryView is the final report of an operation.
type SummaryView struct {
	Steps      int
	Succeeded  int
	Failed     int
	Skipped    int
	Discovered int
	Hosts      int
	Ports      int
	Matches    []string
	Elapsed    string
	// Truncated reports that --max-steps stopped the run.
	Truncated bool
	// ResultsPath is the directory that holds this operation's reports.
	ResultsPath string
	// Notes are truthful remarks about the run (partial runs, missing
	// tools, interrupted work).
	Notes []string
}

// validTarget rejects obvious mistakes before a plan is built: an empty
// value, whitespace or shell metacharacters. The scope engine and the reviewed
// argv remain the authoritative validation.
func validTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || strings.ContainsAny(target, " \t\r\n;|&`$<>") {
		return false
	}
	return true
}

// Targets splits a comma or space separated answer into targets.
func Targets(answer string) []string {
	fields := strings.FieldsFunc(answer, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	seen := map[string]bool{}
	var targets []string
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" || seen[field] {
			continue
		}
		seen[field] = true
		targets = append(targets, field)
	}
	return targets
}

// KnownCategories lists everything the hub can really do today.
var KnownCategories = []Item{
	{Key: "1", Label: "RECONNAISSANCE", Detail: "passive and active discovery"},
	{Key: "2", Label: "NETWORK OPERATIONS", Detail: "port scanning and service detection"},
	{Key: "3", Label: "WEB AND API SECURITY", Detail: "web enumeration, TLS, API probing"},
	{Key: "4", Label: "VULNERABILITY ASSESSMENT", Detail: "nuclei, sqlmap, scripts"},
	{Key: "5", Label: "CREDENTIAL TESTING", Detail: "hydra and medusa"},
	{Key: "6", Label: "FULL AGGRESSIVE RUN", Detail: "every reviewed tool"},
	{Key: "7", Label: "TOOLS AND STATUS", Detail: "detect and describe external tools"},
	{Key: "8", Label: "CONFIGURATION AND SCOPE", Detail: "paths, config, scope file"},
	{Key: "9", Label: "HISTORY AND RESULTS", Detail: "operations recorded in the database"},
}
