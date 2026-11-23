package aggressive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lunalully/cyberm4ncer/internal/execution"
	"github.com/lunalully/cyberm4ncer/internal/tools"
)

// StepResult is the outcome of one planned execution.
type StepResult struct {
	Step        Step
	Target      string
	ExecutionID string
	Status      execution.Status
	ExitCode    int
	Duration    time.Duration
	Error       string
	// Success is true when the command completed and, for credential
	// invocations, the success regex matched (when configured).
	Success bool
	// Skipped is set when the step could not be built or had no assets.
	Skipped bool
	// Discovered counts assets learned by this step.
	Discovered int
	// Matches lists success-regex matches.
	Matches []string
}

// Operation tells the executor what to record and where.
type Operation struct {
	// ID links executions to an operation row.
	ID string
	// DataDir is the root of the data directory.
	DataDir string
	// MaxReadBytes bounds how much of one artifact is parsed.
	MaxReadBytes int64
	// StepTimeout is the per-execution timeout.
	StepTimeout time.Duration
	// MaxSteps stops scheduling after this many recorded steps; 0 is
	// unlimited.
	MaxSteps int
	// Progress receives human-readable events; may be nil.
	Progress io.Writer
	// Stream receives the live stdout and stderr of every process in
	// addition to the artifact files; may be nil.
	Stream io.Writer
}

// Summary is the final report of a run.
type Summary struct {
	Steps      int          `json:"steps"`
	Succeeded  int          `json:"succeeded"`
	Failed     int          `json:"failed"`
	Skipped    int          `json:"skipped"`
	Discovered int          `json:"discovered"`
	Hosts      int          `json:"hosts"`
	Ports      int          `json:"ports"`
	Matches    []string     `json:"matches,omitempty"`
	Results    []StepResult `json:"results,omitempty"`
	// Truncated reports that MaxSteps stopped the run early.
	Truncated bool `json:"truncated,omitempty"`
}

// Executor runs a plan through the scoped execution function.
type Executor struct {
	// Execute must perform scope checks; the engine never calls a runner
	// directly.
	Execute ExecuteFunc
	// Registry resolves manifests for option flags.
	Registry *tools.Registry
}

// Run expands and executes the plan. Port-dependent steps run once per
// captured open port for each planned round.
func (e *Executor) Run(ctx context.Context, plan *Plan, op Operation) (Summary, error) {
	if e == nil || e.Execute == nil {
		return Summary{}, fmt.Errorf("executor requires a scoped execution function")
	}
	if plan == nil {
		return Summary{}, fmt.Errorf("plan is required")
	}
	captures := NewCaptures()
	base := baseContext(plan.Target)
	if base.Host != "" {
		captures.AddHost(base.Host)
	}
	report := func(format string, args ...any) {
		if op.Progress != nil {
			fmt.Fprintf(op.Progress, format+"\n", args...)
		}
	}
	maxRead := op.MaxReadBytes
	if maxRead <= 0 {
		maxRead = 8 << 20
	}
	artifactRoot := ""
	if op.DataDir != "" {
		artifactRoot = op.DataDir + "/artifacts"
	}

	summary := Summary{}
	limitReached := func() bool {
		if op.MaxSteps > 0 && summary.Steps >= op.MaxSteps {
			summary.Truncated = true
			report("max-steps %d reached; remaining invocations were not scheduled", op.MaxSteps)
			return true
		}
		return false
	}
	record := func(result StepResult) {
		summary.Results = append(summary.Results, result)
		summary.Steps++
		summary.Discovered += result.Discovered
		summary.Matches = append(summary.Matches, result.Matches...)
		switch {
		case result.Skipped:
			summary.Skipped++
		case result.Success:
			summary.Succeeded++
		default:
			summary.Failed++
		}
	}

	var expansions []Step
	attempts := 0
	for _, step := range plan.Steps {
		if step.Expand {
			expansions = append(expansions, step)
			continue
		}
		if limitReached() {
			break
		}
		// Each round of a discovery step re-scans and can find new assets.
		attempts++
		record(e.runStep(ctx, plan, step, captures, op, artifactRoot, maxRead, attempts, report))
	}
	// Port-dependent steps run once per captured open port for each planned
	// round.
	maxRound := 0
	for _, step := range expansions {
		if step.Round > maxRound {
			maxRound = step.Round
		}
	}
	for round := 1; round <= maxRound && !summary.Truncated; round++ {
		for _, step := range expansions {
			if step.Round != round {
				continue
			}
			if limitReached() {
				break
			}
			pairs := scopePairs(plan, captures)
			if len(pairs) == 0 {
				report("%s/%s: no open ports captured; skipped", step.Tool, step.Invocation)
				record(StepResult{Step: step, Skipped: true, Error: "no captured ports"})
				continue
			}
			// Every expansion must be an open port: a capture learned from
			// unrelated output must never trigger a connection attempt.
			pairs = filterOpen(captures, pairs)
			for _, pair := range pairs {
				if limitReached() {
					break
				}
				host, port := splitHostPortLoose(pair)
				_ = host
				expanded := step
				expanded.Target = pair
				expanded.Port = port
				expanded.TargetURL = ""
				attempts++
				record(e.runStep(ctx, plan, expanded, captures, op, artifactRoot, maxRead, attempts, report))
			}
		}
	}

	summary.Hosts = captures.HostCount()
	summary.Ports = captures.PortCount()
	if len(summary.Matches) > 0 {
		report("note: %d credential/success match(es) found", len(summary.Matches))
	}
	report("target %s finished: %d step(s) - %d ok, %d failed, %d skipped, %d discovered",
		plan.Target, summary.Steps, summary.Succeeded, summary.Failed, summary.Skipped, summary.Discovered)
	return summary, nil
}

// filterOpen keeps the pairs that were proven open by a scanner or probe.
func filterOpen(captures *Captures, pairs []string) []string {
	open := map[string]bool{}
	for _, pair := range captures.OpenHostPorts() {
		open[pair] = true
	}
	kept := pairs[:0]
	for _, pair := range pairs {
		if open[pair] {
			kept = append(kept, pair)
		}
	}
	return kept
}

// scopePairs returns captured host:port pairs that are inside the scope.
func scopePairs(plan *Plan, captures *Captures) []string {
	var allowed []string
	for _, pair := range captures.OpenHostPorts() {
		if checkAllowed(plan.Policy, pair) {
			allowed = append(allowed, pair)
		}
	}
	return allowed
}

func (e *Executor) runStep(ctx context.Context, plan *Plan, step Step, captures *Captures, op Operation, artifactRoot string, maxRead int64, attempt int, report func(string, ...any)) StepResult {
	if err := ctx.Err(); err != nil {
		report("[%d] CANCELED %s/%s: %v", attempt, step.Tool, step.Invocation, err)
		return StepResult{Step: step, Status: execution.StatusCanceled, Error: err.Error()}
	}
	target := strings.TrimSpace(step.Target)
	if target == "" {
		target = plan.Target
	}
	values := StepContext(step, "")
	values.Options = copiedValues(values.Options)
	values.Target = target
	if step.Port > 0 {
		// Expanded steps carry the host alone; the port lives separately.
		values.Port = step.Port
		values.HostPort = fmt.Sprintf("%s:%d", values.Host, step.Port)
	}
	spec := specFor(plan.Registry, step)
	scheme := parsedScheme(plan.TargetURL)
	// Service tools carry their conventional protocol port as a reviewed
	// option; the scope still checks that port below.
	if step.OptionValues[KeyDefaultPort] != "" {
		values.Options[KeyDefaultPort] = step.OptionValues[KeyDefaultPort]
	}
	// The port this step contacts and the form its tool expects.
	effectivePort := step.Port
	kind := targetKind(spec, step)
	urlOption := hasURLOption(step)
	if effectivePort == 0 && (kind == "hostport" || kind == "url" || urlOption) {
		effectivePort = values.Port
	}
	targetValue := targetArg(values.Host, effectivePort, kind, scheme)
	values.Target = targetValue
	values.Options[KeyTarget] = targetValue
	// URL tools take the full URL, including the operator's scheme and port.
	if kind == "url" || urlOption {
		urlValue := buildURLWithScheme(values.Host, effectivePort, scheme)
		for name := range step.OptionFlags {
			if strings.EqualFold(name, KeyURL) || strings.EqualFold(name, "url") {
				values.Options[name] = urlValue
			}
		}
	}
	// The operator's wordlist applies to every option of that name.
	if values.Options[KeyWordlist] != "" && step.OptionValues[KeyWordlist] == "" {
		adjusted := false
		for name := range step.OptionFlags {
			if name == KeyWordlist || step.OptionValues[name] != "" {
				continue
			}
			if strings.Contains(strings.ToLower(name), "wordlist") {
				if !adjusted {
					step.OptionValues = copiedValues(step.OptionValues)
					adjusted = true
				}
				step.OptionValues[name] = values.Options[KeyWordlist]
			}
		}
	}
	if missing := unresolvedServiceOptions(step, values); len(missing) > 0 {
		report("[%d] %s/%s: skipped, missing option(s) %s", attempt, step.Tool, step.Invocation, strings.Join(missing, ", "))
		return StepResult{Step: step, Target: target, Skipped: true, Error: "missing option: " + strings.Join(missing, ",")}
	}
	if op.DataDir != "" {
		key := sanitizePath(plan.Target)
		values.Out = fmt.Sprintf("%s/aggressive/%s/%s-%s/report", op.DataDir, key, step.Tool, step.Invocation)
		// Tools fail when their report directory is missing; create it first.
		if err := os.MkdirAll(filepath.Dir(values.Out), 0o700); err != nil {
			report("[%d] %s/%s: cannot create report directory: %v", attempt, step.Tool, step.Invocation, err)
			return StepResult{Step: step, Target: target, Skipped: true, Error: "create report directory: " + err.Error()}
		}
	}
	// Every address the command contacts is checked before the process
	// starts: the primary target plus any protocol address in the argv.
	for _, checked := range scopeChecks(step, values, kind, effectivePort, scheme, urlOption) {
		if !checkAllowed(plan.Policy, checked) {
			reason := guardReason(plan.Policy, checked)
			report("[%d] %s/%s: refused, %s", attempt, step.Tool, step.Invocation, reason)
			return StepResult{Step: step, Target: target, Skipped: true, Error: "scope denied: " + reason}
		}
	}
	// The log and audited target name the address the command contacts.
	scopeDisplay := targetValue
	if kind == "url" || urlOption {
		scopeDisplay = buildURLWithScheme(values.Host, effectivePort, scheme)
	} else if effectivePort > 0 {
		scopeDisplay = hostForURL(values.Host, effectivePort)
	} else if step.AllowConventionalPort > 0 {
		scopeDisplay = hostForURL(values.Host, step.AllowConventionalPort)
	}

	args := buildArgs(step, values)

	report("[%d] round %d %s/%s on %s -> %s", attempt, step.Round, step.Tool, step.Invocation, scopeDisplay, strings.Join(args, " "))
	result, err := e.Execute(ctx, execution.Request{
		Tool:              step.Tool,
		Args:              args,
		Target:            scopeDisplay,
		OperationID:       op.ID,
		Timeout:           op.StepTimeout,
		ExpectedExitCodes: step.Accepted,
		Stream:            op.Stream,
	})
	stepResult := StepResult{Step: step, Target: target}
	if err != nil {
		stepResult.Status = execution.StatusError
		stepResult.Error = err.Error()
		report("[%d] ERROR %s/%s on %s: %v", attempt, step.Tool, step.Invocation, scopeDisplay, err)
		return stepResult
	}

	stdoutPath, stderrPath := ArtifactPaths(artifactRoot, result.StdoutPath, result.StderrPath)
	stdout, _ := ReadArtifact(stdoutPath, maxRead)
	stderr, _ := ReadArtifact(stderrPath, maxRead)
	// Several tools write their findings to a report file instead of stdout.
	reported := ReadReport(OutputTarget(step.Args, values.Out), maxRead)

	stepResult.ExecutionID = result.ID
	stepResult.Status = result.Status
	stepResult.ExitCode = result.ExitCode
	stepResult.Duration = result.Duration
	stepResult.Error = result.Error
	stepResult.Success = result.Status == execution.StatusSuccess

	report("[%d] %s %s/%s on %s exit=%d duration=%s", attempt, outcomeLabel(result.Status),
		step.Tool, step.Invocation, scopeDisplay, result.ExitCode, result.Duration.Round(time.Millisecond))
	if result.Status != execution.StatusSuccess {
		if result.Error != "" {
			report("    reason: %s", result.Error)
		}
		for _, line := range previewLines(result.StderrPreview, result.StdoutPreview, 6) {
			report("    | %s", line)
		}
	}

	if step.Success != nil {
		combined := result.StdoutPreview + "\n" + result.StderrPreview + "\n" + stdout + "\n" + stderr
		if match := step.Success.FindString(combined); match != "" {
			stepResult.Matches = append(stepResult.Matches, match)
			report("    SUCCESS %s/%s on %s: %s", step.Tool, step.Invocation, scopeDisplay, match)
			stepResult.Success = true
		}
	}

	learned := ParseOutput(step.Tool, stdout+"\n"+result.StdoutPreview+"\n"+reported, stderr+"\n"+result.StderrPreview, values.Host)
	for _, host := range learned.Hosts {
		if captures.AddHost(host) {
			stepResult.Discovered++
			report("  + host %s", host)
		}
	}
	for _, port := range learned.Ports {
		if captures.AddPort(port.Host, port.Port) {
			stepResult.Discovered++
			report("  + port %s:%d", port.Host, port.Port)
		}
	}
	for _, url := range learned.URLs {
		if captures.AddURL(url) {
			stepResult.Discovered++
			report("  + url %s", url)
		}
	}
	if step.Produces {
		for _, url := range WebURLs(captures) {
			if captures.AddURL(url) {
				stepResult.Discovered++
				report("  + url %s", url)
			}
		}
	}
	return stepResult
}

// buildURL builds a default http URL for a host and optional port.
func buildURL(host string, port int) string {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	return buildURLWithScheme(host, port, scheme)
}

// buildURLWithScheme builds a URL for a host and optional port; an empty
// scheme means http.
func buildURLWithScheme(host string, port int, scheme string) string {
	if host == "" {
		return ""
	}
	if scheme != "https" {
		scheme = "http"
	}
	return scheme + "://" + hostForURL(host, port)
}

// buildArgs expands templates and appends reviewed option flags that are not
// already placed by a positional template.
func buildArgs(step Step, values Context) []string {
	type option struct{ name, flag, value string }
	var options []option
	for name, flag := range step.OptionFlags {
		// Engine-provided options (the target, the wordlist) fill their
		// reviewed flag; the target itself is only emitted once.
		value := step.OptionValues[name]
		if value == "" {
			value = values.Options[name]
		}
		options = append(options, option{name: name, flag: flag, value: value})
	}
	for i := 1; i < len(options); i++ {
		for j := i; j > 0 && options[j].name < options[j-1].name; j-- {
			options[j], options[j-1] = options[j-1], options[j]
		}
	}

	args := make([]string, 0, len(step.Args)+2*len(options))
	used := map[string]bool{}
	// A positional {{host}}, {{hostport}} or {{url}} is the target; the
	// reviewed target flag must not add it a second time.
	if hasTargetPlaceholder(step.Args) {
		used[KeyTarget] = true
	}
	argsEmitted := 0
	for _, arg := range step.Args {
		// A placeholder with no value (for example an optional wordlist) is
		// dropped instead of leaving an empty flag value.
		if !Resolved(arg, values) {
			for _, match := range placeholder.FindAllStringSubmatch(arg, -1) {
				used[strings.TrimSpace(match[1])] = true
			}
			if argsEmitted > 0 && isFlag(args[argsEmitted-1]) {
				args = args[:argsEmitted-1]
				argsEmitted--
			}
			continue
		}
		resolved := Resolve(arg, values)
		if strings.TrimSpace(resolved) == "" {
			continue
		}
		args = append(args, resolved)
		argsEmitted++
		for _, match := range placeholder.FindAllStringSubmatch(arg, -1) {
			used[strings.TrimSpace(match[1])] = true
		}
	}
	for _, option := range options {
		if used[option.name] {
			continue
		}
		value := option.value
		if value == "" {
			value = values.Options[option.name]
		} else if !Resolved(value, values) {
			// A reviewed value may reference the target (for example a
			// domain); without a value the option is not passed at all.
			continue
		}
		value = Resolve(value, values)
		if strings.TrimSpace(value) == "" {
			continue
		}
		if option.flag != "" {
			args = append(args, option.flag)
		}
		args = append(args, value)
	}
	return args
}

func sanitizePath(value string) string {
	replacer := strings.NewReplacer("/", "_", ":", "_", "*", "_", "\\", "_", "?", "_")
	return replacer.Replace(value)
}

func isScopeDenial(err error) bool {
	var denied *scopeDeniedError
	if errors.As(err, &denied) {
		return true
	}
	return strings.Contains(err.Error(), "scope denied")
}

// scopeDeniedError mirrors core.ScopeDeniedError without importing core.
type scopeDeniedError struct{ message string }

func (e *scopeDeniedError) Error() string { return e.message }

// parsedScheme returns "http" or "https" for a URL, or "" otherwise.
func parsedScheme(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return scheme
}

// unresolvedServiceOptions reports template values that are still missing
// once the engine has filled everything it can. A service tool without a
// port is not run: it would silently fall back to the protocol default and
// bypass the scope port check.
func unresolvedServiceOptions(step Step, values Context) []string {
	missing := unresolvedKeys(step.Args, values)
	for name := range step.OptionFlags {
		if name == KeyDefaultPort && strings.TrimSpace(values.Options[KeyDefaultPort]) == "" {
			missing = append(missing, KeyDefaultPort)
		}
	}
	return missing
}

// isFlag reports whether a token is a CLI flag rather than a value.
func isFlag(token string) bool {
	return strings.HasPrefix(token, "-") && len(token) > 1
}

// copiedValues returns a copy so per-step adjustments never mutate the plan.
func copiedValues(values map[string]string) map[string]string {
	copied := make(map[string]string, len(values)+1)
	for key, value := range values {
		copied[key] = value
	}
	return copied
}

// outcomeLabel renders one execution status for the live progress stream.
func outcomeLabel(status execution.Status) string {
	switch status {
	case execution.StatusSuccess:
		return "OK"
	case execution.StatusFailed:
		return "FAIL"
	case execution.StatusTimeout:
		return "TIMEOUT"
	case execution.StatusCanceled:
		return "CANCELED"
	default:
		return "ERROR"
	}
}

// previewLines condenses the first lines of stderr (falling back to stdout)
// so a failed attempt explains itself without dumping the full artifact.
func previewLines(stderr, stdout string, limit int) []string {
	text := strings.TrimSpace(stderr)
	if text == "" {
		text = strings.TrimSpace(stdout)
	}
	if text == "" || limit <= 0 {
		return nil
	}
	lines := make([]string, 0, limit)
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r\n"))
		if line == "" {
			continue
		}
		if utf8.RuneCountInString(line) > 240 {
			line = string([]rune(line)[:240]) + "..."
		}
		lines = append(lines, line)
		if len(lines) == limit {
			break
		}
	}
	return lines
}
