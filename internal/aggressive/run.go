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
	for _, step := range plan.Steps {
		if step.Expand {
			expansions = append(expansions, step)
			continue
		}
		if limitReached() {
			break
		}
		// Each round of a discovery step re-scans and can find new assets.
		record(e.runStep(ctx, plan, step, captures, op, artifactRoot, maxRead, report))
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
				record(e.runStep(ctx, plan, expanded, captures, op, artifactRoot, maxRead, report))
			}
		}
	}

	summary.Hosts = captures.HostCount()
	summary.Ports = captures.PortCount()
	if len(summary.Matches) > 0 {
		report("note: %d credential/success match(es) found", len(summary.Matches))
	}
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
		decision, err := plan.Policy.CheckTarget(pair)
		if err == nil && decision.Allowed {
			allowed = append(allowed, pair)
		}
	}
	return allowed
}

func (e *Executor) runStep(ctx context.Context, plan *Plan, step Step, captures *Captures, op Operation, artifactRoot string, maxRead int64, report func(string, ...any)) StepResult {
	if err := ctx.Err(); err != nil {
		return StepResult{Step: step, Status: execution.StatusCanceled, Error: err.Error()}
	}
	target := strings.TrimSpace(step.Target)
	if target == "" {
		target = plan.Target
	}
	values := StepContext(step, "")
	values.Target = target
	values.Options = copiedValues(values.Options)
	if step.Port > 0 {
		// Expanded steps carry the host alone; the port lives separately.
		values.Port = step.Port
		values.HostPort = fmt.Sprintf("%s:%d", values.Host, step.Port)
	}
	// Any remaining {{default_port}} placeholder receives the reviewed
	// conventional port of the step; the scope still checks that port below.
	if step.Port == 0 && values.Options[KeyDefaultPort] == "" && step.OptionValues[KeyDefaultPort] != "" {
		if len(unresolvedKeys(step.Args, valuesForDefaultPort(values, step.OptionValues[KeyDefaultPort]))) > 0 {
			values.Options[KeyDefaultPort] = step.OptionValues[KeyDefaultPort]
		}
	}
	if step.Port > 0 && step.Expand {
		// Expanded steps pass host and port separately; on a bare host the
		// port placeholder falls back to the listed default port.
		values.Options[KeyPort] = fmt.Sprint(values.Port)
	}
	// The reviewed target flag receives the address the tool will scan:
	// host:port (or the raw target) for host/CIDR/port tools, and the URL for
	// tools that were reviewed for one.
	targetArg := reviewedTargetPlaceholder(plan, step)
	// Addressed tools receive that address in their reviewed flag.
	toolURL := targetArg
	// The target is available to templates and option values from the start;
	// expanded steps may refine it once their port is known.
	if step.Port == 0 {
		values.Target = targetArg
		values.Options[KeyTarget] = targetArg
	}
	// Service tools (hydra, medusa) need the port passed once, as the value
	// of their reviewed port flag; the address itself stays bare. A step on a
	// bare host uses the conventional port of its protocol, which the scope
	// must allow (set further below, before the arguments are built).
	if step.Port > 0 {
		values.Options[KeyDefaultPort] = fmt.Sprint(step.Port)
	}
	// Tools whose target goes in a flag named after the address itself take
	// the address the step actually scans (a URL for URL targets).
	for name := range step.OptionFlags {
		if strings.EqualFold(name, KeyURL) || strings.EqualFold(name, "url") {
			values.Options[name] = targetArg
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

	// URLs are re-checked like any other asset; a URL built from a discovered
	// host must not escape the scope.
	scopeTarget := target
	if step.Port > 0 {
		// An expanded step addresses host:port; the port is never added twice.
		scopeTarget = fmt.Sprintf("%s:%d", values.Host, step.Port)
	} else if _, portInURL := parsePortInURL(toolURL); portInURL {
		scopeTarget = toolURL
	} else if scheme := parsedScheme(toolURL); scheme != "" {
		// A URL without an explicit port is checked with the port it implies
		// (80 for http, 443 for https), so port-restricted scopes still apply.
		implied := 80
		if scheme == "https" {
			implied = 443
		}
		scopeTarget = fmt.Sprintf("%s:%d", values.Host, implied)
	}
	if step.Port == 0 && step.AllowConventionalPort != 0 {
		// A service step planned on the conventional port of its protocol
		// contacts that port; the scope decides whether it may be tried.
		// The flag is added below, after this check.
		scopeTarget = fmt.Sprintf("%s:%d", values.Host, step.AllowConventionalPort)
		if decision, err := plan.Policy.CheckTarget(scopeTarget); err != nil || !decision.Allowed {
			reason := "invalid target"
			if err == nil {
				reason = decision.Reason
			}
			report("%s/%s: refused, %s", step.Tool, step.Invocation, reason)
			return StepResult{Step: step, Target: target, Skipped: true, Error: "scope denied: " + reason}
		}
		values.Options[KeyDefaultPort] = fmt.Sprint(step.AllowConventionalPort)
	}
	// Context options are filled in place: buildArgs and the validity check
	// both read this map.
	values.Options[KeyTarget] = targetArg
	values.Target = targetArg
	if missing := unresolvedServiceOptions(step, values); len(missing) > 0 {
		report("%s/%s: skipped, missing option(s) %s", step.Tool, step.Invocation, strings.Join(missing, ", "))
		return StepResult{Step: step, Target: target, Skipped: true, Error: "missing option: " + strings.Join(missing, ",")}
	}
	if op.DataDir != "" {
		key := sanitizePath(plan.Target)
		values.Out = fmt.Sprintf("%s/aggressive/%s/%s-%s/report", op.DataDir, key, step.Tool, step.Invocation)
		// Tools fail when their report directory is missing; create it first.
		if err := os.MkdirAll(filepath.Dir(values.Out), 0o700); err != nil {
			report("%s/%s: cannot create report directory: %v", step.Tool, step.Invocation, err)
			return StepResult{Step: step, Target: target, Skipped: true, Error: "create report directory: " + err.Error()}
		}
	}

	if decision, err := plan.Policy.CheckTarget(scopeTarget); err != nil || !decision.Allowed {
		reason := "invalid target"
		if err == nil {
			reason = decision.Reason
		}
		report("%s/%s: refused, %s", step.Tool, step.Invocation, reason)
		return StepResult{Step: step, Target: target, Skipped: true, Error: "scope denied: " + reason}
	}

	args := buildArgs(step, values)

	report("round %d %s/%s on %s -> %s", step.Round, step.Tool, step.Invocation, scopeTarget, strings.Join(args, " "))
	result, err := e.Execute(ctx, execution.Request{
		Tool:              step.Tool,
		Args:              args,
		Target:            scopeTarget,
		OperationID:       op.ID,
		Timeout:           op.StepTimeout,
		ExpectedExitCodes: step.Accepted,
	})
	stepResult := StepResult{Step: step, Target: target}
	if err != nil {
		stepResult.Status = execution.StatusError
		stepResult.Error = err.Error()
		report("ERROR %s/%s: %v", step.Tool, step.Invocation, err)
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

	if step.Success != nil {
		combined := result.StdoutPreview + "\n" + result.StderrPreview + "\n" + stdout + "\n" + stderr
		if match := step.Success.FindString(combined); match != "" {
			stepResult.Matches = append(stepResult.Matches, match)
			report("SUCCESS %s/%s on %s: %s", step.Tool, step.Invocation, scopeTarget, match)
			stepResult.Success = true
		}
	}
	if result.Status == execution.StatusSuccess && len(stepResult.Matches) == 0 {
		report("done %s/%s on %s (%s)", step.Tool, step.Invocation, scopeTarget, result.Duration.Round(time.Millisecond))
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

// parsePortInURL reports the explicit port of a URL, and whether one exists.
func parsePortInURL(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if port := parsed.Port(); port != "" {
		return port, true
	}
	return "", false
}

// reviewedTargetPlaceholder returns what the manifest's positional target
// placeholder resolves to: the URL form for URL tools and the bare host or
// host:port for the others.
func reviewedTargetPlaceholder(plan *Plan, step Step) string {
	var manifest tools.Manifest
	if plan.Registry != nil {
		manifest, _ = plan.Registry.Get(step.Tool)
	}
	host := baseContext(plan.Target).Host
	if expanded := strings.TrimSpace(step.Target); expanded != "" && step.Port > 0 {
		host = baseContext(expanded).Host
	}
	wantsURL := manifest.Usage.TargetMode == "url"
	for _, flag := range manifest.Usage.TargetFlags {
		if strings.Contains(flag, "{{url}}") {
			wantsURL = true
		}
	}
	if !wantsURL {
		for _, arg := range step.Args {
			for _, match := range placeholder.FindAllStringSubmatch(arg, -1) {
				switch strings.TrimSpace(match[1]) {
				case KeyURL:
					wantsURL = true
				case KeyHostPort:
					return fmt.Sprintf("%s:%d", host, step.Port)
				}
			}
		}
	}
	if wantsURL {
		// Keep the scheme the operator used; https on 443 otherwise.
		scheme := parsedScheme(plan.TargetURL)
		return buildURLWithScheme(host, step.Port, scheme)
	}
	return host
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

// valuesForDefaultPort copies the context with a candidate default port.
func valuesForDefaultPort(values Context, port string) Context {
	copied := values
	copied.Options = copiedValues(values.Options)
	copied.Options[KeyDefaultPort] = port
	return copied
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
