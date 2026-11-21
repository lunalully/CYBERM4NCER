// Package aggressive expands a target into an exhaustive, repeated run of the
// reviewed tool invocations.
//
// The engine is explicit about what it does: it plans every command before
// running anything, repeats each invocation to the configured quota, chains
// discovered ports into later tools and records every execution in the shared
// database. It never builds shell strings and never invents arguments that are
// not in a tool manifest.
package aggressive

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/lunalully/cyberm4ncer/internal/execution"
	"github.com/lunalully/cyberm4ncer/internal/scope"
	"github.com/lunalully/cyberm4ncer/internal/tools"
)

// Mode selects how much of each tool is used.
type Mode struct {
	// Name is "recon", "enum", "vuln" or "all".
	Name string
	// Level is the intensity from 1 (gentle) to 5 (maximum).
	Level int
	// RepeatQuota caps how many times one invocation can run.
	RepeatQuota int
	// IncludeCredential enables hydra/medusa credential invocations.
	IncludeCredential bool
	// IncludeIntrusive enables tools whose manifest is marked intrusive.
	IncludeIntrusive bool
	// Wordlist overrides the default web wordlist when set.
	Wordlist string
	// UserList and PassList enable credential invocations.
	UserList string
	PassList string
}

// DefaultMode is the full aggressive run.
func DefaultMode() Mode {
	return Mode{Name: "all", Level: 5, RepeatQuota: 50, IncludeCredential: true, IncludeIntrusive: true}
}

// Template keys understood by the planner.
const (
	KeyTarget      = "target"
	KeyHost        = "host"
	KeyHostPort    = "hostport"
	KeyPort        = "port"
	KeyURL         = "url"
	KeyDefaultPort = "default_port"
	KeyOut         = "out"
	KeyWordlist    = "wordlist"
	KeyUserList    = "userlist"
	KeyPassList    = "passlist"
	KeyExtensions  = "extensions"
)

// DefaultWordlist is used by free-form web tools when none is supplied.
func DefaultWordlist() string { return "/usr/share/wordlists/dirb/common.txt" }

// DefaultExtensions is the reviewed extension list for directory brute force.
func DefaultExtensions() string { return ".php,.html,.txt,.bak,.zip,.json,.xml,.js" }

// ScopeDenied is returned when the target is outside the authorized scope.
var ScopeDenied = fmt.Errorf("target is outside the authorized scope")

// Context carries values substituted into invocation templates.
type Context struct {
	Target   string
	Host     string
	HostPort string
	Port     int
	URL      string
	// Out is the artifact directory reserved for the step.
	Out     string
	Options map[string]string
}

type contextKey struct{}

// WithContext attaches a template context to a context.Context.
func WithContext(ctx context.Context, value Context) context.Context {
	return context.WithValue(ctx, contextKey{}, value)
}

func contextFrom(ctx context.Context) (Context, bool) {
	value, ok := ctx.Value(contextKey{}).(Context)
	return value, ok
}

var placeholder = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)

// Resolve substitutes template placeholders. Unknown placeholders are left
// untouched so a typo shows up in the plan instead of silently vanishing.
func Resolve(template string, values Context) string {
	return placeholder.ReplaceAllStringFunc(template, func(match string) string {
		key := strings.TrimSpace(match[2 : len(match)-2])
		switch key {
		case KeyTarget:
			return values.Target
		case KeyHost:
			return values.Host
		case KeyHostPort:
			return values.HostPort
		case KeyPort:
			if values.Port > 0 {
				return fmt.Sprint(values.Port)
			}
			return ""
		case KeyURL:
			return values.URL
		case KeyOut:
			return values.Out
		}
		if values.Options != nil {
			if value, ok := values.Options[key]; ok {
				return value
			}
		}
		return match
	})
}

// unresolvedKeys lists placeholders that have no value.
func unresolvedKeys(args []string, values Context) []string {
	seen := map[string]bool{}
	for _, arg := range args {
		for _, match := range placeholder.FindAllStringSubmatch(arg, -1) {
			key := strings.TrimSpace(match[1])
			switch key {
			case KeyTarget, KeyHost, KeyHostPort, KeyURL, KeyOut:
				continue
			case KeyPort:
				if values.Port > 0 {
					continue
				}
			}
			if values.Options != nil {
				if _, ok := values.Options[key]; ok {
					continue
				}
			}
			seen[key] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// withoutKey removes one placeholder name from a missing list.
func withoutKey(keys []string, drop string) []string {
	kept := keys[:0]
	for _, key := range keys {
		if key != drop {
			kept = append(kept, key)
		}
	}
	return kept
}

// Skip records why a tool or invocation will not run.
type Skip struct {
	Tool       string `json:"tool"`
	Invocation string `json:"invocation,omitempty"`
	Reason     string `json:"reason"`
}

// Step is one planned process execution.
type Step struct {
	Tool       string
	Invocation string
	Mode       string
	Round      int
	Target     string
	TargetURL  string
	Port       int
	Args       []string
	Accepted   []int
	Success    *regexp.Regexp
	Produces   bool
	// Expand runs the step once per captured open port.
	Expand bool
	// Discovered ports/URLs feed later steps.
	OptionFlags map[string]string
	// OptionValues are fixed reviewed values for some options.
	OptionValues map[string]string
	// AllowConventionalPort is the protocol default a service step is
	// planned to contact when the target names no port. The engine checks
	// it against the scope before adding the port flag.
	AllowConventionalPort int
}

// MarshalJSON renders a step for human/JSON output. Map keys are sorted by
// encoding/json and the compiled regex is not exposed.
func (s Step) MarshalJSON() ([]byte, error) {
	type plain struct {
		Tool         string            `json:"tool"`
		Invocation   string            `json:"invocation"`
		Mode         string            `json:"mode"`
		Round        int               `json:"round"`
		Target       string            `json:"target"`
		Args         []string          `json:"args"`
		Accepted     []int             `json:"accept_exit_codes,omitempty"`
		Produces     bool              `json:"produces_urls,omitempty"`
		Expand       bool              `json:"per_open_port,omitempty"`
		OptionFlags  map[string]string `json:"option_flags,omitempty"`
		OptionValues map[string]string `json:"option_values,omitempty"`
		// ConventionalPort is the protocol default planned when the target
		// carries no explicit port.
		ConventionalPort int `json:"conventional_port,omitempty"`
	}
	return json.Marshal(plain{
		Tool: s.Tool, Invocation: s.Invocation, Mode: s.Mode, Round: s.Round,
		Target: s.Target, Args: s.Args, Accepted: s.Accepted, Produces: s.Produces,
		Expand: s.Expand, OptionFlags: s.OptionFlags, OptionValues: s.OptionValues,
		ConventionalPort: s.AllowConventionalPort,
	})
}

// Plan is the full command list for an operation.
type Plan struct {
	Target string
	Policy *scope.Policy
	// Registry resolves manifests when a step must be re-checked at run time.
	Registry *tools.Registry
	// TargetURL keeps the URL the operator typed (empty for bare targets) so
	// URL steps still use its scheme once they run on a host:port pair.
	TargetURL string
	Mode      Mode
	Steps     []Step
	Tools     []string
	Skips     []Skip
	Repeats   int
}

// Planner compiles manifests into steps.
type Planner struct {
	Registry *tools.Registry
	Mode     Mode
}

var webPorts = map[int]bool{
	80: true, 81: true, 443: true, 591: true, 3000: true, 5000: true, 7001: true,
	8000: true, 8008: true, 8080: true, 8081: true, 8088: true, 8443: true,
	8888: true, 9000: true, 9090: true, 9292: true, 9443: true, 10443: true,
}

// WebPorts returns the ports treated as HTTP services.
func WebPorts() map[int]bool {
	copied := make(map[int]bool, len(webPorts))
	for port := range webPorts {
		copied[port] = true
	}
	return copied
}

func (m Mode) allows(toolMode string) bool {
	if toolMode == "credential" && !m.IncludeCredential {
		return false
	}
	switch m.Name {
	case "", "all":
		return true
	case "vuln":
		return toolMode == "vuln" || toolMode == "enum" || toolMode == "recon"
	case "enum":
		return toolMode == "enum" || toolMode == "recon"
	default:
		return toolMode == m.Name
	}
}

func (m Mode) effectiveRepeat(invocation tools.Invocation) int {
	repeat := invocation.Repeat
	if repeat < 1 {
		repeat = 1
	}
	quota := m.RepeatQuota
	if quota < 1 {
		quota = 1
	}
	if repeat > quota {
		repeat = quota
	}
	return repeat
}

func (m Mode) speedArgs(manifest tools.Manifest) []string {
	level := m.Level
	for level > 0 {
		if args, ok := manifest.Usage.SpeedArgs[level]; ok {
			return append([]string(nil), args...)
		}
		level--
	}
	return nil
}

// Plan builds the steps for a target after validating its scope.
func (p *Planner) Plan(target string, policy *scope.Policy) (*Plan, error) {
	if p == nil || p.Registry == nil {
		return nil, fmt.Errorf("planner requires a tool registry")
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if policy == nil {
		return nil, ScopeDenied
	}
	decision, err := policy.CheckTarget(target)
	if err != nil {
		return nil, fmt.Errorf("evaluate scope for %q: %w", target, err)
	}
	if !decision.Allowed {
		return nil, fmt.Errorf("%w: %s", ScopeDenied, decision.Reason)
	}

	plan := &Plan{Target: target, Policy: policy, Mode: p.Mode, Registry: p.Registry, TargetURL: baseContext(target).URL}
	base := baseContext(target)
	if p.Mode.Wordlist != "" {
		base.Options[KeyWordlist] = p.Mode.Wordlist
		base.Options[KeyExtensions] = DefaultExtensions()
	}
	base.Options[KeyUserList] = p.Mode.UserList
	base.Options[KeyPassList] = p.Mode.PassList

	for _, manifest := range p.Registry.List() {
		if len(manifest.Invocations) == 0 {
			continue
		}
		if manifest.Intrusive && !p.Mode.IncludeIntrusive {
			plan.Skips = append(plan.Skips, Skip{Tool: manifest.Name, Reason: "intrusive tool disabled by mode"})
			continue
		}
		added := 0
		for _, invocation := range manifest.Invocations {
			if !p.Mode.allows(invocation.Mode) {
				if invocation.Mode == "credential" {
					plan.Skips = append(plan.Skips, Skip{Tool: manifest.Name, Invocation: invocation.Name, Reason: "credential testing disabled"})
				}
				continue
			}
			if manifest.Usage.TargetMode == "" {
				plan.Skips = append(plan.Skips, Skip{Tool: manifest.Name, Invocation: invocation.Name, Reason: "no reviewed target mode"})
				continue
			}
			if manifest.Usage.TargetMode == "free" && len(invocation.Options) == 0 {
				plan.Skips = append(plan.Skips, Skip{Tool: manifest.Name, Invocation: invocation.Name, Reason: "free-form tool requires explicit options"})
				continue
			}
			// A service step without a port in the target uses the
			// protocol default; it is planned with that port explicit.
			conventional := 0
			base.Options[KeyDefaultPort] = ""
			if port := atoi(fixedValue(invocation.Options, KeyDefaultPort)); port > 0 {
				conventional = port
				base.Options[KeyDefaultPort] = fmt.Sprint(port)
			}
			missing := unresolvedKeys(invocation.Args, base)
			if invocation.UsesCapturedPorts {
				// {{port}} is filled for each captured open port at run time.
				missing = withoutKey(missing, KeyPort)
			}
			if len(missing) > 0 {
				plan.Skips = append(plan.Skips, Skip{Tool: manifest.Name, Invocation: invocation.Name, Reason: "missing option(s): " + strings.Join(missing, ", ")})
				continue
			}
			args := append(p.Mode.speedArgs(manifest), invocation.Args...)
			flags := map[string]string{}
			fixed := map[string]string{}
			for _, option := range invocation.Options {
				flags[option.Name] = option.Flag
				if option.Value != "" {
					fixed[option.Name] = option.Value
				}
			}
			// Addressed tools receive their target through reviewed flags so
			// the argv order is explicit in the plan.
			if manifest.Usage.TargetMode != "" && manifest.Usage.TargetMode != "free" {
				// A reviewed positional placeholder already carries the
				// target; otherwise it goes in the first target flag. The
				// port of service tools is passed by their own option.
				flags[KeyTarget] = ""
				if len(manifest.Usage.TargetFlags) > 0 && manifest.Usage.TargetFlags[0] != "" {
					flags[KeyTarget] = manifest.Usage.TargetFlags[0]
				}
			}

			repeat := p.Mode.effectiveRepeat(invocation)
			for round := 1; round <= repeat; round++ {
				plan.Steps = append(plan.Steps, Step{
					Tool:                  manifest.Name,
					Invocation:            invocation.Name,
					Mode:                  invocation.Mode,
					Round:                 round,
					Target:                target,
					Args:                  args,
					Accepted:              append([]int(nil), invocation.AcceptExitCodes...),
					Success:               compileSuccess(invocation.SuccessRegex),
					Produces:              invocation.ProducesURLs,
					Expand:                invocation.UsesCapturedPorts,
					OptionFlags:           flags,
					OptionValues:          fixed,
					AllowConventionalPort: conventional,
				})
			}
			added++
			plan.Repeats += repeat
		}
		if added > 0 {
			plan.Tools = append(plan.Tools, manifest.Name)
		}
	}
	sort.Strings(plan.Tools)
	return plan, nil
}

// fixedValue returns the reviewed value of an option, if any.
func fixedValue(options []tools.Option, name string) string {
	for _, option := range options {
		if option.Name == name {
			return option.Value
		}
	}
	return ""
}

func compileSuccess(expr string) *regexp.Regexp {
	if strings.TrimSpace(expr) == "" {
		return nil
	}
	compiled, err := regexp.Compile(expr)
	if err != nil {
		return nil
	}
	return compiled
}

// baseContext derives template values for a raw target.
func baseContext(target string) Context {
	rawTarget := strings.TrimSpace(target)
	host := strings.ToLower(rawTarget)
	port := 0
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		if parsed, err := url.Parse(host); err == nil {
			host = strings.ToLower(parsed.Hostname())
			port = 443
			if parsed.Scheme == "http" {
				port = 80
			}
			if parsed.Port() != "" {
				port = atoi(parsed.Port())
			}
		}
	} else if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
		host = strings.ToLower(parsedHost)
		port = atoi(parsedPort)
	}
	url := ""
	if strings.HasPrefix(strings.ToLower(rawTarget), "http://") || strings.HasPrefix(strings.ToLower(rawTarget), "https://") {
		url = rawTarget
	}
	return Context{
		Target: rawTarget,
		Host:   host,
		Port:   port,
		URL:    url,
		Options: map[string]string{
			KeyWordlist:   DefaultWordlist(),
			KeyExtensions: DefaultExtensions(),
		},
	}
}

// Resolved reports whether every placeholder in a template has a value.
func Resolved(template string, values Context) bool {
	for _, match := range placeholder.FindAllStringSubmatch(template, -1) {
		name := strings.TrimSpace(match[1])
		if name == "" {
			return false
		}
		// Options are the only keys that can be legitimately absent (an
		// optional wordlist, a target flag); everything else must have a
		// value or the argument is meaningless.
		if values.Options != nil {
			if value, ok := values.Options[name]; ok && strings.TrimSpace(value) != "" {
				continue
			}
		}
		switch name {
		case KeyOut:
			continue
		case KeyTarget, KeyHost, KeyHostPort, KeyURL:
			if contextValue(values, name) != "" {
				continue
			}
		case KeyPort:
			if values.Port > 0 {
				continue
			}
		}
		return false
	}
	return true
}

// contextValue returns the direct (non-option) value of a template key.
func contextValue(values Context, key string) string {
	switch key {
	case KeyTarget:
		return values.Target
	case KeyHost:
		return values.Host
	case KeyHostPort:
		return values.HostPort
	case KeyURL:
		return values.URL
	}
	return ""
}

// StepContext builds template values for one step.
func StepContext(step Step, out string) Context {
	values := baseContext(step.Target)
	values.Out = out
	if step.Port > 0 {
		values.Port = step.Port
		values.HostPort = fmt.Sprintf("%s:%d", values.Host, step.Port)
	}
	if step.TargetURL != "" {
		values.URL = step.TargetURL
	}
	return values
}

// hostForURL renders host[:port] for URL use, bracketing IPv6 literals.
func hostForURL(host string, port int) string {
	rendered := host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		rendered = "[" + host + "]"
	}
	if port <= 0 {
		return rendered
	}
	return fmt.Sprintf("%s:%d", rendered, port)
}

// ExecuteFunc is the scoped execution entry point supplied by the core.
type ExecuteFunc func(ctx context.Context, req execution.Request) (execution.Result, error)
