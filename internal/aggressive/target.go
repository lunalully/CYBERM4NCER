package aggressive

import (
	"net/url"
	"sort"
	"strings"

	"github.com/lunalully/cyberm4ncer/internal/tools"
)

// targetPosition is where a reviewed manifest places the target.
type targetPosition int

const (
	// targetNone means the target is appended by the reviewed target flag
	// (or as the last positional argument when that flag is empty).
	targetNone targetPosition = iota
	// targetPositional means an argv placeholder such as {{host}} or {{url}}.
	targetPositional
	// targetFlag means a reviewed target flag such as -u or -d.
	targetFlag
)

// binarySpec is the target placement of one step, resolved from the manifest.
type binarySpec struct {
	tool string
	// position is where the target goes.
	position targetPosition
	// flag is the reviewed target flag (targetFlag only).
	flag string
	// placeholders are the target placeholders present in the argv.
	placeholders []string
	// mode is the manifest target mode (url, host, hostport, cidr, free).
	mode string
}

// specFor reads the reviewed target placement of a step from the registry.
func specFor(registry *tools.Registry, step Step) binarySpec {
	spec := binarySpec{tool: step.Tool}
	if registry != nil {
		if manifest, ok := registry.Get(step.Tool); ok {
			spec.mode = manifest.Usage.TargetMode
			if len(manifest.Usage.TargetFlags) > 0 {
				spec.flag = manifest.Usage.TargetFlags[0]
			}
		}
	}
	seen := map[string]bool{}
	for _, arg := range step.Args {
		for _, match := range placeholder.FindAllStringSubmatch(arg, -1) {
			name := strings.TrimSpace(match[1])
			if !isTargetPlaceholder(name) || seen[name] {
				continue
			}
			seen[name] = true
			spec.placeholders = append(spec.placeholders, name)
		}
	}
	sort.Strings(spec.placeholders)
	switch {
	case len(spec.placeholders) > 0:
		spec.position = targetPositional
	case spec.flag != "":
		spec.position = targetFlag
	}
	return spec
}

// isTargetPlaceholder reports whether a template key carries the target.
func isTargetPlaceholder(name string) bool {
	switch name {
	case KeyHost, KeyHostPort, KeyURL, "host:port":
		return true
	}
	return false
}

// hasTargetPlaceholder reports whether the argv names the target itself.
func hasTargetPlaceholder(args []string) bool {
	for _, arg := range args {
		for _, match := range placeholder.FindAllStringSubmatch(arg, -1) {
			if isTargetPlaceholder(strings.TrimSpace(match[1])) {
				return true
			}
		}
	}
	return false
}

// placeholderKind returns host, hostport or url for a target placeholder.
func placeholderKind(name string) string {
	switch name {
	case KeyURL:
		return "url"
	case KeyHostPort, "host:port":
		return "hostport"
	}
	return "host"
}

// targetKind returns how the step hands the target to its tool.
func targetKind(spec binarySpec, step Step) string {
	for _, name := range spec.placeholders {
		if placeholderKind(name) == "url" {
			return "url"
		}
	}
	if len(spec.placeholders) > 0 {
		return placeholderKind(spec.placeholders[0])
	}
	if spec.mode == "url" {
		return "url"
	}
	if spec.mode == "hostport" {
		return "hostport"
	}
	if hasURLOption(step) {
		return "url"
	}
	return "host"
}

// hasURLOption reports whether the reviewed invocation takes a URL option
// (ffuf -u, gobuster dir -u); those always receive a full URL.
func hasURLOption(step Step) bool {
	for name := range step.OptionFlags {
		if strings.EqualFold(name, KeyURL) || strings.EqualFold(name, "url") {
			return true
		}
	}
	return false
}

// targetArg renders the reviewed target argument for an address.
func targetArg(host string, port int, kind, scheme string) string {
	switch kind {
	case "url":
		return buildURLWithScheme(host, port, scheme)
	case "hostport":
		if port <= 0 {
			return host
		}
		return hostForURL(host, port)
	}
	return host
}

// impliedPort is the port a URL uses when it names none.
func impliedPort(scheme string) int {
	if strings.EqualFold(scheme, "https") {
		return 443
	}
	return 80
}

// scopeChecks lists the addresses one reviewed command contacts, rendered
// from the very argv it will execute. A tool that passes host and port in
// separate arguments, or names several protocol addresses, is checked for
// each of them before the process starts.
func scopeChecks(step Step, values Context, kind string, port int, scheme string, urlOption bool) []string {
	seen := map[string]bool{}
	var checks []string
	add := func(host string, candidate int) {
		host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
		if host == "" {
			return
		}
		rendered := host
		if candidate > 0 {
			rendered = hostForURL(host, candidate)
		}
		if seen[rendered] {
			return
		}
		seen[rendered] = true
		checks = append(checks, rendered)
	}
	if port == 0 {
		if kind == "url" || urlOption {
			port = impliedPort(scheme)
		}
		if step.AllowConventionalPort > 0 {
			port = step.AllowConventionalPort
		}
	}
	add(values.Host, port)
	// The argv may name additional addresses (ssh://host:22, host:port).
	for _, arg := range step.Args {
		rendered := Resolve(arg, values)
		for _, raw := range urlPattern.FindAllString(rendered, -1) {
			parsed, err := url.Parse(raw)
			if err != nil || parsed.Hostname() == "" {
				continue
			}
			candidate := atoi(parsed.Port())
			if candidate == 0 {
				candidate = impliedPort(parsed.Scheme)
			}
			add(parsed.Hostname(), candidate)
		}
		for _, raw := range hostPortPattern.FindAllString(rendered, -1) {
			host, candidate := splitHostPortLoose(raw)
			add(host, candidate)
		}
	}
	return checks
}

// requestTarget is the target recorded for an execution: the address the
// command actually contacts.
func requestTarget(display string) string {
	return display
}
