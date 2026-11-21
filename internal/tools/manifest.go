package tools

import (
	"fmt"
	"regexp"
	"strings"
)

// Manifest describes a supported external tool. It is data, not an
// installer: installation is implemented and reviewed in Phase 3.
type Manifest struct {
	Name          string          `yaml:"name" json:"name"`
	Description   string          `yaml:"description" json:"description"`
	Category      string          `yaml:"category" json:"category"`
	Homepage      string          `yaml:"homepage" json:"homepage"`
	Documentation string          `yaml:"documentation" json:"documentation"`
	License       string          `yaml:"license" json:"license"`
	Binary        string          `yaml:"binary" json:"binary"`
	MinVersion    string          `yaml:"min_version" json:"min_version,omitempty"`
	TestedVersion string          `yaml:"tested_version" json:"tested_version,omitempty"`
	Architectures []string        `yaml:"architectures" json:"architectures"`
	Risk          string          `yaml:"risk" json:"risk"`
	Intrusive     bool            `yaml:"intrusive" json:"intrusive"`
	Capabilities  []string        `yaml:"capabilities" json:"capabilities"`
	Outputs       []string        `yaml:"outputs" json:"outputs"`
	VersionCheck  VersionCheck    `yaml:"version_check" json:"version_check"`
	Install       []InstallMethod `yaml:"install" json:"install"`
	Usage         Usage           `yaml:"usage,omitempty" json:"usage,omitempty"`
	Invocations   []Invocation    `yaml:"invocations,omitempty" json:"invocations,omitempty"`
	Dependencies  []string        `yaml:"dependencies" json:"dependencies,omitempty"`
	Notes         string          `yaml:"notes,omitempty" json:"notes,omitempty"`

	versionRegex *regexp.Regexp
}

// Usage describes how the tool addresses a target. The aggressive
// orchestrator uses it to build arguments and decide how to repeat a tool.
type Usage struct {
	// TargetMode is one of: url, host, hostport, cidr, free.
	//   url      - builds a URL from context (scheme, host, port, path)
	//   host     - receives a bare hostname or IP
	//   hostport - receives host:port (addresses a specific open port)
	//   cidr     - a host or range for network scanning
	//   free     - operator-supplied free-form arguments; not auto-targeted
	TargetMode string `yaml:"target_mode,omitempty" json:"target_mode,omitempty"`
	// TargetFlags are prepended to the target address, in order. They are
	// literal argv elements, for example ["-u"] or ["-host"].
	TargetFlags []string `yaml:"target_flags,omitempty" json:"target_flags,omitempty"`
	// SpeedArgs are the arguments that raise intensity, from 1 to 5.
	SpeedArgs map[int][]string `yaml:"speed_args,omitempty" json:"speed_args,omitempty"`
	// DefaultPorts limits the tool to these destination ports.
	DefaultPorts []int `yaml:"default_ports,omitempty" json:"default_ports,omitempty"`
	// URLPaths lists paths to try when TargetMode is url.
	URLPaths []string `yaml:"url_paths,omitempty" json:"url_paths,omitempty"`
}

// Invocation is one reviewed way of running a tool. The aggressive
// orchestrator expands an operation into these commands, repeating the ones
// marked Repeat.
type Invocation struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Mode is recon, enum, credential, vuln or search.
	Mode string `yaml:"mode" json:"mode"`
	// Args are the reviewed argument template. They run exactly as written
	// apart from templating; review them before adding an invocation.
	Args []string `yaml:"args" json:"args"`
	// Repeat is how many rounds the invocation runs against the same target
	// in full mode (1 disables repetition).
	Repeat int `yaml:"repeat,omitempty" json:"repeat,omitempty"`
	// UsesCapturedPorts runs one execution per open port found by
	// PortDiscovery.
	UsesCapturedPorts bool `yaml:"uses_captured_ports,omitempty" json:"uses_captured_ports,omitempty"`
	// PortDiscovery scans hosts discovered or in scope and fills the
	// captured-port list used by later invocations.
	PortDiscovery bool `yaml:"port_discovery,omitempty" json:"port_discovery,omitempty"`
	// ProducesURLs turns captured web ports into http/https URLs that later
	// invocations can use.
	ProducesURLs bool `yaml:"produces_urls,omitempty" json:"produces_urls,omitempty"`
	// AcceptExitCodes lists exit codes that mean "completed". Many tools
	// return non-zero when they simply find nothing; anything else counts
	// as an error. Defaults to [0].
	AcceptExitCodes []int `yaml:"accept_exit_codes,omitempty" json:"accept_exit_codes,omitempty"`
	// SuccessRegex marks output matching it as a real result (for example a
	// valid password line).
	SuccessRegex string `yaml:"success_regex,omitempty" json:"success_regex,omitempty"`
	// Options are name/value pairs appended as flag/value or bare values.
	Options []Option `yaml:"options,omitempty" json:"options,omitempty"`
}

// positionalAllowed reports whether an invocation already uses a positional
// placeholder such as "{{wordlist}}", so a bare option value is unambiguous.
func positionalAllowed(args []string) bool {
	for _, arg := range args {
		if strings.Contains(arg, "{{") {
			return true
		}
	}
	return false
}

// Option appends a reviewed flag (and optional value) to an invocation. A
// flag may be empty when the invocation uses a positional placeholder.
type Option struct {
	Name  string `yaml:"name" json:"name"`
	Flag  string `yaml:"flag" json:"flag"`
	Value string `yaml:"value,omitempty" json:"value,omitempty"`
}

var validTargetModes = map[string]bool{
	"url": true, "host": true, "hostport": true, "cidr": true, "free": true,
}

var validInvocationModes = map[string]bool{
	"recon": true, "enum": true, "credential": true, "vuln": true, "search": true,
}

// VersionCheck describes how to obtain the tool version.
type VersionCheck struct {
	Args  []string `yaml:"args" json:"args"`
	Regex string   `yaml:"regex" json:"regex"`
	// AcceptExitCodes lists exit codes after which the printed banner is
	// still a valid version source (for tools whose -h returns non-zero).
	AcceptExitCodes []int `yaml:"accept_exit_codes,omitempty" json:"accept_exit_codes,omitempty"`
}

// InstallMethod is declarative metadata. Phase 3 will implement reviewed
// installers per method with explicit consent.
type InstallMethod struct {
	Method     string `yaml:"method" json:"method"`
	Package    string `yaml:"package,omitempty" json:"package,omitempty"`
	Repository string `yaml:"repository,omitempty" json:"repository,omitempty"`
	Notes      string `yaml:"notes,omitempty" json:"notes,omitempty"`
}

var (
	toolNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,31}$`)
	binaryPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

var validCategories = map[string]bool{
	"recon": true, "web": true, "api": true, "network": true,
	"vulnerability": true, "osint": true, "reporting": true, "utility": true,
}

var validRisks = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

var validArchitectures = map[string]bool{
	"amd64": true, "arm64": true, "386": true, "arm": true, "any": true,
}

var validInstallMethods = map[string]bool{
	"go": true, "apt": true, "pipx": true, "cargo": true,
	"github_release": true, "manual": true,
}

var validOutputs = map[string]bool{
	"text": true, "json": true, "jsonl": true, "xml": true,
	"csv": true, "html": true, "sarif": true, "yaml": true,
}

// Compile validates the manifest and compiles its version regex.
func (m *Manifest) Compile() error {
	var errs []error
	if !toolNamePattern.MatchString(m.Name) {
		errs = append(errs, fmt.Errorf("invalid tool name %q", m.Name))
	}
	if strings.TrimSpace(m.Description) == "" {
		errs = append(errs, fmt.Errorf("%s: description is required", m.Name))
	}
	if !validCategories[m.Category] {
		errs = append(errs, fmt.Errorf("%s: invalid category %q", m.Name, m.Category))
	}
	if !strings.HasPrefix(m.Homepage, "https://") {
		errs = append(errs, fmt.Errorf("%s: homepage must be an https URL", m.Name))
	}
	if !binaryPattern.MatchString(m.Binary) {
		errs = append(errs, fmt.Errorf("%s: invalid binary %q", m.Name, m.Binary))
	}
	if len(m.Architectures) == 0 {
		errs = append(errs, fmt.Errorf("%s: architectures are required", m.Name))
	}
	for _, arch := range m.Architectures {
		if !validArchitectures[arch] {
			errs = append(errs, fmt.Errorf("%s: unsupported architecture %q", m.Name, arch))
		}
	}
	if !validRisks[m.Risk] {
		errs = append(errs, fmt.Errorf("%s: invalid risk %q", m.Name, m.Risk))
	}
	if m.VersionCheck.Args == nil {
		errs = append(errs, fmt.Errorf("%s: version_check.args is required (use [] for bare invocation)", m.Name))
	}
	for _, code := range m.VersionCheck.AcceptExitCodes {
		if code < 0 || code > 255 {
			errs = append(errs, fmt.Errorf("%s: version_check has invalid exit code %d", m.Name, code))
		}
	}
	if m.VersionCheck.Regex == "" {
		errs = append(errs, fmt.Errorf("%s: version_check.regex is required", m.Name))
	} else {
		compiled, err := regexp.Compile(m.VersionCheck.Regex)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid version regex: %w", m.Name, err))
		} else {
			m.versionRegex = compiled
		}
	}
	if m.MinVersion != "" {
		if _, ok := ParseSemVersion(m.MinVersion); !ok {
			errs = append(errs, fmt.Errorf("%s: invalid min_version %q", m.Name, m.MinVersion))
		}
	}
	if m.TestedVersion != "" {
		if _, ok := ParseSemVersion(m.TestedVersion); !ok {
			errs = append(errs, fmt.Errorf("%s: invalid tested_version %q", m.Name, m.TestedVersion))
		}
	}
	if len(m.Install) == 0 {
		errs = append(errs, fmt.Errorf("%s: at least one install method is required", m.Name))
	}
	for i, method := range m.Install {
		if !validInstallMethods[method.Method] {
			errs = append(errs, fmt.Errorf("%s: install[%d] has invalid method %q", m.Name, i, method.Method))
		}
	}
	for _, output := range m.Outputs {
		if !validOutputs[output] {
			errs = append(errs, fmt.Errorf("%s: unsupported output %q", m.Name, output))
		}
	}
	if m.Usage.TargetMode != "" && !validTargetModes[m.Usage.TargetMode] {
		errs = append(errs, fmt.Errorf("%s: invalid usage.target_mode %q", m.Name, m.Usage.TargetMode))
	}
	for speed, args := range m.Usage.SpeedArgs {
		if speed < 1 || speed > 5 {
			errs = append(errs, fmt.Errorf("%s: usage.speed_args level %d out of range 1-5", m.Name, speed))
		}
		for _, arg := range args {
			if arg == "" {
				errs = append(errs, fmt.Errorf("%s: usage.speed_args[%d] contains an empty argument", m.Name, speed))
			}
		}
	}
	for _, port := range m.Usage.DefaultPorts {
		if port < 1 || port > 65535 {
			errs = append(errs, fmt.Errorf("%s: usage.default_ports contains invalid port %d", m.Name, port))
		}
	}
	seen := make(map[string]bool)
	for i, inv := range m.Invocations {
		if !toolNamePattern.MatchString(inv.Name) {
			errs = append(errs, fmt.Errorf("%s: invocations[%d] has invalid name %q", m.Name, i, inv.Name))
		}
		if seen[inv.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate invocation %q", m.Name, inv.Name))
		}
		seen[inv.Name] = true
		if !validInvocationModes[inv.Mode] {
			errs = append(errs, fmt.Errorf("%s: invocation %q has invalid mode %q", m.Name, inv.Name, inv.Mode))
		}
		if len(inv.Args) == 0 && len(inv.Options) == 0 && m.Usage.TargetMode == "" {
			errs = append(errs, fmt.Errorf("%s: invocation %q has no args, options or usage target mode", m.Name, inv.Name))
		}
		if inv.Repeat < 0 || inv.Repeat > 1000 {
			errs = append(errs, fmt.Errorf("%s: invocation %q has repeat outside 0-1000", m.Name, inv.Name))
		}
		if inv.UsesCapturedPorts && m.Usage.TargetMode != "hostport" && m.Usage.TargetMode != "free" {
			errs = append(errs, fmt.Errorf("%s: invocation %q uses captured ports but target_mode is %q", m.Name, inv.Name, m.Usage.TargetMode))
		}
		if inv.UsesCapturedPorts && inv.PortDiscovery {
			errs = append(errs, fmt.Errorf("%s: invocation %q cannot both discover and consume ports", m.Name, inv.Name))
		}
		if inv.PortDiscovery && m.Usage.TargetMode != "cidr" && m.Usage.TargetMode != "host" {
			errs = append(errs, fmt.Errorf("%s: invocation %q performs port discovery but target_mode is %q", m.Name, inv.Name, m.Usage.TargetMode))
		}
		if (inv.SuccessRegex != "" || len(inv.AcceptExitCodes) > 0) && inv.Mode != "credential" {
			// Exit codes and success checks are meaningful for credential
			// attempts but are accepted for any mode: some tools signal
			// "nothing found" with a non-zero code.
		}
		if inv.SuccessRegex != "" {
			if _, err := regexp.Compile(inv.SuccessRegex); err != nil {
				errs = append(errs, fmt.Errorf("%s: invocation %q invalid success_regex: %w", m.Name, inv.Name, err))
			}
		}
		for _, code := range inv.AcceptExitCodes {
			if code < 0 || code > 255 {
				errs = append(errs, fmt.Errorf("%s: invocation %q has invalid exit code %d", m.Name, inv.Name, code))
			}
		}
		for j, option := range inv.Options {
			if option.Name == "" {
				errs = append(errs, fmt.Errorf("%s: invocation %q options[%d] requires a name", m.Name, inv.Name, j))
			}
			if option.Flag == "" && m.Usage.TargetMode != "cidr" && !positionalAllowed(inv.Args) {
				errs = append(errs, fmt.Errorf("%s: invocation %q options[%d] needs a flag unless the invocation uses positional placeholders", m.Name, inv.Name, j))
			}
		}
	}
	if len(errs) > 0 {
		messages := make([]string, 0, len(errs))
		for _, err := range errs {
			messages = append(messages, err.Error())
		}
		return fmt.Errorf("invalid manifest: %s", strings.Join(messages, "; "))
	}
	return nil
}

// ansiEscape strips terminal color/style sequences. Many tools (Python
// Click, Ruby gems) color their version banner, and the escape introducer is
// not printable text, so a match spanning it fails in RE2.
var ansiEscape = regexp.MustCompile("\\x1b\\[[0-9;?]*[ -/]*[@-~]")

// StripANSI removes ANSI escape sequences from captured output.
func StripANSI(output string) string { return ansiEscape.ReplaceAllString(output, "") }

// VersionFromOutput extracts a version from a tool's output.
func (m Manifest) VersionFromOutput(output string) string {
	if m.versionRegex == nil {
		return ""
	}
	match := m.versionRegex.FindStringSubmatch(StripANSI(output))
	if match == nil {
		return ""
	}
	if len(match) > 1 && match[1] != "" {
		return strings.TrimSpace(match[1])
	}
	return strings.TrimSpace(match[0])
}
