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
	Dependencies  []string        `yaml:"dependencies" json:"dependencies,omitempty"`
	Notes         string          `yaml:"notes,omitempty" json:"notes,omitempty"`

	versionRegex *regexp.Regexp
}

// VersionCheck describes how to obtain the tool version.
type VersionCheck struct {
	Args  []string `yaml:"args" json:"args"`
	Regex string   `yaml:"regex" json:"regex"`
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
	"csv": true, "html": true, "sarif": true,
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
	if len(m.VersionCheck.Args) == 0 {
		errs = append(errs, fmt.Errorf("%s: version_check.args is required", m.Name))
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
	if len(errs) > 0 {
		messages := make([]string, 0, len(errs))
		for _, err := range errs {
			messages = append(messages, err.Error())
		}
		return fmt.Errorf("invalid manifest: %s", strings.Join(messages, "; "))
	}
	return nil
}

// VersionFromOutput extracts a version from a tool's output.
func (m Manifest) VersionFromOutput(output string) string {
	if m.versionRegex == nil {
		return ""
	}
	match := m.versionRegex.FindStringSubmatch(output)
	if match == nil {
		return ""
	}
	if len(match) > 1 && match[1] != "" {
		return strings.TrimSpace(match[1])
	}
	return strings.TrimSpace(match[0])
}
