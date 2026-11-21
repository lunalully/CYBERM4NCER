// Package scope implements the authorization boundary for every target the
// framework touches. It is independent from modules and execution.
//
// Security properties:
//   - hostnames are matched by DNS label boundaries, never by substring;
//   - exclusions always take precedence over inclusions;
//   - IP literals are matched only against IP/CIDR rules;
//   - HTTP redirects are re-checked before being followed;
//   - an authorization statement is mandatory.
package scope

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxScopeFileSize = 1 << 20

var projectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// File is the on-disk YAML representation of a scope.
type File struct {
	Version       int    `yaml:"version" json:"version"`
	Project       string `yaml:"project" json:"project"`
	Authorization string `yaml:"authorization" json:"authorization"`
	Includes      []Rule `yaml:"includes" json:"includes"`
	Excludes      []Rule `yaml:"excludes" json:"excludes"`
	Ports         []int  `yaml:"ports" json:"ports"`
}

// Rule is a single inclusion or exclusion.
type Rule struct {
	Domain     string `yaml:"domain,omitempty" json:"domain,omitempty"`
	Subdomains bool   `yaml:"subdomains,omitempty" json:"subdomains,omitempty"`
	IP         string `yaml:"ip,omitempty" json:"ip,omitempty"`
	CIDR       string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
	Comment    string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// Policy is a compiled scope.
type Policy struct {
	Project       string
	Authorization string
	includes      []matcher
	excludes      []matcher
	ports         map[uint16]struct{}
	path          string
}

// Summary describes a compiled policy for CLI output.
type Summary struct {
	Project       string   `json:"project"`
	Authorization string   `json:"authorization"`
	Includes      int      `json:"includes"`
	Excludes      int      `json:"excludes"`
	Domains       int      `json:"domains"`
	IPs           int      `json:"ips"`
	CIDRs         int      `json:"cidrs"`
	Ports         []uint16 `json:"ports"`
	SourcePath    string   `json:"source_path,omitempty"`
}

// Load reads and compiles a scope file.
func Load(path string) (*Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open scope file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxScopeFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read scope file: %w", err)
	}
	if len(data) > maxScopeFileSize {
		return nil, fmt.Errorf("scope file exceeds %d bytes", maxScopeFileSize)
	}
	policy, err := Parse(data)
	if err != nil {
		return nil, err
	}
	policy.path = path
	return policy, nil
}

// Parse compiles a YAML scope document.
func Parse(data []byte) (*Policy, error) {
	var file File
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse scope YAML: %w", err)
	}
	return compile(file)
}

func compile(file File) (*Policy, error) {
	var errs []error
	if file.Version != 1 {
		errs = append(errs, fmt.Errorf("scope version must be 1, got %d", file.Version))
	}
	if !projectPattern.MatchString(file.Project) {
		errs = append(errs, fmt.Errorf("invalid project %q (use letters, digits, dot, dash or underscore)", file.Project))
	}
	if strings.TrimSpace(file.Authorization) == "" {
		errs = append(errs, fmt.Errorf("authorization statement is required"))
	}
	if len(file.Includes) == 0 {
		errs = append(errs, fmt.Errorf("at least one include rule is required"))
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid scope: %w", joinErrors(errs))
	}

	policy := &Policy{
		Project:       file.Project,
		Authorization: strings.TrimSpace(file.Authorization),
		ports:         make(map[uint16]struct{}),
	}
	for i, rule := range file.Includes {
		compiled, err := compileRule(rule, false)
		if err != nil {
			errs = append(errs, fmt.Errorf("includes[%d]: %w", i, err))
			continue
		}
		policy.includes = append(policy.includes, compiled)
	}
	for i, rule := range file.Excludes {
		compiled, err := compileRule(rule, true)
		if err != nil {
			errs = append(errs, fmt.Errorf("excludes[%d]: %w", i, err))
			continue
		}
		policy.excludes = append(policy.excludes, compiled)
	}
	for _, port := range file.Ports {
		if port < 1 || port > 65535 {
			errs = append(errs, fmt.Errorf("invalid port %d", port))
			continue
		}
		policy.ports[uint16(port)] = struct{}{}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid scope: %w", joinErrors(errs))
	}
	return policy, nil
}

// Summary returns a serializable description of the policy.
func (p *Policy) Summary() Summary {
	summary := Summary{
		Project:       p.Project,
		Authorization: p.Authorization,
		Includes:      len(p.includes),
		Excludes:      len(p.excludes),
		SourcePath:    p.path,
	}
	for _, rule := range p.includes {
		switch rule.kind {
		case kindDomain:
			summary.Domains++
		case kindIP:
			summary.IPs++
		case kindCIDR:
			summary.CIDRs++
		}
	}
	for port := range p.ports {
		summary.Ports = append(summary.Ports, port)
	}
	sortPorts(summary.Ports)
	return summary
}

func joinErrors(errs []error) error {
	messages := make([]string, 0, len(errs))
	for _, err := range errs {
		messages = append(messages, err.Error())
	}
	return fmt.Errorf("%s", strings.Join(messages, "; "))
}
