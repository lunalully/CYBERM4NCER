package scope

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type ruleKind int

const (
	kindDomain ruleKind = iota
	kindIP
	kindCIDR
)

type matcher struct {
	kind       ruleKind
	text       string
	domain     string
	subdomains bool
	apex       bool
	ip         netip.Addr
	cidr       netip.Prefix
	exclude    bool
}

func compileRule(rule Rule, exclude bool) (matcher, error) {
	set := 0
	if strings.TrimSpace(rule.Domain) != "" {
		set++
	}
	if strings.TrimSpace(rule.IP) != "" {
		set++
	}
	if strings.TrimSpace(rule.CIDR) != "" {
		set++
	}
	if set != 1 {
		return matcher{}, fmt.Errorf("exactly one of domain, ip or cidr must be set")
	}

	result := matcher{exclude: exclude}
	switch {
	case rule.Domain != "":
		domain := strings.ToLower(strings.TrimSpace(rule.Domain))
		domain = strings.TrimSuffix(domain, ".")
		apex := true
		if strings.HasPrefix(domain, "*.") {
			domain = strings.TrimPrefix(domain, "*.")
			apex = false
		}
		if err := validateHostname(domain); err != nil {
			return matcher{}, fmt.Errorf("domain %q: %w", rule.Domain, err)
		}
		subdomains := rule.Subdomains || !apex
		result.kind = kindDomain
		result.domain = domain
		result.subdomains = subdomains
		result.apex = apex
		result.text = "domain:" + domain
		if !apex {
			result.text = "wildcard:*." + domain
		} else if subdomains {
			result.text = "domain:" + domain + " (+subdomains)"
		}
	case rule.IP != "":
		addr, err := netip.ParseAddr(strings.TrimSpace(rule.IP))
		if err != nil {
			return matcher{}, fmt.Errorf("ip %q: %w", rule.IP, err)
		}
		addr = addr.Unmap()
		result.kind = kindIP
		result.ip = addr
		result.text = "ip:" + addr.String()
	case rule.CIDR != "":
		prefix, err := netip.ParsePrefix(strings.TrimSpace(rule.CIDR))
		if err != nil {
			return matcher{}, fmt.Errorf("cidr %q: %w", rule.CIDR, err)
		}
		result.kind = kindCIDR
		result.cidr = prefix.Masked()
		result.text = "cidr:" + result.cidr.String()
	}
	return result, nil
}

// Decision is the result of evaluating a target against a policy.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Target  string `json:"target"`
	Kind    string `json:"kind"`
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason"`
	Port    int    `json:"port,omitempty"`
}

// CheckTarget evaluates a hostname, IP, CIDR or URL.
func (p *Policy) CheckTarget(target string) (Decision, error) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return Decision{}, fmt.Errorf("target is empty")
	}
	if strings.Contains(raw, "://") {
		return p.CheckURL(raw)
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return p.CheckCIDR(prefix)
	}

	host, port, err := splitTarget(raw)
	if err != nil {
		return Decision{}, err
	}
	decision, err := p.checkHost(host)
	if err != nil {
		return Decision{}, err
	}
	decision.Target = raw
	decision.Port = port
	if decision.Allowed && port != 0 && !p.portAllowed(port) {
		return Decision{
			Allowed: false,
			Target:  raw,
			Kind:    decision.Kind,
			Rule:    decision.Rule,
			Reason:  fmt.Sprintf("port %d is not allowed by scope", port),
			Port:    port,
		}, nil
	}
	return decision, nil
}

// CheckHost evaluates a bare hostname or IP literal.
func (p *Policy) CheckHost(host string) (Decision, error) {
	return p.checkHost(host)
}

// AllowsHost is a boolean convenience wrapper. Invalid hosts are denied.
func (p *Policy) AllowsHost(host string) bool {
	decision, err := p.checkHost(host)
	return err == nil && decision.Allowed
}

func (p *Policy) checkHost(raw string) (Decision, error) {
	host := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
	if host == "" {
		return Decision{}, fmt.Errorf("host is empty")
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		return p.checkIP(addr.Unmap()), nil
	}
	if err := validateHostname(host); err != nil {
		return Decision{}, fmt.Errorf("invalid host %q: %w", raw, err)
	}

	for _, rule := range p.excludes {
		if rule.matchesHost(host) {
			return Decision{
				Allowed: false,
				Target:  raw,
				Kind:    "host",
				Rule:    rule.text,
				Reason:  "excluded by " + rule.text,
			}, nil
		}
	}
	for _, rule := range p.includes {
		if rule.matchesHost(host) {
			return Decision{
				Allowed: true,
				Target:  raw,
				Kind:    "host",
				Rule:    rule.text,
				Reason:  "included by " + rule.text,
			}, nil
		}
	}
	return Decision{
		Allowed: false,
		Target:  raw,
		Kind:    "host",
		Reason:  "no matching include rule",
	}, nil
}

func (p *Policy) checkIP(addr netip.Addr) Decision {
	for _, rule := range p.excludes {
		if rule.matchesIP(addr) {
			return Decision{
				Allowed: false,
				Target:  addr.String(),
				Kind:    "ip",
				Rule:    rule.text,
				Reason:  "excluded by " + rule.text,
			}
		}
	}
	for _, rule := range p.includes {
		if rule.matchesIP(addr) {
			return Decision{
				Allowed: true,
				Target:  addr.String(),
				Kind:    "ip",
				Rule:    rule.text,
				Reason:  "included by " + rule.text,
			}
		}
	}
	return Decision{
		Allowed: false,
		Target:  addr.String(),
		Kind:    "ip",
		Reason:  "no matching include rule",
	}
}

// CheckCIDR verifies whether an entire CIDR is authorized. A partially
// covered range is denied: scanners must not touch addresses outside scope.
func (p *Policy) CheckCIDR(prefix netip.Prefix) (Decision, error) {
	target := prefix.Masked()
	decision := Decision{
		Target: target.String(),
		Kind:   "cidr",
	}

	// Any overlapping exclusion makes at least part of the target forbidden.
	for _, rule := range p.excludes {
		if rule.overlapsPrefix(target) {
			decision.Allowed = false
			decision.Rule = rule.text
			decision.Reason = "range overlaps exclusion " + rule.text
			return decision, nil
		}
	}

	covered := false
	overlap := false
	for _, rule := range p.includes {
		if rule.coversPrefix(target) {
			covered = true
			decision.Rule = rule.text
			break
		}
		if rule.overlapsPrefix(target) {
			overlap = true
		}
	}
	if covered {
		decision.Allowed = true
		decision.Reason = "range fully covered by " + decision.Rule
		return decision, nil
	}
	if overlap {
		decision.Reason = "range is only partially covered by scope"
	} else {
		decision.Reason = "no matching include rule"
	}
	return decision, nil
}

func (p *Policy) portAllowed(port int) bool {
	if len(p.ports) == 0 {
		return true
	}
	_, ok := p.ports[uint16(port)]
	return ok
}

func (m matcher) matchesHost(host string) bool {
	if m.kind != kindDomain {
		return false
	}
	if host == m.domain {
		return m.apex
	}
	return m.subdomains && strings.HasSuffix(host, "."+m.domain)
}

func (m matcher) matchesIP(addr netip.Addr) bool {
	switch m.kind {
	case kindIP:
		return m.ip == addr
	case kindCIDR:
		return m.cidr.Contains(addr)
	default:
		return false
	}
}

func (m matcher) overlapsPrefix(prefix netip.Prefix) bool {
	switch m.kind {
	case kindIP:
		return prefix.Contains(m.ip)
	case kindCIDR:
		return prefixesOverlap(prefix, m.cidr)
	default:
		return false
	}
}

func (m matcher) coversPrefix(prefix netip.Prefix) bool {
	return m.kind == kindCIDR && prefix.Bits() >= m.cidr.Bits() && m.cidr.Contains(prefix.Addr())
}

func prefixesOverlap(a, b netip.Prefix) bool {
	if a.Addr().BitLen() != b.Addr().BitLen() {
		return false
	}
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validateHostname(host string) error {
	if len(host) > 253 {
		return fmt.Errorf("hostname exceeds 253 bytes")
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return fmt.Errorf("empty label")
	}
	for _, r := range host {
		if r > 127 {
			return fmt.Errorf("non-ASCII hostnames must be provided in punycode (xn--) form")
		}
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !labelPattern.MatchString(label) {
			return fmt.Errorf("invalid label %q", label)
		}
	}
	return nil
}

func splitTarget(raw string) (host string, port int, err error) {
	// Bracketed IPv6 with optional port.
	if strings.HasPrefix(raw, "[") {
		if strings.Contains(raw, "]:") {
			host, portText, splitErr := net.SplitHostPort(raw)
			if splitErr != nil {
				return "", 0, splitErr
			}
			parsed, parseErr := parsePort(portText)
			if parseErr != nil {
				return "", 0, parseErr
			}
			return host, parsed, nil
		}
		if strings.HasSuffix(raw, "]") {
			return strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]"), 0, nil
		}
		return "", 0, fmt.Errorf("invalid bracketed host %q", raw)
	}
	if strings.Count(raw, ":") == 1 {
		host, portText, splitErr := net.SplitHostPort(raw)
		if splitErr != nil {
			return "", 0, splitErr
		}
		parsed, parseErr := parsePort(portText)
		if parseErr != nil {
			return "", 0, parseErr
		}
		return host, parsed, nil
	}
	return raw, 0, nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return port, nil
}

func sortPorts(ports []uint16) {
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
}
