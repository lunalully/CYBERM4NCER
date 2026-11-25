package aggressive

import (
	"net"
	"strconv"
	"strings"
	"sync"
)

// Captures holds everything learned while running a plan. Parallel workers
// record into the same set, so every access is guarded by mu.
type Captures struct {
	mu    sync.RWMutex
	hosts map[string]bool
	ports map[string]map[int]bool
	urls  map[string]bool
}

// NewCaptures returns an empty capture set.
func NewCaptures() *Captures {
	return &Captures{
		hosts: map[string]bool{},
		ports: map[string]map[int]bool{},
		urls:  map[string]bool{},
	}
}

// AddHost records a hostname or IP. It returns true when the host is new.
func (c *Captures) AddHost(host string) bool {
	host = normalizeHost(host)
	if host == "" || !validHost(host) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hosts[host] {
		return false
	}
	c.hosts[host] = true
	return true
}

// AddPort records an open port. It returns true when the port is new.
func (c *Captures) AddPort(host string, port int) bool {
	host = normalizeHost(host)
	if port < 1 || port > 65535 || host == "" || !validHost(host) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ports[host] == nil {
		c.ports[host] = map[int]bool{}
	}
	if c.ports[host][port] {
		return false
	}
	c.ports[host][port] = true
	return true
}

// AddURL records a discovered URL. It returns true when the URL is new.
func (c *Captures) AddURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.urls[raw] {
		return false
	}
	c.urls[raw] = true
	return true
}

// HostsList returns hosts in ascending order.
func (c *Captures) HostsList() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return sortedStrings(c.hosts)
}

// PortList returns the ports of a host in ascending order.
func (c *Captures) PortList(host string) []int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	set := c.ports[normalizeHost(host)]
	if len(set) == 0 {
		return nil
	}
	ports := make([]int, 0, len(set))
	for port := range set {
		ports = append(ports, port)
	}
	for i := 1; i < len(ports); i++ {
		for j := i; j > 0 && ports[j] < ports[j-1]; j-- {
			ports[j], ports[j-1] = ports[j-1], ports[j]
		}
	}
	return ports
}

// URLList returns URLs in ascending order.
func (c *Captures) URLList() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return sortedStrings(c.urls)
}

// OpenHostPorts returns "host:port" pairs for every captured port.
func (c *Captures) OpenHostPorts() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var pairs []string
	for _, host := range sortedStrings(c.hosts) {
		ports := c.ports[host]
		sorted := make([]int, 0, len(ports))
		for port := range ports {
			sorted = append(sorted, port)
		}
		sortInts(sorted)
		for _, port := range sorted {
			if strings.Contains(host, ":") {
				pairs = append(pairs, "["+host+"]:"+itoa(port))
				continue
			}
			pairs = append(pairs, host+":"+itoa(port))
		}
	}
	return pairs
}

// sortInts orders integers ascending; the sets are small, so insertion sort
// avoids the sort package at the call site.
func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// HostCount returns the number of captured hosts.
func (c *Captures) HostCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.hosts)
}

// PortCount returns the number of captured open ports.
func (c *Captures) PortCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	total := 0
	for _, set := range c.ports {
		total += len(set)
	}
	return total
}

// productDomains are vendor/toolkit sites that appear in banners, tracebacks
// and help output. They are documentation, never engagement assets.
var productDomains = map[string]bool{
	"nmap.org": true, "insecure.org": true, "seclists.org": true,
	"projectdiscovery.io": true, "github.com": true, "gitlab.com": true,
	"python.org": true, "pypi.org": true, "pypa.io": true, "ruby-lang.org": true,
	"golang.org": true, "go.dev": true, "kali.org": true, "offensive-security.com": true, "sqlmap.org": true,
	"foofus.net": true, "metasploit.com": true, "rapid7.com": true,
	"portswigger.net": true, "owasp.org": true,
	"pythonhosted.org": true, "readthedocs.io": true, "rust-lang.org": true,
	"example.com": true, "example.org": true, "example.net": true,
	"w3.org": true, "schemas.xmlsoap.org": true, "xmlsoap.org": true,
}

func isProductDomain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for domain := range productDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func validHost(host string) bool {
	if isProductDomain(host) {
		return false
	}
	if strings.ContainsAny(host, " /@\\?#") {
		return false
	}
	if !strings.Contains(host, ".") || strings.HasSuffix(host, "..") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	// Require a plausible top-level label so file names and stack frames
	// never become hosts.
	suffix := host[strings.LastIndex(host, ".")+1:]
	if _, err := strconv.Atoi(suffix); err == nil {
		return false
	}
	for _, r := range suffix {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	if len(suffix) < 2 {
		return false
	}
	for _, r := range suffix {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == ':':
		default:
			return false
		}
	}
	return !strings.Contains(host, "..")
}

func sortedStrings(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
	return values
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
