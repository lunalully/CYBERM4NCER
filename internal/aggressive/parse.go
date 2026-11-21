package aggressive

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	urlPattern = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)
	// bareURLPattern matches a URL that fills the whole token, so trailing
	// sentence punctuation never reaches the parser.
	bareURLPattern = regexp.MustCompile(`^https?://[^\s]+$`)
	// hostPortPattern matches host:port tokens in plain-text tool output,
	// including bracketed IPv6 addresses.
	hostPortPattern = regexp.MustCompile(`(\[[0-9a-fA-F:]+\]:[0-9]{1,5})|((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}:[0-9]{1,5})|((?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5})`)
	// sourceLocationPattern matches "file.rb:1421" in stack traces; those are
	// not network assets and must never be captured as hosts.
	sourceLocationPattern = regexp.MustCompile(`[A-Za-z0-9_./-]+\.(?:rb|py|go|js|ts|sh|pl|php|conf):[0-9]+$`)
	// nmapPortPattern matches "80/tcp open http".
	nmapPortPattern = regexp.MustCompile(`^\s*(\d{1,5})/(?:tcp|udp)\s+open\b`)
	// onHostPattern matches masscan-style "port 22/tcp on 10.0.0.1".
	onHostPattern = regexp.MustCompile(`(?i)port\s+(\d{1,5})/(?:tcp|udp)\s+on\s+([0-9a-zA-Z.:\[\]-]+)`)
	// plainPortPattern matches "port 80/tcp" inside sentences.
	plainPortPattern = regexp.MustCompile(`(?i)port\s+(\d{1,5})/(?:tcp|udp)`)
	// bracketedPortPattern matches hydra/medusa "[22][ssh]".
	bracketedPortPattern = regexp.MustCompile(`^\[(\d{1,5})\]\[`)
)

// Learned is the set of assets discovered in one tool output.
type Learned struct {
	Hosts []string
	Ports []HostPort
	URLs  []string
}

// HostPort is one discovered open port.
type HostPort struct {
	Host string
	Port int
}

// OutputTarget is the report path configured by an invocation, derived from
// the {{out}} placeholder and its flag.
func OutputTarget(args []string, outDir string) string {
	if outDir == "" {
		return ""
	}
	for _, arg := range args {
		if !strings.Contains(arg, "{{out}}") {
			continue
		}
		value := strings.TrimSpace(arg)
		for _, prefix := range []string{"--log-json=", "--jsonfile=", "-oJ="} {
			if strings.HasPrefix(value, prefix) {
				value = strings.TrimPrefix(value, prefix)
				break
			}
		}
		for _, prefix := range []string{"-o", "--output", "-oJ", "--jsonfile"} {
			if value == prefix {
				continue
			}
			if strings.HasPrefix(value, prefix+"=") {
				value = strings.TrimPrefix(value, prefix+"=")
				break
			}
		}
		path := strings.ReplaceAll(value, "{{out}}", outDir)
		path = strings.TrimSpace(strings.Trim(path, `"'`))
		if path == "" || !strings.HasPrefix(path, outDir) {
			return ""
		}
		return path
	}
	return ""
}

// ReadReport reads a report file or the files of a report directory, capped
// at maxBytes in total.
func ReadReport(path string, maxBytes int64) string {
	if path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return ""
		}
		var builder strings.Builder
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			content, _ := ReadArtifact(filepath.Join(path, entry.Name()), maxBytes)
			builder.WriteString(content)
			builder.WriteString("\n")
		}
		return builder.String()
	}
	content, _ := ReadArtifact(path, maxBytes)
	return content
}

// ParseOutput extracts hosts, ports and URLs from any supported tool output.
//
// Parsers are permissive because the engine only needs assets, not semantics.
// Port lines without a host name are attached to defaultHost.
func ParseOutput(tool, stdout, stderr, defaultHost string) Learned {
	seenHosts := map[string]bool{}
	seenPorts := map[string]bool{}
	seenURLs := map[string]bool{}
	seenHostURL := map[string]bool{}
	learned := Learned{}
	help := looksLikeHelpOutput(stdout + "\n" + stderr)
	// Host discovery is only trusted from tools that actually discover
	// hosts; web scanners mostly echo their own flags in errors.
	addHost := func(host string) {
		if help {
			return
		}
		host = normalizeHost(host)
		if host == "" || seenHosts[host] {
			return
		}
		seenHosts[host] = true
		learned.Hosts = append(learned.Hosts, host)
	}
	addPort := func(host string, port int) {
		host = normalizeHost(host)
		if host == "" || port < 1 || port > 65535 {
			return
		}
		key := host + ":" + fmt.Sprint(port)
		if seenPorts[key] {
			return
		}
		seenPorts[key] = true
		learned.Ports = append(learned.Ports, HostPort{Host: host, Port: port})
	}
	addURL := func(raw string) {
		if help {
			return
		}
		raw = strings.TrimRight(strings.TrimSpace(raw), ".,);'\"")
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return
		}
		if isProductDomain(parsed.Hostname()) || !validHost(parsed.Hostname()) {
			return
		}
		if seenURLs[raw] {
			return
		}
		seenURLs[raw] = true
		learned.URLs = append(learned.URLs, raw)

		if !seenHostURL[parsed.Hostname()] {
			seenHostURL[parsed.Hostname()] = true
			addHost(parsed.Hostname())
		}
		if parsed.Port() != "" {
			addPort(parsed.Hostname(), atoi(parsed.Port()))
		}
	}

	// Host discovery is only credited to tools that actually discover hosts;
	// web scanners mostly echo their own flags and URLs in errors.
	discovery := addHost
	if !discoversHosts(tool) {
		discovery = func(string) {}
	}
	for _, text := range []string{stdout, stderr} {
		scanLines(text, func(line string) {
			parseLine(line, defaultHost, discovery, addPort, addURL)
		})
	}
	return learned
}

// hostDiscoveryTools return real hosts, not URLs seen in their own output.
var hostDiscoveryTools = map[string]bool{
	"nmap": true, "masscan": true, "naabu": true, "rustscan": true,
	"subfinder": true, "amass": true, "dnsx": true, "gobuster": true,
	"ffuf": false, "httpx": true, "nxc": true, "enum4linux-ng": true,
	"netcat": true, "nc": true, "telnet": true, "nuclei": true,
}

func discoversHosts(tool string) bool {
	return hostDiscoveryTools[strings.ToLower(tool)]
}

// looksLikeHelpOutput detects a command that only printed usage information
// (for example because the operator-supplied wordlist was missing).
func looksLikeHelpOutput(output string) bool {
	for _, line := range splitLines(output) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Usage:") || strings.HasPrefix(trimmed, "USAGE:") ||
			strings.HasPrefix(trimmed, "Usage of ") || strings.HasPrefix(trimmed, "Usage for ") {
			return true
		}
	}
	return false
}

func parseLine(line, defaultHost string, addHost func(string), addPort func(string, int), addURL func(string)) {
	line = strings.TrimSpace(stripANSI(line))
	trimmed := strings.TrimSpace(strings.TrimLeft(line, "*|-+> "))
	if trimmed == "" {
		return
	}
	// JSON is recognised before the prose filters so that braces and quotes
	// in structured findings are never mistaken for banner art.
	if trimmed[0] == '{' || strings.HasPrefix(trimmed, "[{") {
		parseJSON(trimmed, addHost, addPort, addURL)
		return
	}
	if isToolHelpLine(line) || isProseAboutSite(trimmed) || isBannerArt(trimmed) {
		return
	}
	// A bare URL line is always a candidate asset.
	if bareURLPattern.MatchString(trimmed) {
		addURL(trimmed)
		return
	}
	// Tools name hosts explicitly; "on HOST" and "Discovered open port"
	// lines are the only prose shapes trusted for host/port discovery.
	if match := openPortOnHostPattern.FindStringSubmatch(trimmed); match != nil {
		addPort(normalizeHost(match[2]), atoi(match[1]))
		return
	}
	// Hydra/medusa results: "[22][ssh] host: 10.0.0.5 login: admin ...".
	if match := credentialHostPattern.FindStringSubmatch(trimmed); match != nil {
		if port := atoi(match[1]); port > 0 && port < 65536 {
			addPort(normalizeHost(match[2]), port)
		}
		return
	}
	// Open ports always belong to the host being scanned. Addresses seen in
	// banners (nameservers, help screens, vulnerability text) are not ports.
	if match := nmapPortPattern.FindStringSubmatch(trimmed); match != nil {
		if defaultHost != "" {
			addPort(defaultHost, atoi(match[1]))
		}
		return
	}
	if strings.Contains(trimmed, "://") {
		for _, raw := range urlPattern.FindAllString(trimmed, -1) {
			addURL(raw)
		}
	}
}

// helpPrefixes marks usage/help output. Those lines describe flags and
// examples, not discovered assets, and must never feed the capture set.
var helpPrefixes = []string{
	"Usage", "usage:", "USAGE", "Example", "example", "Examples", "Options",
	"OPTIONS", "Flags", "FLAGS", "Commands", "COMMANDS", "Syntax", "SYNTAX",
	"See ", "see ", "Documentation", "Homepage",
}

func isToolHelpLine(line string) bool {
	for _, prefix := range helpPrefixes {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	// "  -u, --url string" and "            -u URL" style flag tables.
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "-") && (strings.Contains(trimmed, ", --") || len(trimmed) < 12) {
		return true
	}
	return false
}

// bannerChars are the symbols tool banners (ASCII art) are made of. A line
// richer in them than in letters is artwork, not a finding.
const bannerChars = "_|\\/-=+*<>[](){}~^:.,'`\""

func isBannerArt(line string) bool {
	// Only artwork matters: mask the URLs so their letters and dots do not
	// count as content.
	masked := urlPattern.ReplaceAllString(line, "")
	art, letters := 0, 0
	for _, r := range masked {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			letters++
		case strings.ContainsRune(bannerChars, r):
			art++
		}
	}
	return art > letters+1
}

// prosePrefixes mark documentation, bug-report and changelog sentences that
// may contain project URLs (nmap.org, github.com/...). They are not assets.
var prosePrefixes = []string{
	"Report ", "report ", "Read ", "read ", "- ", "* ", "Bug ", "Bugs ", "Submit ",
	"Copyright", "(c) ", "Nmap ", "nmap ", "https://nmap.org", "see ", "See ",
	"Learn ", "Find ", "Join ", "Follow ",
}

func isProseAboutSite(line string) bool {
	for _, prefix := range prosePrefixes {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// credentialHostPattern matches the host line of a successful login.
var credentialHostPattern = regexp.MustCompile(`^\[([0-9]{1,5})\]\[[^\]]*\]\s+host:\s+([A-Za-z0-9._:\[\]-]+)`)

// openPortOnHostPattern matches "Discovered open port 22/tcp on 10.0.0.5".
var openPortOnHostPattern = regexp.MustCompile(`open port ([0-9]{1,5})/(?:tcp|udp) on ([A-Za-z0-9._:\[\]-]+)`)

func looksLikeURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Host != ""
}

func parseJSON(line string, addHost func(string), addPort func(string, int), addURL func(string)) {
	var objects []map[string]any
	single := map[string]any{}
	if err := json.Unmarshal([]byte(line), &single); err == nil {
		objects = append(objects, single)
	} else if err := json.Unmarshal([]byte(line), &objects); err != nil {
		return
	}
	for _, object := range objects {
		host := ""
		for _, key := range []string{"host", "ip", "hostname", "host_ip"} {
			if value, ok := object[key].(string); ok && value != "" {
				if strings.HasPrefix(value, "http") {
					addURL(value)
					continue
				}
				host = value
				addHost(value)
			}
		}
		for _, key := range []string{"url", "endpoint", "matched-at", "matched_at"} {
			if value, ok := object[key].(string); ok {
				addURL(value)
			}
		}
		for _, key := range []string{"input"} {
			if value, ok := object[key].(string); ok && strings.HasPrefix(value, "http") {
				addURL(value)
			}
		}
		port := 0
		for _, key := range []string{"port", "dst_port"} {
			switch value := object[key].(type) {
			case float64:
				port = int(value)
			case string:
				port = atoi(value)
			}
			if port > 0 {
				break
			}
		}
		if port > 0 && host != "" {
			addPort(host, port)
		}
	}
}

// ArtifactPaths resolves artifact files recorded for an execution. Paths are
// stored relative to the artifact root.
func ArtifactPaths(root, stdoutPath, stderrPath string) (string, string) {
	resolve := func(relative string) string {
		if relative == "" || root == "" {
			return ""
		}
		return filepath.Join(root, filepath.FromSlash(relative))
	}
	return resolve(stdoutPath), resolve(stderrPath)
}

// ReadArtifact reads an artifact, keeping at most maxBytes from the end.
func ReadArtifact(path string, maxBytes int64) (string, error) {
	if path == "" {
		return "", nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	offset := int64(0)
	if maxBytes > 0 && info.Size() > maxBytes {
		offset = info.Size() - maxBytes
	}
	if _, err := file.Seek(offset, 0); err != nil {
		return "", err
	}
	buffer := make([]byte, info.Size()-offset)
	read := 0
	for read < len(buffer) {
		n, err := file.Read(buffer[read:])
		read += n
		if err != nil {
			break
		}
	}
	return string(buffer[:read]), nil
}

func splitLines(text string) []string {
	var lines []string
	scanLines(text, func(line string) { lines = append(lines, line) })
	return lines
}

func scanLines(text string, fn func(string)) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		fn(scanner.Text())
	}
}

// WebURLs turns captured open ports into HTTP URLs for later web tools.
func WebURLs(captures *Captures) []string {
	var urls []string
	web := WebPorts()
	for _, host := range captures.HostsList() {
		for _, port := range captures.PortList(host) {
			if !web[port] {
				continue
			}
			scheme := "http"
			if port == 443 || port == 8443 || port == 9443 || port == 10443 {
				scheme = "https"
			}
			hostPart := host
			if port != 80 && port != 443 {
				hostPart = fmt.Sprintf("%s:%d", host, port)
			}
			urls = append(urls, scheme+"://"+hostPart+"/")
		}
	}
	return urls
}

func normalizeHost(host string) string {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	host = strings.Trim(host, "[]")
	return strings.ToLower(host)
}

func splitHostPortLoose(value string) (string, int) {
	if strings.HasPrefix(value, "[") {
		if end := strings.LastIndex(value, "]"); end > 0 {
			host := value[1:end]
			if end+1 < len(value) && value[end+1] == ':' {
				return host, atoi(value[end+2:])
			}
			return host, 0
		}
		return "", 0
	}
	index := strings.LastIndex(value, ":")
	if index < 0 {
		return value, 0
	}
	return value[:index], atoi(value[index+1:])
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func stripANSI(value string) string {
	return ansiPattern.ReplaceAllString(value, "")
}

func atoi(value string) int {
	result := 0
	for _, r := range strings.TrimSpace(value) {
		if r < '0' || r > '9' {
			return result
		}
		result = result*10 + int(r-'0')
	}
	return result
}
