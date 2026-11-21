package aggressive

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lunalully/cyberm4ncer/internal/scope"
	"github.com/lunalully/cyberm4ncer/internal/tools"
)

const testScope = `
version: 1
project: aggressive-test
authorization: "aggressive unit-test authorization"
includes:
  - ip: 127.0.0.1
  - domain: example.com
    subdomains: true
excludes:
  - domain: out.example.com
`

func mustPolicy(t *testing.T) *scope.Policy {
	t.Helper()
	policy, err := scope.Parse([]byte(testScope))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func mustRegistry(t *testing.T) *tools.Registry {
	t.Helper()
	registry, err := tools.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestPlanRefusesOutOfScopeTarget(t *testing.T) {
	planner := &Planner{Registry: mustRegistry(t), Mode: DefaultMode()}
	if _, err := planner.Plan("evil.invalid", mustPolicy(t)); err == nil {
		t.Fatal("expected scope denial")
	}
	if _, err := planner.Plan("out.example.com", mustPolicy(t)); err == nil {
		t.Fatal("expected exclusion to deny the target")
	}
	if _, err := planner.Plan("example.com", nil); err == nil {
		t.Fatal("expected missing policy to deny the target")
	}
}

func TestPlanExpandsRepeatedInvocations(t *testing.T) {
	planner := &Planner{Registry: mustRegistry(t), Mode: DefaultMode()}
	plan, err := planner.Plan("127.0.0.1", mustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) == 0 {
		t.Fatal("plan has no steps")
	}

	counts := map[string]int{}
	for _, step := range plan.Steps {
		counts[step.Tool]++
	}
	// Every reviewed invocation repeats at least two rounds; nmap has two
	// invocations of two rounds each.
	if counts["nmap"] < 4 {
		t.Fatalf("nmap steps = %d, want at least 4", counts["nmap"])
	}
	if counts["nuclei"] < 6 {
		t.Fatalf("nuclei steps = %d, want at least 6", counts["nuclei"])
	}
	if counts["hydra"] != 2 {
		t.Fatalf("hydra steps = %d, want 2", counts["hydra"])
	}
	for _, step := range plan.Steps {
		for _, arg := range step.Args {
			if strings.Contains(arg, "{{") && !strings.Contains(arg, "{{out}}") && !strings.Contains(arg, "{{wordlist}}") && !strings.Contains(arg, "{{url}}") {
				t.Fatalf("%s/%s left an unresolved template in args: %q", step.Tool, step.Invocation, arg)
			}
		}
		if step.Tool != "telnet" && len(step.Args) == 0 {
			t.Fatalf("%s/%s has empty args", step.Tool, step.Invocation)
		}
	}
}

func TestPlanRespectsQuotaAndLevels(t *testing.T) {
	mode := DefaultMode()
	mode.RepeatQuota = 1
	mode.Level = 1
	planner := &Planner{Registry: mustRegistry(t), Mode: mode}
	plan, err := planner.Plan("example.com", mustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.Round != 1 {
			t.Fatalf("%s round = %d, want 1", step.Tool, step.Round)
		}
		for _, arg := range step.Args {
			if arg == "-T5" || arg == "-rate" {
				t.Fatalf("level 1 used aggressive speed args: %v", step.Args)
			}
		}
	}
}

func TestPlanDisablesCredentialsAndIntrusiveTools(t *testing.T) {
	mode := DefaultMode()
	mode.IncludeCredential = false
	mode.IncludeIntrusive = false
	planner := &Planner{Registry: mustRegistry(t), Mode: mode}
	plan, err := planner.Plan("127.0.0.1", mustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.Tool == "hydra" || step.Tool == "medusa" || step.Tool == "nuclei" {
			t.Fatalf("disabled tool planned: %s", step.Tool)
		}
	}
}

func TestPlanOnlyVulnMode(t *testing.T) {
	mode := DefaultMode()
	mode.Name = "vuln"
	planner := &Planner{Registry: mustRegistry(t), Mode: mode}
	plan, err := planner.Plan("https://example.com", mustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	toolsSeen := map[string]bool{}
	for _, step := range plan.Steps {
		toolsSeen[step.Tool] = true
		if step.Mode == "credential" {
			t.Fatalf("credential step in vuln mode: %s", step.Tool)
		}
	}
	if !toolsSeen["nuclei"] || !toolsSeen["sqlmap"] {
		t.Fatalf("vuln mode is missing tools: %v", toolsSeen)
	}
}

func TestResolveLeavesUnknownPlaceholders(t *testing.T) {
	values := Context{Target: "example.com", Host: "example.com", Port: 443, HostPort: "example.com:443", Out: "/tmp/out", Options: map[string]string{"wordlist": "/w.txt"}}
	got := Resolve("{{target}} {{host}} {{port}} {{hostport}} {{out}} {{wordlist}} {{missing}}", values)
	want := "example.com example.com 443 example.com:443 /tmp/out /w.txt {{missing}}"
	if got != want {
		t.Fatalf("Resolve = %q, want %q", got, want)
	}
}

func TestBuildArgsPlacesOptionsAfterTemplates(t *testing.T) {
	step := Step{
		Args:        []string{"-w", "{{wordlist}}", "-u", "{{url}}", "-o", "{{out}}"},
		OptionFlags: map[string]string{"wordlist": "-w", "extensions": "-e"},
	}
	values := Context{
		URL:     "http://127.0.0.1:8080/",
		Out:     "/data/out",
		Options: map[string]string{"wordlist": "/w.txt", "extensions": ".php,.bak"},
	}
	args := buildArgs(step, values)
	want := []string{"-w", "/w.txt", "-u", "http://127.0.0.1:8080/", "-o", "/data/out", "-e", ".php,.bak"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v, want %v", args, want)
	}
}

func TestBuildArgsSkipsMissingOptions(t *testing.T) {
	step := Step{
		Args:        []string{"-u", "{{url}}", "-o", "{{out}}"},
		OptionFlags: map[string]string{"userlist": "-L", "passlist": "-P"},
	}
	args := buildArgs(step, Context{URL: "http://example.com/", Out: "/o", Options: map[string]string{}})
	if strings.Contains(strings.Join(args, " "), "-L") {
		t.Fatalf("missing wordlist produced a flag: %v", args)
	}
}

func TestParseNmapText(t *testing.T) {
	stdout := `Starting Nmap 7.95
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  closed https
`
	learned := ParseOutput("nmap", stdout, "", "127.0.0.1")
	if len(learned.Ports) != 2 {
		t.Fatalf("ports = %+v", learned.Ports)
	}
	if learned.Ports[0].Port != 22 || learned.Ports[1].Port != 80 {
		t.Fatalf("ports = %+v", learned.Ports)
	}
	if learned.Ports[0].Host != "127.0.0.1" {
		t.Fatalf("host = %q", learned.Ports[0].Host)
	}
}

func TestParseNaabuJSON(t *testing.T) {
	stdout := `{"host":"127.0.0.1","ip":"127.0.0.1","port":8080}
{"host":"127.0.0.1","port":3306}`
	learned := ParseOutput("naabu", stdout, "", "")
	if len(learned.Ports) != 2 {
		t.Fatalf("ports = %+v", learned.Ports)
	}
	if learned.Hosts[0] != "127.0.0.1" {
		t.Fatalf("hosts = %+v", learned.Hosts)
	}
}

func TestParseHttpxURLs(t *testing.T) {
	stdout := `https://lab.internal [200] [Acme] [nginx]
{"url":"http://lab.internal:8080/login","status_code":200}`
	learned := ParseOutput("httpx", stdout, "", "lab.internal")
	if len(learned.URLs) != 2 {
		t.Fatalf("urls = %+v", learned.URLs)
	}
	if len(learned.Ports) != 1 || learned.Ports[0].Port != 8080 {
		t.Fatalf("ports = %+v", learned.Ports)
	}
}

func TestParseMasscanAndBanners(t *testing.T) {
	stdout := `Discovered open port 22/tcp on 127.0.0.1
Discovered open port 631/tcp on 127.0.0.1
[+] 127.0.0.1:3306 - banner: "mysql" - nmap.org in banner`
	learned := ParseOutput("masscan", stdout, "", "")
	if len(learned.Ports) != 2 {
		t.Fatalf("ports = %+v", learned.Ports)
	}
	if len(learned.Hosts) != 0 {
		t.Fatalf("banner text produced hosts: %+v", learned.Hosts)
	}
	help := ParseOutput("nmap", "- nmap.org in banner\nReport bugs: https://nmap.org", "", "127.0.0.1")
	if len(help.Hosts) != 0 || len(help.URLs) > 1 {
		t.Fatalf("help text leaked into captures: %+v", help)
	}
}

func TestParseIgnoresVendorOutputOfAnyTool(t *testing.T) {
	banner := `       ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
[!] legal disclaimer: standard notice
home: https://www.foofus.net]`
	for _, tool := range []string{"wpscan", "whatweb", "medusa", "hydra", "sqlmap"} {
		learned := ParseOutput(tool, banner, "", "127.0.0.1")
		if len(learned.URLs) != 0 {
			t.Fatalf("%s: tool banner leaked URLs: %+v", tool, learned.URLs)
		}
	}
	corpus := `Report bugs: https://nmap.org/submit/
https://lab.internal/docs
https://example.org/FUZZ
Homepage: https://projectdiscovery.io
https://github.com/vanhauser-thc/thc-hydra
https://lab.internal/path`
	for _, tool := range []string{"nmap", "ffuf", "hydra", "sqlmap"} {
		learned := ParseOutput(tool, corpus, "", "127.0.0.1")
		if len(learned.Hosts) != 1 || learned.Hosts[0] != "lab.internal" {
			t.Fatalf("%s: hosts = %v", tool, learned.Hosts)
		}
	}
}

// lab.internal is a placeholder used here instead of example domains, which
// the parser (correctly) discards as documentation.
func TestParseCandidateURLs(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   []string
	}{
		{"json lines", `{"url":"https://lab.internal:8443/admin"}` + "\n", []string{"https://lab.internal:8443/admin"}},
		{"hostport line", "lab.internal:8443 [200]\n", nil},
		{"single url", "https://lab.internal/plain\n", []string{"https://lab.internal/plain"}},
	}
	for _, tc := range cases {
		learned := ParseOutput("nuclei", tc.stdout, "", "")
		if len(learned.URLs) != len(tc.want) {
			t.Fatalf("%s: urls = %v, want %v", tc.name, learned.URLs, tc.want)
		}
		for index := range tc.want {
			if learned.URLs[index] != tc.want[index] {
				t.Fatalf("%s: urls = %v, want %v", tc.name, learned.URLs, tc.want)
			}
		}
	}
}

func TestParseIgnoresToolHelpOutput(t *testing.T) {
	help := `Usage:
  ffuf [flags]

Examples:
  ffuf -u https://example.org/FUZZ

Options:
  -u, --url string   Target URL
  -w, --wordlist     Wordlist
See https://github.com/ffuf/ffuf`
	learned := ParseOutput("ffuf", help, "", "127.0.0.1")
	if len(learned.Hosts) != 0 || len(learned.URLs) != 0 {
		t.Fatalf("help output produced assets: %+v", learned)
	}
}

func TestParseCredentialSuccess(t *testing.T) {
	stdout := `[22][ssh] host: 127.0.0.1   login: admin   password: admin`
	learned := ParseOutput("hydra", stdout, "", "127.0.0.1")
	if len(learned.Ports) != 1 || learned.Ports[0].Port != 22 {
		t.Fatalf("ports = %+v", learned.Ports)
	}
}

func TestCapturesAreDeduplicatedAndSorted(t *testing.T) {
	captures := NewCaptures()
	captures.AddHost("127.0.0.1")
	captures.AddHost("127.0.0.1")
	captures.AddHost("APP.Internal.")
	captures.AddPort("127.0.0.1", 8080)
	captures.AddPort("127.0.0.1", 80)
	captures.AddPort("127.0.0.1", 8080)
	captures.AddHost("not a host")
	captures.AddHost("whatweb.rb:1421")
	if captures.HostCount() != 2 {
		t.Fatalf("hosts = %v", captures.HostsList())
	}
	if captures.AddHost("whatweb.rb:1421") {
		t.Fatal("a source location was captured as a host")
	}
	if captures.AddHost("nmap.org") || captures.AddHost("docs.python.org") {
		t.Fatal("a vendor product domain was captured as an asset")
	}
	pairs := captures.OpenHostPorts()
	if len(pairs) != 2 || pairs[0] != "127.0.0.1:80" || pairs[1] != "127.0.0.1:8080" {
		t.Fatalf("pairs = %v", pairs)
	}
	urls := WebURLs(captures)
	if len(urls) != 2 || urls[0] != "http://127.0.0.1/" || urls[1] != "http://127.0.0.1:8080/" {
		t.Fatalf("urls = %v", urls)
	}
}

func TestReadArtifactTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stdout.log")
	if err := writeFile(path, strings.Repeat("a", 100)+"tail"); err != nil {
		t.Fatal(err)
	}
	content, err := ReadArtifact(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(content, "tail") || len(content) != 10 {
		t.Fatalf("content = %q", content)
	}
	if _, err := ReadArtifact(filepath.Join(dir, "missing.log"), 10); err == nil {
		t.Fatal("expected error for a missing artifact")
	}
}

func TestSuccessRegexMatchesHydra(t *testing.T) {
	expr := compileSuccess(`(?i)\[\d+\]\[[^\]]+\]\s+host:\s+\S+\s+.*login:\s+\S+\s+password:\s+\S+`)
	if expr == nil {
		t.Fatal("regex did not compile")
	}
	if !regexp.MustCompile(expr.String()).MatchString("[22][ssh] host: 1.2.3.4 login: root password: toor") {
		t.Fatal("valid hydra line did not match")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
