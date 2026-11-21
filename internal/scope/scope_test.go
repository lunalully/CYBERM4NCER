package scope

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const testScope = `
version: 1
project: acme
authorization: "ENG-2026-001 signed by asset owner"
includes:
  - domain: example.com
    subdomains: true
  - domain: apex.test
  - domain: "*.wild.test"
  - ip: 203.0.113.10
  - cidr: 10.0.0.0/24
excludes:
  - domain: admin.example.com
    subdomains: true
  - ip: 10.0.0.5
  - cidr: 10.0.0.128/25
ports: [80, 443]
`

func mustPolicy(t *testing.T, document string) *Policy {
	t.Helper()
	policy, err := Parse([]byte(document))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return policy
}

func TestHostMatching(t *testing.T) {
	policy := mustPolicy(t, testScope)
	tests := []struct {
		target  string
		allowed bool
		reason  string
	}{
		{"example.com", true, "included"},
		{"a.example.com", true, "included"},
		{"a.b.example.com", true, "included"},
		{"notexample.com", false, "no matching"},
		{"badexample.com", false, "no matching"},
		{"example.com.evil", false, "no matching"},
		{"admin.example.com", false, "excluded"},
		{"deep.admin.example.com", false, "excluded"},
		{"apex.test", true, "included"},
		{"sub.apex.test", false, "no matching"},
		{"one.wild.test", true, "included"},
		{"wild.test", false, "no matching"},
		{"203.0.113.10", true, "included"},
		{"203.0.113.11", false, "no matching"},
		{"10.0.0.6", true, "included"},
		{"10.0.0.5", false, "excluded"},
		{"10.0.0.200", false, "excluded"},
	}
	for _, test := range tests {
		decision, err := policy.CheckTarget(test.target)
		if err != nil {
			t.Fatalf("%s: %v", test.target, err)
		}
		if decision.Allowed != test.allowed {
			t.Errorf("%s: allowed=%t, want %t (%s)", test.target, decision.Allowed, test.allowed, decision.Reason)
		}
		if !strings.Contains(decision.Reason, test.reason) {
			t.Errorf("%s: reason=%q, want substring %q", test.target, decision.Reason, test.reason)
		}
	}
}

func TestURLPortAndScheme(t *testing.T) {
	policy := mustPolicy(t, testScope)
	tests := []struct {
		url     string
		allowed bool
	}{
		{"http://example.com/", true},
		{"https://example.com/path?q=1", true},
		{"http://example.com:8080/", false},
		{"https://example.com:8443/", false},
		{"ftp://example.com/", false},
	}
	for _, test := range tests {
		decision, err := policy.CheckURL(test.url)
		if err != nil {
			t.Fatalf("%s: %v", test.url, err)
		}
		if decision.Allowed != test.allowed {
			t.Errorf("%s: allowed=%t, want %t (%s)", test.url, decision.Allowed, test.allowed, decision.Reason)
		}
	}

	decision, err := policy.CheckURL("http://user:supersecret@example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("userinfo URL should be allowed: %s", decision.Reason)
	}
	if strings.Contains(decision.Target, "supersecret") {
		t.Fatalf("decision target leaked credentials: %s", decision.Target)
	}
}

func TestTargetWithPort(t *testing.T) {
	policy := mustPolicy(t, testScope)
	decision, err := policy.CheckTarget("example.com:22")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatal("port 22 should be denied")
	}
	decision, err = policy.CheckTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("port 443 should be allowed: %s", decision.Reason)
	}
}

func TestCIDRCoverage(t *testing.T) {
	policy := mustPolicy(t, testScope)
	tests := []struct {
		cidr    string
		allowed bool
		reason  string
	}{
		{"10.0.0.0/24", false, "overlaps exclusion"},
		{"10.0.0.16/28", true, "fully covered"},
		{"10.0.0.128/25", false, "overlaps exclusion"},
		{"10.0.0.0/16", false, "overlaps exclusion"},
		{"10.0.1.0/24", false, "no matching"},
		{"192.0.2.0/24", false, "no matching"},
	}
	for _, test := range tests {
		prefix, err := netip.ParsePrefix(test.cidr)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := policy.CheckCIDR(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Allowed != test.allowed {
			t.Errorf("%s: allowed=%t, want %t (%s)", test.cidr, decision.Allowed, test.allowed, decision.Reason)
		}
		if !strings.Contains(decision.Reason, test.reason) {
			t.Errorf("%s: reason=%q, want %q", test.cidr, decision.Reason, test.reason)
		}
	}
}

func TestInvalidScopes(t *testing.T) {
	tests := []string{
		"version: 1\nproject: x\nincludes:\n  - domain: example.com\n",
		"version: 1\nproject: x\nauthorization: yes\n",
		"version: 1\nproject: x\nauthorization: yes\nincludes:\n  - domain: example.com\n    ip: 127.0.0.1\n",
		"version: 1\nproject: x\nauthorization: yes\nincludes:\n  - domain: example.com\nports: [70000]\n",
		"version: 1\nproject: x\nauthorization: yes\nincludes:\n  - domain: exämple.com\n",
		"version: 2\nproject: x\nauthorization: yes\nincludes:\n  - domain: example.com\n",
		"version: 1\nproject: x\nauthorization: yes\nincludes:\n  - domain: example.com\nunknown: true\n",
	}
	for i, document := range tests {
		if _, err := Parse([]byte(document)); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestSummary(t *testing.T) {
	policy := mustPolicy(t, testScope)
	summary := policy.Summary()
	if summary.Project != "acme" || summary.Includes != 5 || summary.Excludes != 3 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if summary.Domains != 3 || summary.IPs != 1 || summary.CIDRs != 1 {
		t.Fatalf("unexpected rule counts: %+v", summary)
	}
	if len(summary.Ports) != 2 || summary.Ports[0] != 80 || summary.Ports[1] != 443 {
		t.Fatalf("unexpected ports: %+v", summary.Ports)
	}
}

func redirectPolicy(t *testing.T) *Policy {
	t.Helper()
	return mustPolicy(t, `
version: 1
project: redirects
authorization: "test authorization"
includes:
  - ip: 127.0.0.1
`)
}

func TestHTTPClientFollowsInScopeRedirect(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer destination.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer redirector.Close()

	client := redirectPolicy(t).HTTPClient(2 * time.Second)
	response, err := client.Get(redirector.URL)
	if err != nil {
		t.Fatalf("in-scope redirect failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestHTTPClientBlocksOutOfScopeRedirect(t *testing.T) {
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.org/outside", http.StatusFound)
	}))
	defer redirector.Close()

	client := redirectPolicy(t).HTTPClient(2 * time.Second)
	_, err := client.Get(redirector.URL)
	if err == nil {
		t.Fatal("expected redirect to be blocked")
	}
	var outOfScope *OutOfScopeError
	if !errors.As(err, &outOfScope) {
		t.Fatalf("error = %T %v, want OutOfScopeError", err, err)
	}
	if !strings.Contains(outOfScope.Reason, "no matching include rule") {
		t.Fatalf("unexpected reason: %s", outOfScope.Reason)
	}
}

func TestGuardRequest(t *testing.T) {
	policy := redirectPolicy(t)
	request, err := http.NewRequest(http.MethodGet, "http://example.org/", nil)
	if err != nil {
		t.Fatal(err)
	}
	var outOfScope *OutOfScopeError
	if err := policy.GuardRequest(request); !errors.As(err, &outOfScope) {
		t.Fatalf("error = %v, want OutOfScopeError", err)
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	if _, err := Load("/definitely/missing/scope.yaml"); err == nil {
		t.Fatal("expected error")
	}
}
