package scope

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExampleScopeFileIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "scope.example.yaml")
	policy, err := Load(path)
	if err != nil {
		t.Fatalf("example scope is invalid: %v", err)
	}
	if policy.Project != "replace-me" {
		t.Fatalf("project = %s", policy.Project)
	}
}

func TestIPv6Scope(t *testing.T) {
	policy := mustPolicy(t, `
version: 1
project: ipv6
authorization: "IPv6 test authorization"
includes:
  - cidr: 2001:db8::/32
excludes:
  - cidr: 2001:db8:dead::/48
`)
	tests := []struct {
		target  string
		allowed bool
	}{
		{"2001:db8::1", true},
		{"[2001:db8::1]:443", true},
		{"2001:db8:dead::1", false},
		{"2001:db9::1", false},
	}
	for _, test := range tests {
		decision, err := policy.CheckTarget(test.target)
		if err != nil {
			t.Fatalf("%s: %v", test.target, err)
		}
		if decision.Allowed != test.allowed {
			t.Errorf("%s: allowed=%t, want %t (%s)", test.target, decision.Allowed, test.allowed, decision.Reason)
		}
	}
}

func TestRedirectPortRestriction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	redirector := server.URL
	policy := mustPolicy(t, `
version: 1
project: ports
authorization: "port test authorization"
includes:
  - ip: 127.0.0.1
ports: [80]
`)
	client := policy.HTTPClient(2 * time.Second)
	_, err := client.Get(redirector)
	if err == nil {
		t.Fatal("expected redirect port denial")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Fatalf("unexpected error: %v", err)
	}
}
