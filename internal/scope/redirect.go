package scope

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OutOfScopeError is returned by the guarded HTTP client when a redirect
// leaves the authorized scope.
type OutOfScopeError struct {
	Target string
	Reason string
}

func (e *OutOfScopeError) Error() string {
	return fmt.Sprintf("redirect blocked by scope: %s (%s)", e.Target, e.Reason)
}

// CheckURL evaluates an HTTP(S) URL.
func (p *Policy) CheckURL(raw string) (Decision, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Decision{}, fmt.Errorf("parse URL: %w", err)
	}
	return p.checkURL(parsed)
}

func (p *Policy) checkURL(parsed *url.URL) (Decision, error) {
	if parsed == nil {
		return Decision{}, fmt.Errorf("URL is nil")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return Decision{
			Allowed: false,
			Target:  safeURL(parsed),
			Kind:    "url",
			Reason:  "only http and https URLs are supported",
		}, nil
	}
	host := parsed.Hostname()
	if host == "" {
		return Decision{}, fmt.Errorf("URL has no host")
	}
	port := 0
	if text := parsed.Port(); text != "" {
		parsedPort, err := strconv.Atoi(text)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return Decision{}, fmt.Errorf("invalid URL port %q", text)
		}
		port = parsedPort
	}
	decision, err := p.checkHost(host)
	if err != nil {
		return Decision{}, err
	}
	decision.Target = safeURL(parsed)
	decision.Kind = "url"

	if decision.Allowed {
		effectivePort := port
		if effectivePort == 0 {
			if scheme == "https" {
				effectivePort = 443
			} else {
				effectivePort = 80
			}
		}
		decision.Port = effectivePort
		if !p.portAllowed(effectivePort) {
			return Decision{
				Allowed: false,
				Target:  safeURL(parsed),
				Kind:    "url",
				Rule:    decision.Rule,
				Reason:  fmt.Sprintf("port %d is not allowed by scope", effectivePort),
				Port:    effectivePort,
			}, nil
		}
	}
	return decision, nil
}

// HTTPClient returns an HTTP client whose redirect policy validates every
// hop against the scope. The initial request must be checked by the caller
// with CheckURL or GuardRequest.
func (p *Policy) HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			decision, err := p.checkURL(req.URL)
			if err != nil {
				return fmt.Errorf("validate redirect: %w", err)
			}
			if !decision.Allowed {
				return &OutOfScopeError{Target: decision.Target, Reason: decision.Reason}
			}
			return nil
		},
	}
}

// GuardRequest validates the initial request before it is sent.
func (p *Policy) GuardRequest(req *http.Request) error {
	if req == nil || req.URL == nil {
		return fmt.Errorf("request has no URL")
	}
	decision, err := p.checkURL(req.URL)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return &OutOfScopeError{Target: decision.Target, Reason: decision.Reason}
	}
	return nil
}

func safeURL(parsed *url.URL) string {
	copy := *parsed
	copy.User = nil
	copy.Fragment = ""
	return copy.String()
}
