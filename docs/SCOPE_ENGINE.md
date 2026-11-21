# Scope Engine

Scope is the authorization boundary. It is evaluated before target-facing work
and cannot be disabled by a module.

## File format

```yaml
version: 1
project: acme-web
authorization: "ENG-2026-014, signed by Acme Security, valid until 2026-12-31"

includes:
  - domain: example.com
    subdomains: true
  - domain: api.example.net
  - domain: "*.preview.example.net"
  - ip: 203.0.113.10
  - cidr: 203.0.113.0/24

excludes:
  - domain: billing.example.com
    subdomains: true
  - ip: 203.0.113.10
  - cidr: 203.0.113.128/25

ports: [80, 443]
```

### Required fields

- `version`: must be `1`.
- `project`: letters, digits, `.`, `_`, `-`; at most 64 characters.
- `authorization`: non-empty written authorization reference.
- `includes`: at least one rule.

`excludes` and `ports` are optional. `ports: []` or an omitted list means any
port is allowed. When ports are present, only listed ports are authorized.

## Rule semantics

Exactly one of `domain`, `ip` or `cidr` must be set per rule.

### Domains

| Rule | Matches |
|---|---|
| `domain: example.com` | exactly `example.com` |
| `domain: example.com` + `subdomains: true` | `example.com` and `*.example.com` |
| `domain: "*.example.com"` | only proper subdomains; not the apex |

Matching is by DNS label boundary:

- `example.com` matches `example.com` and `a.example.com`
- it does **not** match `notexample.com`, `example.com.evil` or
  `badexample.com`

Hostnames are lowercased, a trailing dot is removed, and non-ASCII names must be
provided in punycode (`xn--`) form. Substring or fuzzy matching is never used.

### IP and CIDR

- IP literals match only `ip` or `cidr` rules, never domain rules.
- IPv4-mapped IPv6 literals are unmapped before comparison.
- Exclusions are checked before inclusions.

### CIDR coverage

A range is only allowed when a single include CIDR fully covers it and no
exclusion overlaps it. A partially covered range is denied. Adjacent include
ranges are not merged (future work).

Examples:

```
include 10.0.0.0/24, exclude 10.0.0.128/25
10.0.0.0/24       DENIED  (contains an excluded range)
10.0.0.0/25       DENIED  (contains excluded 10.0.0.5 if that IP is excluded)
10.0.0.16/28      ALLOWED (fully covered, no exclusion)
10.0.0.0/16       DENIED  (not fully covered)
```

### Ports

Ports apply to host:port targets and URLs. `https://example.com` uses 443,
`http://example.com` uses 80. A URL with an unlisted port is denied.

## Targets accepted by `scope check`

- `example.com`
- `example.com:443`
- `https://example.com/path`
- `203.0.113.10`
- `2001:db8::1`
- `[2001:db8::1]:443`
- `10.0.0.0/24`

CIDR checks report denied when the range is not fully covered. Exit code 2 means
denied.

## HTTP redirects

`scope.Policy.HTTPClient` installs a `CheckRedirect` function that re-evaluates
every hop. A redirect to an unauthorized host, port or scheme aborts the
request with `OutOfScopeError`. Callers must also validate the initial request
with `GuardRequest` or `CheckURL`.

Example:

```go
policy, _ := scope.Load("engagement.yaml")
client := policy.HTTPClient(30 * time.Second)
req, _ := http.NewRequest("GET", "https://app.example.com", nil)
if err := policy.GuardRequest(req); err != nil { /* deny */ }
resp, err := client.Do(req)
```

## Limitations

1. **DNS is not an authorization decision.** The engine authorizes names and
   ranges, not resolved addresses. A scoped name can resolve to an IP outside an
   included CIDR. Network-facing modules must require appropriate IP/CIDR scope;
   a future egress guard may pin resolutions.
2. **Third-party tools.** The internal HTTP client is guarded, but external
   tools execute their own network stack. Adapters must disable redirect
   following where possible and constrain the tool to the validated target list.
   Every adapter needs tests/notes for this behavior.
3. **CDNs and shared hosting.** Authorizing a hostname does not imply ownership
   of every service on that IP. Do not add broad CIDRs to work around CDNs.
4. **Adjacent CIDRs.** Full coverage currently requires one containing include
   rule; adjacent ranges are not merged.
5. **Unicode.** IDNs must be supplied as punycode. This avoids ambiguous
   homograph matching.
6. **Local database.** The audit chain detects edits inside the database, not a
   full database replacement. Anchor logs externally for high-assurance work.

## Testing

The scope package covers:

- exact domain, subdomain and wildcard matching
- sibling-domain confusion (`notexample.com`)
- exclusions, including subdomain exclusions
- IPv4/IPv6 and partial CIDR coverage
- port allowlists and unsupported schemes
- redirects staying inside and leaving scope
- invalid authorization, rules, ports and non-ASCII hostnames

Run:

```bash
go test ./internal/scope
```