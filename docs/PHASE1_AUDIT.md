# Phase 1 — Architecture Audit

Date: 2026-11-21
Status: complete
Scope: environment inspection, repository audit, capability review, architecture
decision and Phase 2 preparation.

## 1. Development environment

| Item | Value |
|---|---|
| OS | Debian GNU/Linux 13 (trixie) |
| Kernel | 6.12.117+deb13-amd64 |
| Architecture | x86_64 / linux-amd64 |
| Go | go1.24.4 |
| Git | 2.47.3 |
| CPUs | 12 |
| RAM | 15 GiB total, ~3.6 GiB available at inspection |
| Disk | 439 GiB total, 160 GiB available on `/` |
| Working directory | `/home/luna/CYBERM4NCER` |
| SQLite CLI | 3.46+ available (framework uses embedded pure-Go driver) |
| Build essentials | gcc, make available |

The machine is suitable for local development and for running modest
assessments. The framework does not require root, CGO or Docker.

## 2. Repository state

- Remote: `https://github.com/lunalully/CYBERM4NCER`
- Branch: `main`
- Commits: none (empty repository at inspection)
- Existing code or assets: none
- License: MIT (selected after the audit)
- Git author identity: configured per repository during publication

Because no prior code existed, there was nothing to preserve or migrate.

## 3. Existing tooling

Detected and version-verified during the audit:

| Tool | Version | Tool | Version |
|---|---|---|---|
| subfinder | 2.17.0 | nuclei | 3.11.1 |
| amass | 4.2.0 | sqlmap | 1.9.6 |
| dnsx | 1.3.1 | nikto | 2.1.5 |
| httpx | 1.12.0 | sslscan | 2.1.5 |
| naabu | 2.7.0 | testssl | 3.2.1 |
| nmap | 7.95 | ffuf | 2.1.0 |
| katana | 1.8.0 | feroxbuster | 2.13.1 |
| gobuster | 3.6 | | |

Also present but not yet manifested: assetfinder, gau, waybackurls, gobuster,
arjun, whatweb, rustscan, netexec, enum4linux-ng, theHarvester, sherlock,
maigret, exiftool, chaos (missing). Their adapters and manifests belong to
Phases 3–5 and must not be claimed before implementation.

WhatWeb is installed but currently broken in this environment (Ruby gem
resolution error). This validates the decision to detect tools at runtime and
report unknown/error states instead of assuming a binary works.

## 4. Functional reference analysis

A reference platform in the same product category was reviewed at the level of
capabilities and workflows. No source code, visual identity, wording, configuration
or proprietary implementation was copied. The following concepts are adopted
with an independent design:

- A single workspace model for an engagement.
- Scan profiles from conservative to full operation.
- Chaining recon → web → vulnerability → reporting.
- Per-tool adaptation and result normalization.
- Operator-visible status, cancellation and evidence.

The reference's scan-mode catalog (normal/stealth/web/full-port/mass) is a
useful mapping for future profiles, but CYBERM4NCER will express profiles as
typed configuration and workflows, not as opaque shell modes. Its commercial
web UI, exploitation catalog and third-party branding are explicitly out of
scope.

## 5. Architectural decisions

| Decision | Rationale | Consequence |
|---|---|---|
| Go 1.24 | Fast startup, static binaries, context/process APIs | `go.mod` pinned to 1.24; SQLite driver pinned accordingly |
| Cobra | Mature CLI conventions | One dependency; tests can execute commands in-process |
| YAML + `KnownFields` | Human-editable config; typos fail fast | Every config/scope/manifest key is explicit |
| SQLite via `modernc.org/sqlite` | No CGO, amd64/arm64 friendly | Slightly larger binary, no system libsqlite dependency |
| `log/slog` | Standard library, structured output | Custom fan-out handler for file vs console levels |
| `exec.CommandContext` + argv | No shell injection surface | Modules pass argument arrays only |
| Process groups | Timeout must kill tool children | Linux-specific implementation, portable fallback |
| Embedded manifests | Offline, reproducible startup | Manifest changes require a rebuild; user overrides are future work |
| Hash-chained audit | Detect retroactive tampering | Not a substitute for external log anchoring |
| Scope always requires authorization | No accidental engagements | A sample scope with a placeholder must be edited before use |
| No installers in Phase 2 | Remote scripts and privilege escalation are high risk | `tools install` intentionally absent until Phase 3 |
| No stubs | Users must not mistake plans for features | CLI and docs publish an explicit status matrix |

### Deliberate scope boundaries

- No exploitation, persistence, lateral movement or exfiltration.
- No automatic tool installation or privilege escalation.
- No Docker requirement.
- No web UI or database server.
- No claims that a tool finding is a confirmed vulnerability before validation.

## 6. Identified risks

| Risk | Impact | Mitigation |
|---|---|---|
| External tool output changes | Parsers break | Version manifests + parser fixtures + structured formats first |
| Tool version drift | Silent incompatibility | Minimum/tested versions and `tools detect` |
| Scope bypass via redirects | Testing unauthorized assets | Per-hop redirect guard + tests |
| DNS resolution outside scope | Name resolves to an unauthorized IP | Documented limitation; network actions still require CIDR scope; future egress guard |
| Credentials in argv/logs | Secret leakage | Redaction before logging/persistence; env-based credentials recommended |
| SQLite lock contention | Slow concurrent writes | Single writer connection, WAL, bounded workers |
| Unbounded output/disk use | Disk exhaustion | Per-stream byte cap and truncation flags |
| Tool child processes surviving | Resource leaks | Process-group kill on timeout/cancel |
| False confidence in audit chain | Local tampering | Explicit threat-model limitation; future external anchoring |
| License ambiguity | Cannot publish legally | Resolved: MIT (`LICENSE`) |

## 6.1 Repository policy

- Visibility: **private**. Publishing or changing visibility requires the
  owner's explicit decision.
- License: MIT.
- No third-party code is vendored; dependencies keep their own licenses.

## 7. Phase 2 deliverable

The core foundation implemented in this phase:

- Cobra CLI with `version`, `doctor`, `config`, `scope`, `tools`.
- Layered configuration with defaults, YAML, env and flag precedence.
- Structured logging with separate file and console levels.
- SQLite schema, migrations, projects/operations/executions and audit chain.
- Scope compiler and evaluator for domains, wildcards, IPs, CIDRs, ports,
  exclusions and HTTP redirects.
- Execution engine with worker pool, timeout, cancellation, process groups,
  artifact capture, truncation and secret redaction.
- Tool registry with 15 validated manifests and live version detection.
- Normalized result model and deduplication fingerprint (persistence Phase 4).
- Unit tests for every implemented package.
- Architecture, scope, tool, security, roadmap and audit documentation.

Intentionally not implemented: tool installation, result parsers/storage,
recon/web/API modules, workflows, NUKE, reporting, TUI.

## 8. Verification

Executed in the project environment:

```
gofmt -l cmd internal          → no output
go vet ./...                   → pass
go test ./...                  → pass
go build ./...                 → pass
tools detect (15 manifests)    → all 15 installed and compatible
```

Live detection confirmed:

- subfinder 2.17.0, amass 4.2.0, dnsx 1.3.1, httpx 1.12.0
- naabu 2.7.0, nmap 7.95, katana 1.8.0, gobuster 3.6
- ffuf 2.1.0, feroxbuster 2.13.1, nuclei 3.11.1
- sqlmap 1.9.6, nikto 2.1.5, sslscan 2.1.5, testssl 3.2.1

## 9. Next phase

Phase 3 — Tool Manager:

- Reviewed install methods per manifest (`go`, `apt`, `github_release`, ...).
- Checksums/signatures for release downloads.
- Explicit consent, no privilege escalation, dry-run and install logs.
- Managed tool directory, update and removal semantics.
- Compatibility and conflict reporting.

No Phase 3 work starts until the Phase 2 result is reviewed.