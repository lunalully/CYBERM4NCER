# Phase 2 — Core Foundation Report

Date: 2026-11-21
Status: delivered for review
Version: 0.1.0-dev

## Objective

Build a core that is testable, extensible and safe enough to support future
offensive modules, without implementing tools, workflows or NUKE prematurely.

## Delivered

### CLI and presentation

- `cmd/cyberm4ncer/main.go`
- `internal/cli/` — root, version, doctor, config, scope, tools, exit codes
- `internal/ui/` — plain output, tables, JSON, terminal-aware color

### Configuration and logging

- `internal/config/` — defaults, YAML (`KnownFields`), env, flags, validation,
  path resolution, duration type, scope discovery
- `internal/logger/` — structured text/JSON logging, separate file and console
  levels, fan-out handler

### Persistence

- `internal/database/` — SQLite (pure Go), migrations, projects, operations,
  executions, results schema, audit hash chain, verification, stats
- `internal/id/` — time-sortable prefixed identifiers

### Safety and execution

- `internal/scope/` — domains, subdomains, wildcards, exclusions, IPv4/IPv6,
  CIDRs, ports, URL checks, full-coverage CIDR checks, redirect guard
- `internal/execution/` — worker pool, timeout, cancellation, process groups,
  artifact capture, output limits, redaction, recorder lifecycle
- `internal/results/` — normalized finding model, severity, fingerprint

### Tool metadata

- `internal/tools/` — manifest schema, embedded registry, validation, semver,
  detector built on the execution engine
- 15 manifests: subfinder, amass, dnsx, httpx, naabu, nmap, katana, ffuf,
  feroxbuster, gobuster, nuclei, sqlmap, sslscan, testssl, nikto

### Documentation and operations

- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE` (MIT)
- `docs/ARCHITECTURE.md`, `docs/PHASE1_AUDIT.md`, `docs/ROADMAP.md`
- `docs/CLI_REFERENCE.md`, `docs/CONFIGURATION.md`, `docs/INSTALLATION.md`,
  `docs/QUICKSTART.md`
- `docs/SCOPE_ENGINE.md`, `docs/TOOL_MANAGER.md`, `docs/RESULT_ENGINE.md`
- `docs/WORKFLOW_ENGINE.md`, `docs/NUKE_MODE.md`
- `docs/modules/README.md`, `docs/tools/README.md`
- `configs/defaults.yaml`, `configs/scope.example.yaml`
- `Makefile`, `scripts/check.sh`, `scripts/build.sh`, CI workflow

## Security controls implemented

- Mandatory authorization statement in scope files.
- Exclusions first; label-boundary host matching.
- Scoped execution boundary (`core.ExecuteScoped`) that refuses execution
  without a policy or target and audits every allow/deny before running.
- Redirect revalidation on every hop.
- No shell execution; separate argv everywhere.
- Timeouts, process-group cancellation and output caps for every process.
- Credential redaction before persistence/logging.
- Execution lifecycle recorded in SQLite; start failure aborts execution.
- Audit hash chain with verification.
- Data/log/artifact permissions restricted.
- No tool installation, no remote scripts, no privilege escalation.

## Verification executed

```
make check
  gofmt -l cmd internal  → clean
  go vet ./...           → pass
  go test ./...          → pass

go test -race ./internal/core ./internal/scope ./internal/execution ./internal/database
  → pass

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build → pass
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build → pass (ELF aarch64, static)
```

Live tool detection (15 manifests, local machine):

```
all 15 tools are ready
```

Scope checks:

- `app.example.com:443` → ALLOWED
- `billing.example.com` → DENIED by exclusion, exit 2
- `evil.example.net` → DENIED, exit 2

## Known gaps

- No tool installers (Phase 3).
- No result parsers or result writer (Phase 4).
- No module commands (Phases 5–6).
- No workflows, NUKE or reporting (Phases 7–9).
- No tool-specific pages beyond the manifest index; added with adapters.
- DNS/egress guard and third-party redirect behavior remain documented
  limitations.
- License: MIT (`LICENSE`). Repository is private by owner decision.

## Next gate

Phase 3 — Tool Manager, starting only after review of this report:

1. Design reviewed install methods per manifest.
2. Add checksums/signatures and download inspection.
3. Require explicit consent and forbid silent privilege escalation.
4. Add install/update/remove tests with local fixtures (no network in CI).
5. Record installation actions in the audit chain.