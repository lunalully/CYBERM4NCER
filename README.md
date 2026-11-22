# CYBERM4NCER

**Modular Offensive Security Framework**

CYBERM4NCER is a Linux-first framework for authorized security assessments. It
provides one consistent interface for scoped reconnaissance, web/API testing,
vulnerability assessment, execution history, normalized results and reporting.

> **Authorized testing only.** You are responsible for having written
> permission to test every asset you touch. Scope files are optional: pass one
> with `-s` and every target is checked against it (exclusions win, ports are
> limited); without one the tool scans the host, IP or URL you give.

## Status

**0.2.0-dev — Core foundation plus the aggressive engine.** This is an
engineering preview, not a complete scanning platform. The project is intentionally honest about what
exists:

| Capability | Status |
|---|---|
| CLI, configuration, logging | Implemented |
| SQLite persistence and migrations | Implemented |
| Tamper-evident audit log | Implemented |
| Scope engine (host, URL, IP, CIDR, redirects) | Implemented |
| Execution engine (timeout, cancellation, process groups) | Implemented |
| Tool registry and version detection (30 manifests with reviewed invocations) | Implemented |
| Aggressive engine (repeated runs, port chaining, reporting) | Implemented |
| Normalized result model and deduplication fingerprint | Model implemented |
| Tool installation / update / removal | Phase 3 |
| Result parsers and persistence | Phase 4 |
| Recon and Web modules | Phase 5 |
| API Security module | Phase 6 |
| Workflow engine | Phase 7 |
| NUKE orchestrator | Phase 8 |
| HTML/JSON/Markdown/CSV reports | Phase 9 |

Commands that do not exist yet are not registered as stubs. The full plan is in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## Requirements

- Linux (amd64 or arm64)
- Go 1.24+
- No root privileges, Docker or graphical interface required

External tools are optional for the core. CYBERM4NCER detects them but does not
install anything automatically.

## Build

```bash
git clone https://github.com/lunalully/CYBERM4NCER.git
cd CYBERM4NCER
make build
./dist/cyberm4ncer version
```

Or:

```bash
go build -o cyberm4ncer ./cmd/cyberm4ncer
```

See [`docs/INSTALLATION.md`](docs/INSTALLATION.md) for cross-compilation and
installation details.

## Quick start

```bash
cyberm4ncer doctor
cyberm4ncer config init
cyberm4ncer config show
cyberm4ncer tools list
cyberm4ncer tools detect
cyberm4ncer aggressive 10.0.0.5                                  # plan only
cyberm4ncer aggressive 10.0.0.5 --execute                        # run it
cyberm4ncer aggressive app.example.com 203.0.113.10 --execute    # several targets
cyberm4ncer scope validate engagement.yaml
cyberm4ncer scope check app.example.com --file engagement.yaml
cyberm4ncer aggressive 10.0.0.5 --scope engagement.yaml --execute # run with a scope
```

A scope file is optional. When you supply one, it is enforced before every
execution:

```yaml
version: 1
project: acme
authorization: "ENG-2026-014 — signed authorization held by the operator"
includes:
  - domain: example.com
    subdomains: true
  - cidr: 203.0.113.0/24
excludes:
  - domain: staging.example.com
    subdomains: true
ports: [80, 443]
```

See [`docs/SCOPE_ENGINE.md`](docs/SCOPE_ENGINE.md) for exact semantics.

## Architecture

CYBERM4NCER separates configuration, scope, execution, persistence, aggressive
orchestration and tool metadata. Modules never build their own process runners or loggers; they use
the core services.

```
cmd/cyberm4ncer      CLI entry point
internal/cli         Cobra commands and presentation
internal/core        Composition root and lifecycle
internal/config      YAML/env/flags resolution and validation
internal/logger      Structured file + console logging
internal/database    SQLite schema, migrations, audit chain
internal/scope       Authorization policy and redirect guard
internal/execution   Safe external process execution
internal/tools       Tool manifests, registry and version detection
internal/results     Normalized finding model and fingerprint
internal/aggressive  Plan expansion, repetition, asset chaining, reporting
```

Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and the
[Phase 1 audit](docs/PHASE1_AUDIT.md) for decisions and trade-offs. The
[Phase 2 delivery report](docs/PHASE2_REPORT.md) lists exactly what was built,
verified and intentionally left out.

## Safety model

- Scope is mandatory for target-facing operations; `core.ExecuteScoped` is the
  only process entry point and fails closed without a policy or target.
- Exclusions always win; matching uses DNS label boundaries, never substrings.
- Redirects are revalidated at every hop.
- Commands use argv arrays, never shell string concatenation.
- Every execution has a timeout, cancellation path, output limits and an
  artifact trail.
- Credential-looking argv values are redacted before persistence and logging.
- Every execution lifecycle is written to SQLite; the audit log is a SHA-256
  hash chain.
- Destructive exploitation, persistence and exfiltration are out of scope.

Read [`SECURITY.md`](SECURITY.md).

## Repository layout

```
cmd/                 CLI entry point
internal/            private implementation packages
configs/             example configuration and scope files
docs/                architecture, phase reports, references
scripts/             development and build helpers
```

## Development

```bash
make check     # gofmt check, go vet, go test
make test
make build
```

Tool adapters and modules will be added under `internal/adapters` and
`internal/modules`; see the roadmap.

## License

MIT. See [`LICENSE`](LICENSE).

The software is provided "as is". Use it only against systems you are
authorized to test; the license grants use rights, not permission to attack
systems.