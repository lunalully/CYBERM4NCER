# Roadmap

Versions are planning targets, not promises. A phase is complete only when its
code, tests and documentation are present and the repository checks pass.

## 0.1.0 — Core foundation (delivered, `0.1.0-dev`)

- [x] Cobra CLI and consistent exit codes
- [x] Layered configuration and validation
- [x] Structured logging
- [x] SQLite schema, migrations, audit chain
- [x] Scope engine with redirect guard
- [x] Execution engine with timeout/cancellation/artifacts
- [x] Tool manifests and version detection
- [x] Result model and fingerprint
- [x] Unit tests and core documentation

## 0.2.0 — Aggressive Engine (delivered, `0.2.0-dev`)

- [x] Plan expansion per tool/invocation/mode
- [x] Repeated rounds with level-based speed arguments
- [x] Port discovery chaining into per-port steps
- [x] Report parsing for stdout, JSON/JSONL and report files
- [x] Credential success detection and reporting
- [x] Operation and audit records for every run
- [x] Multiple targets per run and `--max-steps` campaign cap
- [x] Wordlist/credential list plumbing (`--wordlist`, `--userlist`, `--passlist`)
- [x] Concurrent execution (`--workers`, measured `overlap`)
- [ ] Resume of an interrupted run
- [ ] Per-tool result parsers (Result Engine)

## 0.3.0 — Tool Manager (next phase)

- [ ] Declarative, reviewed install methods
- [ ] Checksums and signature verification for downloads
- [ ] Explicit consent; no silent sudo
- [ ] Managed tool directory and PATH resolution
- [ ] Update/remove with integrity checks
- [ ] Conflict and dependency diagnostics
- [ ] Installation audit records and tests

## 0.3.0 — Result Engine (Phase 4)

- [ ] Independent parsers for structured outputs (JSON/JSONL/XML where available)
- [ ] Fixture tests per parser, including malformed output
- [ ] Deduplication with evidence retention
- [ ] Findings linked to project/operation/execution
- [ ] Severity normalization and validation status
- [ ] CLI inspection commands

## 0.4.0 — Recon module (Phase 5)

- [ ] Subdomain discovery
- [ ] DNS enumeration
- [ ] HTTP probing and technology fingerprinting
- [ ] Port discovery
- [ ] Asset inventory
- [ ] Conservative/assisted profiles

## 0.5.0 — Web module

- [ ] Crawling and endpoint discovery
- [ ] Directory/content enumeration (opt-in)
- [ ] Parameter discovery
- [ ] HTTP response analysis
- [ ] Explicit intrusive confirmation

## 0.6.0 — API Security module (Phase 6)

- [ ] OpenAPI/Swagger discovery
- [ ] Method/authentication/authorization analysis
- [ ] JWT/session/CORS/rate-limit checks
- [ ] IDOR checks with opt-in evidence handling
- [ ] Operator-supplied credentials only

## 0.7.0 — Workflow engine (Phase 7)

- [ ] YAML DAG with dependencies
- [ ] Variables and intermediate results
- [ ] Bounded parallel execution
- [ ] Conditions, timeouts, cancellation
- [ ] Resume and per-step audit
- [ ] Refuse steps whose dependencies failed

## 0.8.0 — NUKE orchestrator (Phase 8)

- [ ] Profile selection and operation plan
- [ ] Mandatory confirmation for intrusive steps
- [ ] Rate limits, allowlists, concurrency and time budgets
- [ ] Global kill switch
- [ ] Consolidation and final report
- [ ] No destructive actions in automatic mode

## 0.9.0 — Reporting (Phase 9)

- [ ] HTML, JSON, Markdown and CSV
- [ ] Evidence, references and CVSS metadata
- [ ] Deduplication and executive summary
- [ ] Recommendations and tool provenance
- [ ] Historical comparison

## 1.0.0 — Stable release

- [ ] Full audit of scope/execution boundaries
- [ ] Parser and workflow regression suite
- [ ] Packaging for amd64/arm64
- [ ] Complete CLI and module reference
- [x] License (MIT) and contribution policy finalized
- [ ] Signed release artifacts

## Cross-cutting work

- Fuzz tests for scope parsing and redirect handling
- Parser fixtures for every supported tool
- Benchmark startup and memory on low-end hardware
- Structured error catalog and shell completion
- Documentation page for every supported tool