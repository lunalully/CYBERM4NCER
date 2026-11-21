# Changelog

All notable changes to CYBERM4NCER are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Cobra CLI with `version`, `doctor`, `config`, `scope` and `tools`.
- Layered configuration: defaults, YAML, environment, CLI flags.
- JSON and text output modes with terminal-aware color.
- Structured logging with separate file and console levels.
- SQLite store with migrations for projects, operations, executions, results
  and audit entries.
- SHA-256 hash-chained audit log with verification.
- Scope engine: domains, subdomain rules, wildcards, IPs, CIDRs, exclusions,
  port allowlists, URL checks and CIDR coverage checks.
- HTTP redirect guard that validates every hop.
- Execution engine: worker pool, timeout, cancellation, process-group kill,
  output caps, artifact files, previews and truncation reporting.
- Redaction of credential-like argv values before logging/persistence.
- Tool registry with 15 validated manifests and live version detection.
- Normalized result model and deduplication fingerprint.
- Unit tests for every implemented package.
- Architecture, scope, tool manager, result engine, workflow, NUKE, security,
  installation, CLI and phase-audit documentation.
- Build/check scripts and Makefile.
- MIT license.

### Security

- Authorization statement is mandatory in every scope.
- Exclusions always precede inclusions.
- Host matching uses DNS label boundaries, not substrings.
- External processes never use a shell; argv is passed separately.
- Every execution has a timeout and a cancellation path.
- Scope denial and failed health checks have explicit exit codes.

### Not yet implemented

- Tool installation, update and removal (Phase 3).
- Tool output parsers and result persistence (Phase 4).
- Recon, Web, API, Network, OSINT modules (Phases 5–6).
- Workflow engine (Phase 7).
- NUKE orchestrator (Phase 8).
- Report generation (Phase 9).
- TUI.
- Release packaging and signed artifacts.

## [0.1.0-dev] — 2026-11-21

Development preview of the core foundation. No stable release has been made.

[Unreleased]: https://github.com/lunalully/CYBERM4NCER/compare/main...HEAD
[0.1.0-dev]: https://github.com/lunalully/CYBERM4NCER