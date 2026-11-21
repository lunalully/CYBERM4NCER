# Changelog

All notable changes to CYBERM4NCER are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Scanners receive a bare host (or `host:port`) instead of a URL and the
  target is emitted exactly once, in the reviewed position.
- Service steps (hydra, medusa) put the port in their protocol target and are
  refused before running when that port is outside the scope.
- Only ports proven open by a scanner feed the per-port fan-out; assets parsed
  from output are still recorded.
- Version detection strips ANSI colour codes (wafw00f) and parses wpscan's
  `Current Version:` line; all 30 tools are detected as ready on the lab host.
- ffuf/gobuster/amass/subfinder/medusa reviewed invocations now pass the
  target; whatweb uses its positional target (`--url` is ambiguous).
- Per-port tools receive host and port as two positional arguments:
  `nc -v -w 3 127.0.0.1 445`, `telnet 127.0.0.1 445`, `sslscan 127.0.0.1:445`.
- ffuf and gobuster receive a full URL (`http://127.0.0.1:8081`), not a bare
  host, and URL tools planned on a bare host are checked against the implied
  port (80/443) before they run.
- `wafw00f` takes its target positionally (`-a` means aggressive mode).
- The reviewed target flag is never added when the argv already carries
  `{{host}}`, `{{hostport}}` or `{{url}}`.

### Added

- Aggressive engine: expanded plans, repeated rounds, per-port fan-out, report
  parsing, credential match reporting and operation/audit records.
- `cyberm4ncer aggressive` command with plan-by-default and `--execute`.
- 15 new manifests (wafw00f, telnet, nc, hydra, medusa, masscan, rustscan,
  dirb, dirsearch, whatweb, nxc, enum4linux-ng, dalfox, arjun, wpscan) and
  reviewed invocations for every existing manifest.
- Execution engine accepts expected exit codes from reviewed invocations.
- Multiple targets per run (`--file`), `--max-steps` campaign cap, `--wordlist`,
  `--userlist` and `--passlist` flags.
- `execution.wordlist` configuration and `CYBERM4NCER_WORDLIST` override.
- Asset capture hardening: help screens, stack traces, documentation prose and
  vendor domains are ignored; open ports are attributed to the scanned host.

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