# Tool Manager

Status: **detection implemented; installation is Phase 3.**

CYBERM4NCER treats external tools as versioned dependencies with explicit
manifests. In 0.1.0 it can discover binaries and verify versions. It does not
download, install, update or remove anything.

## Manifest

Manifests are embedded YAML files under `internal/tools/manifests/`. They are
validated at startup; an invalid manifest prevents the binary from starting.

```yaml
name: nuclei
description: Template-based vulnerability and misconfiguration scanning.
category: vulnerability
homepage: https://github.com/projectdiscovery/nuclei
documentation: https://docs.projectdiscovery.io/tools/nuclei/overview
license: MIT
binary: nuclei
min_version: 3.0.0
tested_version: 3.11.1
architectures: [amd64, arm64, 386, arm]
risk: high
intrusive: true
capabilities: [vulnerability_detection, template_scanning]
outputs: [text, jsonl, json, sarif]
version_check:
  args: ["-version"]
  regex: '(?i)(?:nuclei engine version|current version):\s*v?([0-9]+\.[0-9]+\.[0-9]+)'
install:
  - method: go
    package: github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1
  - method: manual
    notes: Build from a reviewed release of the official repository.
```

### Fields

| Field | Meaning |
|---|---|
| `name` | Lowercase identifier; must match the filename |
| `description` | Human-readable purpose |
| `category` | `recon`, `web`, `api`, `network`, `vulnerability`, `osint`, `reporting`, `utility` |
| `homepage` / `documentation` | Official HTTPS references |
| `binary` | Executable name resolved via `PATH` |
| `min_version` | Minimum supported semantic version |
| `tested_version` | Version validated in this environment |
| `architectures` | `amd64`, `arm64`, `386`, `arm`, `any` |
| `risk` | Capability risk: `low`, `medium`, `high`, `critical` |
| `intrusive` | Requires explicit confirmation in future automation |
| `capabilities` | Machine-readable labels |
| `outputs` | Formats the tool can produce |
| `version_check.args` | argv passed to the version command |
| `version_check.regex` | Capture group 1 (or whole match) is the version |
| `install` | Declarative methods; not executed in 0.1.0 |
| `dependencies` | Other tools or runtime requirements |
| `notes` | Operational warnings |

Install methods: `go`, `apt`, `pipx`, `cargo`, `github_release`, `manual`.
Their presence is metadata for Phase 3; it does not imply that an installer
exists.

## Detection pipeline

`tools detect` and `doctor` use the execution engine, so version probes inherit
worker limits, timeouts (default 5s), output caps and execution records:

1. Resolve the binary with `exec.LookPath`.
2. Run the version command with `exec.CommandContext` and separate argv.
3. Combine stdout and stderr, capped for parsing and display.
4. Extract the version with the manifest regex.
5. Compare with `min_version`.
6. Report `installed`, `missing`, `incompatible`, `unknown` or `error`.

The parser does not trust terminal formatting; manifests target stable version
lines. ANSI codes are tolerated where tools emit them.

## Commands

```bash
cyberm4ncer tools list
cyberm4ncer tools list --detect
cyberm4ncer tools list --category vulnerability
cyberm4ncer tools info nuclei
cyberm4ncer tools detect
cyberm4ncer tools detect nuclei sqlmap
```

`tools detect` exits 1 when any requested tool is not ready.

## Security rules for installation (Phase 3)

Installation is a supply-chain boundary. The planned rules are:

- Never pipe a remote script into a shell.
- Never run `sudo` silently; privileged installation requires explicit consent.
- Prefer distribution packages or official releases with checksums.
- Verify SHA-256 checksums and, when available, signatures.
- Pin versions; no implicit `@latest`.
- Download to a temporary file, inspect, then install.
- Record actor, method, URL, version and checksum in the audit log.
- Install into the managed tools directory by default.
- Remove only files the framework installed.
- Detect dependency and PATH conflicts before writing.
- Provide `--dry-run` and show the exact command/plan.
- Refuse installation in a non-interactive session without an explicit flag.

## Current limitations

- Binary lookup uses `PATH`; per-tool path overrides are not implemented.
- Script tools with unusual version output may report `unknown`.
- Installation/update/removal do not exist yet.
- Manifests are compiled into the binary; user overrides are future work.
- Tool updates are separate from framework updates and must be explicit.

## Adding a manifest

1. Verify the official repository, license, binary name and version command.
2. Choose a conservative `min_version` and record the local `tested_version`.
3. Add the YAML file under `internal/tools/manifests/<name>.yaml`.
4. Run `go test ./internal/tools`.
5. Run `cyberm4ncer tools detect <name>` on a real installation.
6. Document the tool page (function, usage, parameters, dependencies,
   limitations, risks, official documentation) before adding an adapter.