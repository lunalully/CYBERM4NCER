# Security Policy

## Authorization

CYBERM4NCER is for authorized security testing only. Using it against systems
without explicit, written permission may be illegal. The operator is solely
responsible for authorization, lawful use and data handling.

The framework enforces scope mechanically, but a scope file is not proof of
authorization. Do not add assets you do not own or have permission to test.

## Reporting a vulnerability

Do not open a public issue for a security vulnerability.

Use the repository's **private security advisory** feature:

1. Go to the GitHub repository.
2. Open **Security → Advisories → Report a vulnerability**.
3. Include affected version/commit, reproduction steps, impact and any proposed
   fix.

Please avoid including real target data, credentials or third-party personal
data. A maintainer will acknowledge the report and coordinate disclosure.

## Supported versions

| Version | Support |
|---|---|
| 0.1.x (development) | Best effort during active development |
| Older/unreleased snapshots | Not supported |

There is no stable release yet.

## Security model

### Scope

- Authorization is mandatory and part of the scope schema.
- Exclusions take precedence.
- Host matching uses DNS label boundaries.
- IP literals only match IP/CIDR rules.
- CIDRs require full coverage.
- HTTP redirects are revalidated per hop by the internal client.
- Scope is independent of modules and cannot be bypassed by module code.

### Execution

- No shell strings; argv arrays only.
- `exec.CommandContext` with timeouts.
- Process-group kill on timeout/cancellation.
- Bounded stdout/stderr capture.
- Every execution is recorded with status, exit code, artifacts and redacted
  argv.
- Start failures and recorder failures are surfaced; they are never silently
  ignored.

### Secrets

- Credential-looking argv values are redacted before logging/persistence.
- Configuration files must not contain credentials.
- Adapters must accept credentials from environment variables or restricted
  files (mode `0600`), never from command-line values where avoidable.
- Logs and artifacts may still contain secrets printed by the external tool.
  Protect the data directory and review artifacts before sharing.

### Local data

- Data, logs, artifacts and tools directories use mode `0700`.
- Database and log files use `0600`.
- SQLite uses WAL and foreign keys.
- The audit log is a SHA-256 hash chain and detects local edits.

## Known limitations

1. **DNS/egress:** scope authorizes names and ranges, not resolved addresses. A
   scoped name can resolve outside included CIDRs.
2. **Third-party network behavior:** external tools run their own HTTP stacks.
   Adapters must disable redirect-following and constrain targets. Adapters
   without such controls are not ready.
3. **Local tampering:** an attacker with full write access can replace the
   database and recompute the audit chain. External anchoring is future work.
4. **Artifact sensitivity:** tool output can contain tokens, cookies or personal
   data. Treat artifacts as engagement evidence.
5. **Log rotation:** the application does not rotate logs; use logrotate or a
   dedicated data directory.
6. **No sandbox:** external tools run as the operator's user. There is no
   container, seccomp or network namespace isolation.
7. **Dependency limits:** tool behavior and vulnerabilities are outside this
   project's control; keep tools updated and reviewed.

## Secure development rules

- No remote install scripts.
- No silent privileged operations.
- No `sh -c` in production code paths.
- New dependencies require justification, maintenance review and a license
  check.
- Parser fixtures must not contain live secrets or personal data.
- Scope, execution and audit changes require focused tests and review.
- Security-sensitive errors must fail closed.

## Data handling

- No telemetry or phone-home behavior exists.
- All storage is local.
- Reports may contain sensitive data; encrypt or restrict them as required by
  the engagement.
- Delete engagement data according to the client's retention policy.

## Disclosure

Please give maintainers a reasonable window to fix the issue before public
disclosure. Do not test third-party systems while researching this project.