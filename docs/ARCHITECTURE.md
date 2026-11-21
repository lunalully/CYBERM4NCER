# Architecture

## Goals

1. Add a tool by writing an adapter and a manifest, without touching the core.
2. Add a module without changing configuration, logging or execution.
3. Make every target-facing operation scope-checked, time-bounded and auditable.
4. Keep memory use low and startup fast on modest machines.
5. Store evidence locally and keep the data directory portable.

## Non-goals (current phases)

- Exploitation, persistence, privilege escalation and exfiltration.
- A server, web UI or database service.
- Silent installation of external tools.
- Treating a tool's text output as a confirmed vulnerability without validation.

## Layering

```
                    ┌────────────────────────────┐
                    │        cmd / CLI           │
                    │  Cobra · human/JSON output │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │           core             │
                    │ lifecycle · composition    │
                    └───┬───────┬────────┬───────┘
                        │       │        │
          ┌─────────────▼─┐ ┌───▼────┐ ┌─▼─────────────┐
          │   config      │ │ logger │ │   database    │
          └───────────────┘ └────────┘ └───────┬───────┘
                                                │
   ┌──────────────┐   ┌──────────────────┐     │
   │   scope      │   │    execution     │─────┘
   │ policy/guard │◄──│ runner/artifacts │
   └──────────────┘   └────────┬─────────┘
                               │
                      ┌────────▼─────────┐
                      │      tools       │
                      │ manifests/probe  │
                      └──────────────────┘
```

### Package responsibilities

| Package | Responsibility | Must not |
|---|---|---|
| `internal/cli` | Parse flags, render output, map exit codes | Run processes or build SQL |
| `internal/core` | Wire services, own lifecycle | Implement domain logic |
| `internal/config` | Resolve defaults, YAML, env, flags; validate | Create runtime services |
| `internal/logger` | Structured logs to file and console | Contain domain rules |
| `internal/database` | Schema, migrations, queries, audit chain | Know about CLI or tools |
| `internal/scope` | Compile and evaluate authorization rules | Execute anything |
| `internal/execution` | Run argv safely, capture output, persist via recorder | Know module semantics |
| `internal/tools` | Manifests, compatibility, version probes | Install without consent |
| `internal/results` | Normalized finding model and fingerprint | Parse tool output (Phase 4) |

Modules and adapters (Phase 5+) will live in `internal/modules/<domain>` and
`internal/adapters/<tool>`. They receive interfaces from `core`; they do not
construct their own loggers, databases or process runners.

## Startup flow

1. `config.Load` resolves configuration in this order: defaults, YAML,
   `CYBERM4NCER_*` environment variables, CLI flags. Unknown YAML keys are
   rejected.
2. Paths are derived: database, artifacts, logs, tools.
3. Directories are created with mode `0700`.
4. The logger opens the log file with mode `0600`.
5. SQLite is opened with WAL, foreign keys and a busy timeout; migrations run.
6. Tool manifests embedded in the binary are validated and compiled.
7. The execution runner is built with the database recorder.
8. The detector is built on top of the runner.

Any partial failure closes already-opened resources.

## Execution flow

```
Request{Tool, Path, Args, Target, Timeout, OperationID}
   │
   ├─ validate tool/timeout
   ├─ acquire worker slot
   ├─ create artifact files (stdout.log, stderr.log)
   ├─ recorder.Start (abort if this fails)
   ├─ exec.CommandContext(path, args...)
   │    ├─ SysProcAttr.Setpgid = true
   │    ├─ Cancel = kill process group
   │    └─ WaitDelay = 3s
   ├─ stream stdout/stderr to file + bounded preview
   ├─ classify success/failed/timeout/canceled/error
   ├─ recorder.Finish with paths, preview, exit code
   └─ release worker slot
```

Process failures are returned as a `Result` with a status; the `error` return is
reserved for engine failures such as an invalid request, missing executable,
artifact failure or persistence failure. This lets callers distinguish "nmap
found nothing" from "nmap could not be traced".

### Scoped execution boundary

`core.Core.ExecuteScoped` is the only target-facing execution entry point. It
fails closed:

1. A nil policy returns `ErrScopeRequired`.
2. An empty target returns `ErrTargetRequired`.
3. A denied target is written to the audit log and returns `ScopeDeniedError`
   without starting a process.
4. An allowed decision is audited before the process starts.
5. If the audit write fails, nothing runs.

The raw runner is unexported inside `core`, so modules cannot call it directly
by accident. Internal maintenance commands (version probes, future installers)
use the non-target-facing runner and are not subject to scope.

The package tests prove that a denied target cannot execute a side effect, that
allowed execution is recorded, and that a missing policy or target is refused.

### Cancellation and timeout

`exec.CommandContext` receives a context with the request timeout. The custom
`Cancel` function sends `SIGKILL` to the negative PID, killing the whole
process group, including wrapper children. `WaitDelay` prevents an inherited
pipe from blocking shutdown forever. Recorder finalization uses
`context.WithoutCancel` plus a 5-second budget, so a timeout still records its
outcome.

### Output handling

- Full streams go to `artifacts/<execution-id>/{stdout,stderr}.log`.
- Each stream is capped by `execution.max_output_bytes`.
- A bounded preview is kept in memory and stored in SQLite.
- Truncation and write failures are exposed, never silently ignored.
- Paths are stored relative to the artifact root so the data directory can move.

### Secret handling

`execution.RedactArgs` removes values after credential flags (`--token`,
`--password`, `--api-key`, ...), header values (`-H`, `--header`) and URL
userinfo. Only redacted argv is persisted and logged. The real arguments go
directly to the child process. Tool adapters must never put secrets in the
`Target` field.

## Persistence model

| Table | Purpose |
|---|---|
| `projects` | Engagement/project grouping |
| `operations` | A unit of work (scan, workflow run, NUKE plan) |
| `executions` | One external process with argv, status, exit code, artifacts |
| `results` | Normalized findings (schema ready; writer in Phase 4) |
| `audit_log` | Hash-chained security-relevant actions |

The audit hash covers previous hash, timestamp, actor, action, target and
canonical detail JSON. `VerifyAudit` recomputes the chain. This detects
retroactive edits but does not protect against an attacker with full write
access replacing the whole database and chain; external anchoring is out of
scope for now.

SQLite runs with a single open connection (`MaxOpenConns(1)`) to avoid lock
contention on local disks. This is sufficient for the expected concurrency and
trades some read parallelism for predictability.

## Scope engine

The policy compiles include/exclude rules for domains, IPs and CIDRs, plus an
optional port allowlist. Exclusions are evaluated first. Host matches require a
label boundary (`host == domain` or `host` ends with `.domain`), so
`notexample.com` never matches `example.com`. IP literals only match IP/CIDR
rules. CIDR checks require full coverage; a partially covered range is denied.

The guarded HTTP client revalidates every redirect target. The initial request
must be checked by the caller (`GuardRequest`). DNS resolution is not used as
an authorization decision: scope defines names and ranges, not resolved
addresses. See the limitations in `docs/SCOPE_ENGINE.md`.

## Error handling

- Errors are wrapped with context and never swallowed.
- Configuration validation returns all failures joined together.
- Execution capture failures become warnings on the result; recorder failures
  become returned errors.
- CLI maps denied scope checks and failed doctor runs to explicit exit codes.
- `doctor` and `go vet`/`go test` are the supported health checks.

## Performance

- No background services, no model loading, no TUI dependency.
- Tool manifests are embedded; startup does not touch the network.
- Only enabled commands construct the core; `version`, `tools list/info` and
  `scope validate` avoid the database.
- Worker and detection concurrency are configurable.
- SQLite + WAL keeps writes local and synchronous-free at the application level.

## Planned evolution

- Phase 3: reviewed per-method installers, checksums, managed tool directory.
- Phase 4: per-tool parsers emitting `internal/results.Result`, dedup upserts,
  evidence records.
- Phase 5: module contracts, RECON/WEB actions, adapters.
- Phase 6: API Security module with explicit credentialed-test consent.
- Phase 7: YAML workflow DAG with dependencies and bounded parallelism.
- Phase 8: NUKE planner/executor with mandatory confirmation and kill switch.
- Phase 9: reports from the result store.