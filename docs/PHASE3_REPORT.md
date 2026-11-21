# Phase 3 — Aggressive Engine Report

Date: 2026-11-21
Status: delivered for review
Version: 0.2.0-dev

## Objective

Deliver the aggressive scan mode requested by the operator: every reviewed
tool, repeated many times in its strongest setting, with discovered open ports
chained into the next round, and a complete record of every execution — with
the scope as the only enforced boundary.

## Delivered

### Tool metadata (`internal/tools`)

- `usage` block per manifest: `target_mode`, `target_flags`, `speed_args` for
  levels 1..5, `default_ports`, `url_paths`.
- `invocations`: mode, reviewed argv template, `repeat`, `port_discovery`,
  `uses_captured_ports`, `produces_urls`, `accept_exit_codes`,
  `success_regex`, options (flag + optional fixed value).
- Validation: an invocation that both discovers and consumes ports, or a
  port-consuming invocation on a non-`hostport` tool, is rejected at load time.
- 30 manifests carried invocations into this phase; httpx, dnsx and ffuf were
  corrected after live validation (target flag `-u`, wordlist option, vhost
  header fixed by `option value`).

### Aggressive engine (`internal/aggressive`)

- `plan.go` — planner, template resolution, mode/level/repeat quota, speed
  arguments, custom `Step` JSON.
- `run.go` — executor over the scoped execution callback, per-step scope
  pre-check, per-port fan-out, report reading (`-o`, `--log-json`, `-oJ`),
  `--max-steps`, credential match reporting.
- `parse.go` — output parsing for nmap/masscan text, JSON/JSONL (first),
  hydra lines and bare URLs; ignores help screens, banner art, tracebacks,
  documentation prose, vendor domains (`nmap.org`, `sqlmap.org`,
  `pythonhosted.org`, `github.com`, `example.*`, ...) and URL hosts that are
  not valid hostnames.
- `captures.go` — deduplicated, sorted asset set and `WebURLs`.
- Tests: plan/scope/quota, expansion, argument building, parsing, captures,
  max-steps, refused assets, reviewed option values (hermetic shell fakes).

### Core and CLI

- `core.NewAggressive(mode)` / `AggressiveService.Plan/Run` on top of
  `core.ExecuteScoped`.
- `cyberm4ncer aggressive [targets...]` with `--file`, `--mode`, `--level`,
  `--repeat`, `--timeout`, `--execute`, `--max-steps`, `--no-credentials`,
  `--no-intrusive`, `--wordlist`, `--userlist`, `--passlist`.
- One operation per target, plan and run written to the audit chain, campaign
  summary in text and `--json`.
- `execution.wordlist` configuration and `CYBERM4NCER_WORDLIST`.

## Live validation (127.0.0.1 only)

Lab: busybox httpd on 127.0.0.1:8081, python http.server on 0.0.0.0:8080,
socat TCP chat on 0.0.0.0:2222. Scope files include only `127.0.0.1`.

| Scenario | Result |
|---|---|
| Plan only | 30 tools, 112 invocations, no execution |
| Port restricted scope (`ports: [8080, 8081, 2222]`) | URL-driven tools denied on implied port 80 and audited |
| `enum`, level 3, repeat 2 on `127.0.0.1` | 63 steps, port 8080 discovered, nc/telnet expanded per port |
| `all`, level 5, repeat 2 on `127.0.0.1` | 89 steps (30 tools), 8080 captured and fanned out, no false assets |
| `all`, repeat 2 on `http://127.0.0.1:8081` | 21 steps, 8081 captured, sslscan/testssl fanned out per port |
| Two targets with `--max-steps 5` | 2 operations, campaign truncated, exit 0 |
| Credential run with hydra/medusa lists | Steps executed, no match on the fake service |
| Out-of-scope target | Denied before planning, exit 1 |

Database after the runs: one `operations` row per target
(`kind=aggressive`, `profile=<mode>/l<level>`), `executions` rows per command,
`aggressive.plan`, `aggressive.run`, `scope.allowed` and `scope.denied` audit
entries.

## Failures observed and explained

- `wafw00f` is not installed; `whatweb` and `wpscan` fail on missing Ruby gems
  in this environment. The engine reports each failure per step.
- `naabu` needs root for raw sockets; `nmap` runs in connect fallback here.
- `/usr/share/wordlists/dirb/common.txt` does not exist in this lab, so web
  brute-force steps failed with "wordlist not found"; the CLI warns before the
  run and `--wordlist` overrides the path.

## Boundaries kept

- Scope is required and enforced before every process start, including
  per-port fan-out and URL-targeted tools (implied port 80/443 is checked).
- No shell strings; argv arrays only.
- Timeouts and process-group cancellation on every execution.
- No installation, no signature checks (per operator decision).

## Next

- Result Engine (structured findings from tool output).
- Concurrent execution and resume.
- Per-URL fan-out for web crawlers.