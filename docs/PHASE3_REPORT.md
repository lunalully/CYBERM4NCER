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
  port-consuming invocation on a tool that is neither `hostport` nor `free`,
  is rejected at load time.
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

## Second validation round (installation and fixes)

The lab host was repaired and the engine validated again, still only against
`127.0.0.1`. Every problem found in the first round was fixed in code or in a
manifest, not worked around by hand.

### Environment installed

| Item | Result |
|---|---|
| `wafw00f` 2.3.1 | `apt-get install wafw00f` |
| `whatweb` 0.5.5 | runs after `gem install minitest public_suffix` for the user install |
| `wpscan` 4.2.0 | runs after the missing gems (`nokogiri`, `racc`, `xmlrpc`, `rexml`, `webrick`) and `wpscan --update` |
| `dirb/common.txt` | symlinked to SecLists `Discovery/Web-Content/common.txt` (4751 entries) |

`cyberm4ncer tools detect` now reports **30 of 30 tools installed and ready**.
Version parsing handles the coloured wafw00f banner and wpscan's
`Current Version:` line (ANSI escapes are stripped before matching).

### Defects found live and fixed

| Symptom | Cause | Fix |
|---|---|---|
| `nmap`/`masscan`/`naabu` received `http://127.0.0.1:8081` | scanners got the URL | target placeholder returns host or `host:port` for non-URL tools |
| `nmap ... 127.0.0.1 127.0.0.1` (target twice) | positional `{{network}}` plus the target flag | single reviewed target argument, flag only when the manifest has one |
| `whatweb --url` ambiguous error | `--url` is a prefix of three flags | positional target mode |
| `wpscan` aborted: database missing | first run on a fresh install | documented `wpscan --update`; no code change |
| hydra `-s 22 ... -s 127.0.0.1:22` | target and port shared one flag | hydra reviewed as `-I ssh://{{host}}:22`, medusa as `-h {{host}} -n 22` (single reviewed invocation, port checked against the scope) |
| `amass`/`gobuster dns`/`subfinder` ran without a target | positional-only option received nothing | reviewed `value: "{{target}}"` in the manifest |
| ffuf/gobuster `-u` lost | the flag was in the map but its value was not filled | option values resolved through the reviewed flag |
| false open port `127.0.0.1:22` from the hydra success line | credential lines added their port to the assets | only proven open ports feed the fan-out; parsed assets stay recorded |
| `nc`/`telnet`/`sslscan`/`testssl` connected to the bare host (port 80) | captured-port tools used the target flag for a URL | documented contract: these manifests put host and port as separate arguments |
| duplicated URL-target option values | the target was filled twice | one place builds the target value |

New tests cover the target placeholder, the scope refusal of conventional
service ports, verified open-port-only fan-out, and a regression test that
replays every planned step and fails if the target appears twice, if a
template is left unresolved or if a flag is emitted without its value.

### Numbers after the fixes

| Scenario | Result |
|---|---|
| `tools detect` | 30/30 ready |
| `all`, repeat 1, port-restricted scope | 81-94 steps, 13 ports captured, protocols outside the scope refused (`ssh`, `ftp`, `mysql`, `rdp`, port 80) |
| `all`, level 5, repeat 2, full lists | 177 steps in 9m18s on `127.0.0.1`, 15 assets discovered, campaigns per target recorded |
| `recon` on `http://127.0.0.1:8081` | whatweb and wafw00f run against the URL, nmap on the bare host |

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