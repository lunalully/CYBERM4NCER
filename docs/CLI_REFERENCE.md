# CLI Reference

Binary: `cyberm4ncer`

## Global flags

| Flag | Description |
|---|---|
| `--config <path>` | Configuration file |
| `--data-dir <path>` | Override the data directory |
| `--log-level <level>` | Override `debug`, `info`, `warn` or `error` |
| `--json` | Machine-readable output on stdout |
| `--no-color` | Disable ANSI colors |
| `-v, --verbose` | Debug logging to the console |
| `--version` | Print the binary version |
| `-h, --help` | Help for any command |

Colors are disabled automatically for non-terminals, `NO_COLOR`, and
`TERM=dumb`. Logs go to stderr and to the configured log file.

## Implemented commands

### `cyberm4ncer version`

Prints version, commit, build date, Go toolchain and platform. With `--json`,
prints the same fields as JSON.

### `cyberm4ncer doctor [--skip-tools]`

Checks:

- platform and build
- configuration file discovery
- data directory writability
- SQLite schema and statistics
- audit hash-chain integrity
- scope file validity (if configured)
- log file
- external tool versions (unless `--skip-tools`)

Exit code 1 when a critical check fails. Missing tools and missing scope are
warnings.

### `cyberm4ncer config show`

Prints the resolved configuration as YAML (or JSON with `--json`). This includes
resolved data, database and log paths.

### `cyberm4ncer config path`

Prints configuration file, data directory, database, artifacts, logs, log file
and tools directory.

### `cyberm4ncer config init [--force]`

Creates a default configuration file. Refuses to overwrite unless `--force` is
given. The file is created with mode `0600`.

### `cyberm4ncer scope validate [file]`

Compiles and summarizes a scope file. Without an argument, resolution order is:

1. `scope.file` from configuration
2. `./.cyberm4ncer/scope.yaml`
3. `<data-dir>/scope.yaml`

Exit code 0 valid, 1 invalid or missing.

### `cyberm4ncer scope check <target> [--file/-f <file>]`

Evaluates a hostname, IP, CIDR or HTTP(S) URL.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Allowed |
| 1 | Invalid target or scope error |
| 2 | Denied by scope |

### `cyberm4ncer tools list [--detect] [--category <category>]`

Lists embedded manifests. Without `--detect`, only checks `PATH` (fast). With
`--detect`, runs each version command through the execution engine.

### `cyberm4ncer tools info <tool>`

Shows the manifest: description, category, versions, risk, architectures,
capabilities, outputs, version command and declarative install methods.
Install methods are metadata only in 0.1.0.

### `cyberm4ncer tools detect [tool...]`

Runs version detection for all manifests or the named tools. Exit code 1 if any
tool is missing, incompatible or unverified.

### `cyberm4ncer aggressive [targets...]`

Plans (default) or runs the exhaustive repeated scan described in
[`AGGRESSIVE_ENGINE.md`](AGGRESSIVE_ENGINE.md). Targets may be positional
arguments or listed in `--file`, and the same scope policy is enforced for each.

| Flag | Meaning |
|---|---|
| `--scope/-s` | Scope file |
| `--file/-f` | File with one target per line (`#` comments allowed) |
| `--mode` | `all`, `recon`, `enum`, `vuln` |
| `--level` | 1..5 speed arguments |
| `--repeat` | Cap per-invocation repetitions (0 keeps reviewed values) |
| `--timeout` | Per-execution timeout |
| `--execute` | Run the plan (default prints it) |
| `--max-steps` | Stop after N executions (0 is unlimited) |
| `--no-credentials` | Skip hydra/medusa |
| `--no-intrusive` | Skip intrusive tools |
| `--wordlist` | Web wordlist (default `execution.wordlist`) |
| `--userlist`, `--passlist` | Credential lists for hydra/medusa |

Exit codes: 0 success or plan-only, 1 error or scope denial, 130 interrupted.
`--json` prints the plan or the campaign summary as JSON.

```
cyberm4ncer aggressive 10.0.0.5 --scope engagement.yaml
cyberm4ncer aggressive 10.0.0.5 --scope engagement.yaml --execute
cyberm4ncer aggressive https://app.example.com -s engagement.yaml --mode enum --repeat 3 --execute
cyberm4ncer aggressive --file targets.txt -s engagement.yaml --max-steps 200 --execute
```

## Planned commands

These commands are **not registered** until their phases are complete:

| Command | Phase |
|---|---|
| `tools install`, `tools update`, `tools remove` | 3 |
| `results list`, `results show` | 4 |
| `recon`, `web` | 5 |
| `api` | 6 |
| `workflow list`, `workflow run` | 7 |
| `nuke` | 8 |
| `report` | 9 |
| `manual`, `manual <tool>` | with tool adapters |

The absence of a command is intentional; there are no placeholder stubs.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error or failed health check |
| 2 | Scope denial |
| 130 | Interrupted (SIGINT/SIGTERM) |

## Examples

```bash
cyberm4ncer --data-dir /tmp/c4n doctor --skip-tools
cyberm4ncer scope validate engagement.yaml
cyberm4ncer --json scope check 10.0.0.0/24 --file engagement.yaml
cyberm4ncer tools list --category vulnerability
cyberm4ncer tools detect nuclei sqlmap
cyberm4ncer --json config show
```