# Aggressive Engine

Status: **implemented** (`internal/aggressive`, `cyberm4ncer aggressive`).

The aggressive engine turns one or more in-scope targets into a complete,
repeated run of every reviewed tool invocation. It is the project's "brute"
mode: maximum intensity, multiple rounds per tool, chained port discovery and
no built-in throttling beyond what each manifest declares.

## Guarantees

- Nothing runs without `--execute`; the default prints the exact plan.
- Commands are argv arrays from reviewed manifests, never shell strings.
- Every execution has a timeout, process-group cancellation, artifact files
  and a database record.
- Each target gets its own operation; the plan and the summary are written to
  the audit chain.
- **Scope is optional.** With `-s` (or a configured scope file) the target,
  every discovered asset and every per-port fan-out are checked against the
  policy **before** the process starts; a refused step is reported and
  skipped. Without a scope file the targets are used as given and each run is
  audited as `scope.unscoped`.

## Usage

```bash
# Plan only: tools, invocations, rounds and skips.
cyberm4ncer aggressive 10.0.0.5
# With an optional scope file, anything outside it is refused.
cyberm4ncer aggressive 10.0.0.5 --scope engagement.yaml

# Run everything at maximum intensity against one host.
cyberm4ncer aggressive 10.0.0.5 --scope engagement.yaml --execute

# Web-focused, three rounds, credential and destructive tools included.
cyberm4ncer aggressive https://app.example.com --scope engagement.yaml \
  --mode enum --repeat 3 --execute

# Many targets with a hard cap.
cyberm4ncer aggressive --file targets.txt --scope engagement.yaml \
  --max-steps 200 --execute
```

### Target placeholders

Manifests address the target with reviewed placeholders, and the engine fills
the one the manifest asked for:

| Placeholder | Value |
|---|---|
| `{{target}}` | host, `host:port` or URL, as the step scans it |
| `{{host}}` / `{{port}}` | bare host and port as separate arguments |
| `{{host:port}}` | `host:port` in a single argument |
| `{{url}}` | `http://` URL (kept from the operator's scheme) |
| `{{default_port}}` | the protocol default of a service step (22, 445, ...) |
| `{{wordlist}}`, `{{userlist}}`, `{{passlist}}` | operator-supplied lists |
| `{{out}}` | the step's report file or directory |

A flag without a value is never passed on its own, and an argument whose
placeholder has no value is dropped instead of being executed literally.

When the argv already carries `{{host}}`, `{{hostport}}` or `{{url}}`, the
reviewed target flag (`-u`, `-d`, `--url`) is not added again. URL tools
always receive a full URL with the operator's scheme and port (`ffuf -u
http://127.0.0.1:8081`); planned on a bare host they are checked against the
port they imply (80 for `http`, 443 for `https`) before running.

### Flags

| Flag | Meaning |
|---|---|
| `--scope`, `-s` | Scope file (default: configured or discovered) |
| `--file`, `-f` | One target per line, `#` comments allowed |
| `--mode` | `all`, `recon`, `enum`, `vuln` |
| `--level` | 1 to 5; selects the manifest `speed_args` (threads, rate, timing) |
| `--repeat` | Cap for each invocation's reviewed repeat count (0 = reviewed value) |
| `--timeout` | Per-execution timeout (0 = configured default) |
| `--execute` | Actually run the plan |
| `--max-steps` | Stop scheduling after N executions and report truncation |
| `--no-credentials` | Skip hydra/medusa invocations |
| `--no-intrusive` | Skip tools marked intrusive |
| `--wordlist` | Web wordlist (default `execution.wordlist`) |
| `--userlist`, `--passlist` | Credential lists for hydra/medusa |
| `--stream` | Show each tool's raw stdout/stderr live on stderr |

Both guards are opt-out, never opt-in: credential and intrusive tools are
included by default. Removing them is the operator's explicit choice.

## Execution model

1. **Plan.** Every manifest invocation that matches the mode becomes one or
   more `Step`s. Rounds repeat the same reviewed argv with the same target.
2. **Static steps.** Each step runs in plan order with a scope pre-check.
3. **Port discovery.** Steps with `port_discovery: true` add discovered
   host:port pairs to the capture set.
4. **Fan-out.** Steps with `uses_captured_ports: true` run once per captured
   **open** port for each planned round. A port only counts as open when a
   scanner explicitly reported it (`80/tcp open`, `Discovered open port`,
   `"port":8080`); mentions in prose or banners never trigger a connection.
   Each expanded step carries `host:port` as its target; the manifest decides
   how the tool receives it. `nc` and `telnet` take two positional arguments
   (`nc -v -w 3 127.0.0.1 445`, `telnet 127.0.0.1 445`), while `sslscan` and
   `testssl` take `host:port`. Every address named in the final argv is
   checked against the scope before the process starts.
5. **URL production.** Steps with `produces_urls: true` convert captured web
   ports into `http(s)://host[:port]/` URLs; URL-targeted tools receive them
   through their reviewed flag such as `-u`.
6. **Reporting.** A campaign summary (targets, steps, succeeded, failed,
   skipped, discovered assets, credential matches, elapsed, truncation) is
   printed and stored.

## Live progress

Every attempt is printed as it happens, numbered in execution order, so a run
is never silent:

```
executing 112 planned command(s) against 10.0.0.5 (level 5, timeout 10m0s, scope unscoped)
[1] round 1 nmap/top-ports on 10.0.0.5 -> -p- --min-rate 5000 -oX - 10.0.0.5
[1] OK nmap/top-ports on 10.0.0.5 exit=0 duration=41.802s
  + port 10.0.0.5:22
  + port 10.0.0.5:8080
[2] round 1 gobuster/dir-enum on http://10.0.0.5:8080 -> dir -q ... -u http://10.0.0.5:8080
[2] TIMEOUT gobuster/dir-enum on http://10.0.0.5:8080 exit=-1 duration=10m0s
    reason: timed out after 10m0s
    | 2026/01/01 00:00:00 wordlist missing
```

Each line carries the attempt number, the status (`OK`, `FAIL`, `TIMEOUT`,
`CANCELED`, `ERROR`), the real exit code and the measured duration. Failures
add the engine reason plus the first six non-empty lines of stderr (stdout when
stderr is empty), so a broken tool explains itself without opening the
artifacts. Discovered hosts, ports and URLs are reported as they are learned,
and each target ends with a one-line summary. The campaign closes with a
per-tool table (`RUNS`, `OK`, `FAIL`, `SKIP`, `TIME`).

The progress stream carries the engine's view; `--stream` additionally shows
the tools' own raw output (including progress bars) on stderr, keeping stdout
readable or valid JSON. Full streams are always kept in the artifact files and
every execution remains stored in the database.

## What is learned

| Source | Learned |
|---|---|
| nmap text (`80/tcp open`) | open ports on the scanned host |
| masscan (`Discovered open port`) | open ports on the reported host |
| naabu / rustscan JSON or text | open ports |
| httpx / katana / ffuf JSON | URLs |
| hydra / medusa (`[22][ssh] host: ...`) | the port under attack |
| subfinder / amass / dnsx / nmap | new hostnames |
| Report files (`-o`, `--log-json`, `-oJ`) | parsed exactly like stdout |

Helpers and stack traces are ignored: help screens (`Usage:`, flag tables),
source locations (`whatweb.rb:1421`), documentation prose ("Report bugs:
https://nmap.org/...") and vendor domains (`nmap.org`, `pythonhosted.org`,
`github.com`, `example.org`, ...) never become assets. Open ports are always
attributed to the host being scanned, never to an address found in a banner.

## Safety boundaries that remain

- **Scope is mandatory.** Targets, expanded `host:port` pairs and URLs are
  checked before execution; denials are reported per step and audited.
- **Data is local.** Artifacts and the database live in the data directory.
- **Timeouts exist per execution.** A hung tool is killed as a process group.
- **Optional campaign cap.** `--max-steps` bounds very large campaigns; it is
  off by default.

Everything else runs at the intensity selected: level 5 speed arguments,
multiple rounds and full wordlists.

## Credentials and wordlists

- Web tools receive `execution.wordlist` (default
  `/usr/share/wordlists/dirb/common.txt`, overridable with `--wordlist` or
  `CYBERM4NCER_WORDLIST`).
- hydra and medusa require `--userlist` and `--passlist`. Without them the step
  is skipped and listed under `skipped:` in the plan.
- hydra and medusa carry their protocol and port in the reviewed target
  (`hydra -I ssh://{{host}}:22`, `medusa -M ssh -h {{host}} -n 22`). Each is a
  single reviewed invocation, so it mirrors the installed tool exactly; the
  conventional port is checked against the port scope before it runs and a
  port-restricted engagement refuses it instead of falling back to the tool
  default.
- `wpscan` needs its local database (`wpscan --update` once after install).
- A successful login line is printed as `SUCCESS` and listed in the summary.

## Tool setup seen in the lab

`whatweb`, `wpscan` and `wafw00f` were installed and repaired on the lab host:

| Tool | Notes |
|---|---|
| `wafw00f` | `apt-get install wafw00f`; the version banner is coloured, so the detector strips ANSI before matching |
| `whatweb` | needs Ruby gems (fixed with `minitest`, `public_suffix`); PHP/`nokogiri` not required |
| `wpscan` | gems plus a database; `wpscan --update` after install |
| wordlists | `/usr/share/wordlists/dirb/common.txt` created as a symlink to SecLists `common.txt` |

## Known limitations

- Some tools print only human text; parsers learn URLs and ports, not
  vulnerability semantics. Structured findings arrive with the Result Engine.
- Tools that are installed but broken (Ruby gem errors, missing binaries) fail
  per step and are reported; nothing is hidden.
- Steps run sequentially per target. Concurrency, resume and per-URL fan-out
  are planned.