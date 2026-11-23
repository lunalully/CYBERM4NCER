# Operations Hub

Status: **implemented** (`internal/banner`, `internal/hub`, `cyberm4ncer hub`,
bare invocation).

The Operations Hub is the interactive front end. It runs the same reviewed
aggressive engine, the same scope resolution and the same database records as
the `aggressive` command; it is an interface, not a second execution path.

## Starting it

```bash
cyberm4ncer                 # interactive terminal: opens the hub
cyberm4ncer hub             # same, explicit
cyberm4ncer hub 10.0.0.5    # opens with a session target already set
cyberm4ncer hub --scope engagement.yaml
```

Without a terminal (a pipe, a script, `CI`) a bare invocation prints the
header and the help text instead, so automation keeps working.

## What the screen shows

1. The CYBERM4NCER block-letter header in a neon violet gradient
   (`#38;5;56` deep, `129` middle, `165` core), framed and centered on wide
   terminals. `--no-color`, `NO_COLOR` and `TERM=dumb` fall back to plain text.
2. Real system state: `[ SYSTEM ONLINE ]` and `[ TOOLS 30/30 ready ]` from the
   detectors, never a scripted message.
3. Session context: target, scope, mode, level.
4. The menu, built from categories that map to real engine modes.

## Categories

| Key | Category | What it really does |
|---|---|---|
| 01 | Reconnaissance | aggressive `--mode recon` (amass, dnsx, httpx, subfinder, scanners, wafw00f, whatweb) |
| 02 | Network operations | aggressive `--mode enum` (nmap, masscan, naabu, rustscan, per-port service tools) |
| 03 | Web and API security | aggressive `enum`/`recon`/`vuln`/`all` for web tools |
| 04 | Vulnerability assessment | aggressive `--mode vuln` (nuclei, sqlmap, NSE scripts, TLS) |
| 05 | Credential testing | aggressive run with hydra/medusa (needs `--userlist`/`--passlist`) |
| 06 | Full aggressive run | aggressive `--mode all` |
| 07 | Tools and status | `tools detect`-equivalent table of the 30 manifests |
| 08 | Configuration and scope | scope file, targets, session reset |
| 09 | History and results | operations recorded in the local database |

Categories that map to no implemented engine (cloud security, custom modules,
reports) are **not** shown. Running `aggressive` remains the full-featured
non-interactive command.

## Workflow of an operation

1. Target asked when the session has none (host, IP, CIDR or URL; several
   separated by commas).
2. Execution settings: level, repetition cap, timeout, wordlist, credential
   lists, scope file.
3. The plan is shown (mode, target, scope, tools, invocations) and the run
   needs an explicit `y` confirmation.
4. The engine runs with its real progress; `Ctrl+C` cancels the running step.
5. The real summary is printed: status, steps, succeeded/failed/skipped,
   discovered assets, credential matches, artifact path and truthful notes
   (missing wordlist or tools are named).

## Navigation

| Input | Effect |
|---|---|
| `1` … `9`, `01` … | select an item |
| the item label (e.g. `TOOLS AND STATUS`) | same as its number |
| `b` / `back` | return to the previous screen |
| `q` / `exit` | leave the hub |
| `0` | the main menu's EXIT |
| `?` | redraw the current menu |
| anything else | reported as an invalid selection, menu stays |

## Guarantees

- Same planner, executor, scope check, timeouts, process groups and audit
  records as `aggressive`; the hub only assembles the options.
- Every command is an argv array from a reviewed manifest.
- Confirmations are required before a run starts.
- No fabricated output: the hub prints exactly what the engine reported.