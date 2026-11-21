# Quick Start

1. Build and verify:

```bash
make build
./dist/cyberm4ncer doctor
```

2. Create a configuration file:

```bash
./dist/cyberm4ncer config init
./dist/cyberm4ncer config show
```

3. Create a scope file. Do not copy a scope from another engagement.

```yaml
version: 1
project: acme-web
authorization: "ENG-2026-014, signed by Acme Security, valid until 2026-12-31"
includes:
  - domain: example.com
    subdomains: true
  - cidr: 203.0.113.0/24
excludes:
  - domain: billing.example.com
    subdomains: true
ports: [80, 443]
```

4. Validate the scope and test decisions:

```bash
./dist/cyberm4ncer scope validate engagement.yaml
./dist/cyberm4ncer scope check app.example.com --file engagement.yaml
./dist/cyberm4ncer scope check 203.0.113.10 --file engagement.yaml
./dist/cyberm4ncer scope check 10.0.0.1 --file engagement.yaml
```

The last command must exit with code 2 (denied).

5. Inspect supported tools:

```bash
./dist/cyberm4ncer tools list
./dist/cyberm4ncer tools detect nuclei
```

6. Check the installation:

```bash
./dist/cyberm4ncer doctor
```

At this stage there are no scan commands. Modules are delivered in later phases;
the CLI does not register placeholders. See `docs/ROADMAP.md`.

## Data locations

`cyberm4ncer config path` prints every resolved path:

- configuration file
- data directory
- SQLite database
- artifacts (full stdout/stderr)
- logs
- managed tools directory

## JSON output

Most commands accept the global `--json` flag:

```bash
cyberm4ncer --json doctor
cyberm4ncer --json scope check app.example.com --file engagement.yaml
cyberm4ncer --json tools detect
```

Logs are written to stderr and the log file; JSON output stays on stdout.