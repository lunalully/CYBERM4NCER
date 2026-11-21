# Configuration

Configuration precedence, lowest to highest:

1. built-in defaults
2. YAML file
3. `CYBERM4NCER_*` environment variables
4. CLI flags

Unknown YAML keys are rejected. Durations use Go syntax (`30s`, `10m`, `2h`).

## File

Default path: `$XDG_CONFIG_HOME/cyberm4ncer/config.yaml` or
`~/.config/cyberm4ncer/config.yaml`.

Create it with:

```bash
cyberm4ncer config init
```

## Reference

```yaml
version: 1
data_dir: ""                    # empty: XDG data directory

database:
  path: ""                      # empty: <data_dir>/cyberm4ncer.db

execution:
  workers: 4                    # 1..256
  default_timeout: 10m          # 1s..24h
  max_output_bytes: 33554432    # 1 MiB..1 GiB, per stream
  preview_bytes: 65536          # 1 KiB..16 MiB, <= max_output_bytes
  wordlist: /usr/share/wordlists/dirb/common.txt

logging:
  level: info                   # debug, info, warn, error (file)
  format: text                  # text, json
  file: ""                      # empty: <data_dir>/logs/cyberm4ncer.log

scope:
  file: ""                      # empty: auto-discovery

tools:
  dir: ""                       # empty: <data_dir>/tools
  version_timeout: 5s           # 1s..2m
  detect_concurrency: 4         # 1..64
```

## Environment variables

| Variable | Maps to |
|---|---|
| `CYBERM4NCER_CONFIG` | configuration file path |
| `CYBERM4NCER_DATA_DIR` | `data_dir` |
| `CYBERM4NCER_LOG_LEVEL` | `logging.level` |
| `CYBERM4NCER_LOG_FORMAT` | `logging.format` |
| `CYBERM4NCER_SCOPE_FILE` | `scope.file` |
| `CYBERM4NCER_WORKERS` | `execution.workers` |
| `CYBERM4NCER_WORDLIST` | `execution.wordlist` |

Environment variables do not expand inside path values. A leading `~` is
expanded; other variables are left untouched so configuration cannot silently
depend on ambient secrets.

`execution.wordlist` is the default web wordlist for
`cyberm4ncer aggressive`. `--wordlist` on the command line overrides it.

## Paths and permissions

- Data, artifacts, logs and tools directories are created with `0700`.
- The database and log file use `0600`.
- Artifact paths are stored relative to `<data_dir>/artifacts`.
- `cyberm4ncer config path` shows every resolved path.

## Logging

The log file receives the configured level. The console receives warnings and
errors by default, keeping command output clean; `--verbose` sends debug logs to
the console as well. Log files are append-only and currently not rotated by the
application. Use logrotate or a dedicated data directory for long engagements.

## Scope discovery

If `scope.file` is empty, the CLI looks for `./.cyberm4ncer/scope.yaml` and then
`<data_dir>/scope.yaml`. A scope file is never generated automatically because
it must contain a real authorization statement.

## Credentials

Never put credentials in the configuration file. Tool adapters will accept
credentials through environment variables or restrictive files (mode `0600`).
Arguments that look like secrets are redacted from logs and the database.

## Validation failures

`config.Load` returns all semantic failures joined together: unsupported
version, invalid ranges, invalid log format/level, incompatible output limits.
No command silently repairs an invalid configuration.