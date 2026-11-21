# Installation

License: MIT (see `LICENSE`). Installation from source does not require
authenticating against the private repository beyond your existing access.

## Requirements

- Linux amd64 or arm64 (other Go-supported platforms may build)
- Go 1.24 or newer for source builds
- No root, Docker, CGO or graphical environment

## Build from source

```bash
git clone https://github.com/lunalully/CYBERM4NCER.git
cd CYBERM4NCER
make build
./dist/cyberm4ncer version
```

`make build` sets version, commit and build date from Git and produces a static
binary with `CGO_ENABLED=0`.

Direct build:

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w" \
  -o cyberm4ncer ./cmd/cyberm4ncer
```

## Cross-compilation

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 make build
```

`modernc.org/sqlite` is pure Go, so cross-compilation does not require a C
toolchain.

## Install locally

```bash
make install            # installs to ~/.local/bin
PREFIX=/usr/local make install
```

Do not use `sudo` unless you intentionally install to a system path.

## First run

```bash
cyberm4ncer doctor
cyberm4ncer config init
cyberm4ncer config show
cyberm4ncer tools list
```

The default data directory is `$XDG_DATA_HOME/cyberm4ncer` or
`~/.local/share/cyberm4ncer`. The configuration file defaults to
`$XDG_CONFIG_HOME/cyberm4ncer/config.yaml` or
`~/.config/cyberm4ncer/config.yaml`.

No directory is created until a command needs the core. `doctor` creates the
data directory, database and log file.

## External tools

CYBERM4NCER detects tools already installed in `PATH`:

```bash
cyberm4ncer tools detect
```

Tool installation is **not implemented** in 0.1.0. Install external tools using
your distribution or the official project's reviewed release, then verify with
`tools detect`. The framework never runs remote install scripts.

## Updating

```bash
git pull
make check
make build
```

Database migrations are applied automatically by core commands. Migrations are
append-only; keep a backup of your data directory before upgrading.

## Uninstalling

The framework installs no system service and no cron job. Remove the binary and,
if desired, the data directory:

```bash
rm ~/.local/bin/cyberm4ncer
rm -rf ~/.local/share/cyberm4ncer
rm -rf ~/.config/cyberm4ncer
```

Review the scope files and evidence before deleting the data directory.