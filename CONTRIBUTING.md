# Contributing

CYBERM4NCER is developed in phases. Contributions must fit the current phase
and preserve the safety boundaries.

## Before opening a PR

1. Read `docs/ARCHITECTURE.md`, `SECURITY.md` and the current phase in
   `docs/ROADMAP.md`.
2. Open an issue for substantial changes, new dependencies or architecture
   changes.
3. Do not add features that the roadmap places in a later phase without
   agreement.
4. Do not copy code, branding or text from other offensive-security products.

## Development checks

```bash
make check
```

This runs:

- `gofmt` verification
- `go vet ./...`
- `go test ./...`

Also run targeted tests and, for scope/execution/parser changes, the race
detector:

```bash
go test -race ./internal/core ./internal/scope ./internal/execution ./internal/database
```

CI must pass without network access. Tests must not require live targets.

## Engineering rules

- Do not mix CLI/presentation logic with execution or persistence.
- Do not build shell command strings. Pass argv arrays.
- Every process execution goes through `internal/execution`.
- Every external target goes through `internal/scope`.
- Every execution needs timeout and cancellation support.
- Do not swallow errors. Wrap them with context.
- Do not add a dependency without a maintenance/license/security justification.
- Do not add a module without a defined responsibility and tests.
- Do not present planned features as implemented. No placeholder commands.
- Do not install tools or run remote scripts automatically.
- Do not commit real credentials, target data, tokens or personal data.

## Adding a tool manifest

See `docs/TOOL_MANAGER.md`. Verify the official repository, license, binary,
version command and minimum version. Add a live detection check and a parser
fixture if an adapter exists.

## Adding a parser

- Prefer official JSON/JSONL/XML/SARIF output.
- Put fixtures in `testdata/`; never use live engagement data.
- Test empty, malformed, truncated and duplicate output.
- Emit `internal/results.Result` with tool provenance, severity and evidence.
- Do not mark a finding validated without sufficient evidence.
- Do not discard evidence during deduplication.

## Adding a module or adapter

- Module contracts will be introduced in Phase 5.
- An adapter owns tool invocation, argument construction and parsing for exactly
  one tool.
- Adapters receive scope and execution services; they do not create their own.
- Adapters must disable redirect following when the tool supports it and must
  document any residual behavior.
- Intrusive actions need explicit confirmation and audit.
- Tests use mocks/fixtures; no external targets.

## Code style

- Standard Go formatting; wrap errors with `%w`.
- Small packages with a single responsibility.
- Prefer explicit types over `any` at package boundaries.
- Context first argument for blocking operations.
- Keep CLI output free of secrets and unnecessary noise.
- Comments explain decisions, not syntax.

## Commits and pull requests

- Use focused commits with imperative messages.
- Describe what changed, why, security impact, tests run and documentation
  updated.
- Include the exact `make check` result.
- Call out breaking changes and migration impact.
- Contributions are accepted under the MIT license (see `LICENSE`). By opening
  a pull request you agree that your contribution may be distributed under
  that license.

## Documentation

Every user-visible change needs:

- CLI help text
- `docs/CLI_REFERENCE.md` update
- configuration/scope documentation when applicable
- tool page for a new tool
- phase report update when a phase closes

## Reporting security issues

See `SECURITY.md`. Never open a public issue for a vulnerability.