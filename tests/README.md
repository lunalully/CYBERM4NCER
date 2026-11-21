# Integration Tests

Unit tests are co-located with their packages, following Go convention:

```bash
go test ./...
```

This directory is reserved for integration tests that exercise multiple
packages, such as:

- CLI → scope → execution with mocked tools
- parser → result store → report
- workflow DAG with mock adapters
- cancellation propagating across a workflow

Rules:

- No external network access and no real targets.
- No real credentials or engagement data.
- Use local fixtures and test doubles.
- Tests must pass in CI without installed offensive tools.
- A test that needs an optional local tool must skip explicitly and document
  why.

No integration suite exists yet; it arrives with the result and workflow phases.