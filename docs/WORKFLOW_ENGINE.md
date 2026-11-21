# Workflow Engine

Status: **design only (Phase 7).** No workflow command is registered in 0.1.0.

## Purpose

A workflow is a reviewed YAML DAG of module actions. It replaces opaque shell
"scan modes" with explicit steps, dependencies, limits and conditions.

## Draft format

```yaml
name: web-assessment
version: 1
description: Conservative web assessment
scope: engagement.yaml

defaults:
  timeout: 10m
  retries: 0
  intrusive: false

steps:
  - id: subdomains
    module: recon
    action: subdomain-discovery
    with:
      target: "{{ target }}"
    timeout: 15m

  - id: http
    module: recon
    action: http-probing
    needs: [subdomains]
    with:
      input: "{{ steps.subdomains.assets }}"

  - id: crawl
    module: web
    action: crawling
    needs: [http]
    with:
      input: "{{ steps.http.live_urls }}"

  - id: passive
    module: vulnerability
    action: passive-assessment
    needs: [http]
    with:
      input: "{{ steps.http.live_urls }}"

  - id: review
    module: reporting
    action: summarize
    needs: [crawl, passive]
```

## Required engine behavior

1. Parse with `KnownFields(true)`; unknown keys fail.
2. Validate the DAG: unique IDs, known modules/actions, no cycles.
3. Validate scope before starting any step.
4. Re-check scope for every resolved target, including values produced by
   previous steps.
5. Do not run a step if a dependency failed or was skipped.
6. Enforce per-step timeout and the workflow global deadline.
7. Bound parallelism with a configured worker limit.
8. Propagate cancellation to running process groups.
9. Persist every step as an operation/execution linked to the workflow run.
10. Redact secrets in variables, logs and records.
11. Require explicit confirmation for steps marked intrusive.
12. Never evaluate arbitrary shell code. Variable interpolation is typed and
    restricted to documented fields.
13. Distinguish "no results" from failure.
14. Support resume only when the previous state is consistent and recorded.

## Variables

- `{{ target }}` — validated initial target.
- `{{ steps.<id>.<output> }}` — typed output of a successful dependency.
- `{{ env.NAME }}` — only for an allowlist of non-secret settings; credentials
  should come from the adapter's secure input, not workflow text.
- No shell expansion, command substitution, globbing or template functions.

## Conditions

A step may declare a condition over dependency status/counts, for example:

```yaml
when: "steps.http.count > 0"
```

Conditions are small typed expressions, not a general-purpose language. The
implementation will use a restricted parser and tests; it will not use `eval`.

## Parallelism

- `needs` defines ordering.
- Independent ready steps may run in parallel up to `defaults.parallel`.
- A failure cancels dependent branches, not unrelated branches, unless
  `on_failure: abort` is set.
- Global concurrency can never exceed the execution worker limit.

## Persistence

A workflow run is an operation. Each step gets its own execution record and
artifact directory. Status vocabulary: `pending`, `running`, `success`,
`failed`, `skipped`, `canceled`, `timeout`.

## Non-goals

- Storing workflows downloaded from the internet.
- Implicit tool installation during a run.
- Workflows that contain raw shell snippets.
- Automatic destructive steps.

## Phase 7 acceptance criteria

- Unit tests for DAG validation, cycles, dependency failure, conditions,
  timeout, cancellation and variable redaction.
- An integration test with mock adapters that never touches the network.
- Documentation and a validated example workflow.
- Scope revalidation proven for intermediate outputs.