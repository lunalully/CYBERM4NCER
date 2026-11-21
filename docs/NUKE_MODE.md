# NUKE Mode

Status: **design only (Phase 8).** No `nuke` command exists in 0.1.0.

## Definition

NUKE is a bounded operation orchestrator, not a command that runs every tool
indiscriminately. It plans an engagement from an approved profile, validates
scope, requests confirmation, executes controlled steps, consolidates results
and produces a report.

## Profiles

| Profile | Behavior |
|---|---|
| `manual` | Operator selects each tool/action; framework validates and records |
| `assisted` | Framework recommends next steps; operator confirms each |
| `auto` | Runs pre-approved workflows with fixed limits |
| `nuke` | Full configured operation across approved workflows and budgets |

The default is `manual`/`assisted`. `auto` and `nuke` never imply destructive
actions.

## Mandatory controls

- Scope validation before planning and before every step.
- Allowlist of modules/actions for the selected profile.
- Rate limiting per host and globally.
- Concurrency limit shared with the execution engine.
- Per-step, per-operation and global time budgets.
- Exclusion list; exclusions always win.
- Redirect policy enforced by adapters and the internal HTTP client.
- Explicit confirmation for intrusive tools/templates.
- Kill switch that cancels the operation and all process groups.
- Full audit: plan, confirmations, executions, cancellations, report hash.
- Refusal to run when authorization is missing or expired.
- No privilege escalation, persistence, destructive exploitation, data
  exfiltration or lateral movement.
- No credential collection; operator-supplied credentials only.
- No automatic tool installation during an operation.

## Plan artifact

Before execution NUKE will render a plan containing:

- project, authorization reference and scope digest
- profile and workflow versions
- exact actions, tools and argument templates
- expected intrusive steps
- rate/concurrency/time limits
- estimated target count
- exclusions
- report destinations

The plan is written to the data directory and hashed in the audit log. The
operator confirms the hash, not just a prompt.

## Modes and safety gates

```
scope load → plan → confirmation → execute → monitor → cancel/complete → report
                     │
                     ├─ intrusive step → separate confirmation
                     ├─ scope violation → abort
                     ├─ budget exceeded → cancel
                     └─ SIGINT/SIGTERM → kill process groups → record
```

## Prohibited in automatic execution

- Exploitation with side effects (write/drop/delete/upload).
- Password spraying beyond configured, rate-limited budgets.
- Persistence, tunnels, reverse shells, credential dumping.
- Data exfiltration or modification of target state.
- Denial-of-service or resource-exhaustion templates.
- Unbounded fuzzing.

## Kill switch

- Cancels the operation context.
- Kills every active process group.
- Stops scheduling new steps.
- Writes terminal status per step and operation.
- Produces a partial report marked incomplete.
- Leaves artifacts and audit records intact.

## Phase 8 acceptance criteria

- Planner tests for scope, exclusions, allowlist and budgets.
- Confirmation tests: no intrusive step without explicit consent.
- Cancellation test with a child-process group.
- Run records prove every step and every tool invocation.
- A simulated operation uses mock adapters and no network.
- Report clearly separates confirmed, potential and informational findings.