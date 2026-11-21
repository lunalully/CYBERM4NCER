# Result Engine

Status: **model implemented; parsing and persistence are Phase 4.**

External tools emit incompatible formats. The result engine defines one
internal shape so modules, storage and reports do not depend on a tool's text
output.

## Model

```go
type Result struct {
    ID          string
    ProjectID   string
    OperationID string
    ExecutionID string
    Asset       string   // normalized host/URL/range
    Kind        string   // subdomain, service, endpoint, finding, ...
    Source      string   // module/action
    Tool        string   // originating tool
    Severity    Severity // unknown, info, low, medium, high, critical
    Title       string
    Description string
    Evidence    string
    References  []string
    Data        map[string]any
    Fingerprint string
    Validated   bool
    CreatedAt   time.Time
    LastSeenAt  time.Time
}
```

The SQLite `results` table is already part of schema v1. There is no writer yet;
no command claims to produce results.

## Deduplication

`results.Fingerprint` hashes:

- tool (lowercase)
- kind
- asset (lowercase)
- normalized title (whitespace collapsed, lowercase)
- location (for example a URL)

Evidence is deliberately excluded. Repeated scans of the same issue converge on
one fingerprint while new evidence can be attached to the same finding. Phase 4
will store occurrences/evidence separately so deduplication never discards
proof.

## Severity

Severity is normalized, not blindly copied:

| Input examples | Normalized |
|---|---|
| `informational` | `info` |
| `moderate` | `medium` |
| `critical` | `critical` |
| empty/unknown | `unknown` |

Ordering: critical > high > medium > low > info > unknown. The presence of a
severity does not mean a vulnerability is confirmed. `Validated` is set only
after explicit validation with sufficient evidence.

## Parsing policy (Phase 4)

Priority order:

1. Official JSON/JSONL/XML/SARIF output.
2. Documented structured flags with stable schemas.
3. Text parsing only as a last resort, with fixture tests and explicit
   limitations.

Each parser will be independent:

```
internal/adapters/<tool>/
  manifest.go / manifest.yaml
  runner.go
  parse.go
  parse_test.go
  testdata/*.json
```

Parser tests use checked-in fixtures. They never require a live target or a
network connection. Malformed, empty and truncated outputs must be covered.

## Persistence plan

- Insert a result, or update `last_seen_at` when `(project_id, fingerprint)`
  matches.
- Append evidence/occurrence rows instead of overwriting evidence.
- Link `execution_id` to the exact process that produced the finding.
- Store raw structured payload in `data_json` with size limits.
- Keep tool provenance for reports.
- Refuse to mark a result validated without an explicit operator/validation
  step.

## Reporting (Phase 9)

Reports consume only normalized results, never tool text. Planned formats: HTML,
JSON, Markdown, CSV. Fields: executive summary, severity counts, affected
assets, evidence, references, CVSS metadata, recommendations, tool provenance
and scan history.