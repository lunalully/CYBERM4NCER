# Modules

Modules are introduced in Phases 5–6, after the tool manager and result engine.

| Module | Responsibility | Status |
|---|---|---|
| recon | Subdomain/DNS discovery, HTTP probing, port discovery, asset inventory | Phase 5 |
| web | Crawling, endpoint/content discovery, parameter discovery, fingerprinting | Phase 5 |
| api | OpenAPI discovery, auth/authz/JWT/CORS/rate-limit/IDOR assessment | Phase 6 |
| network | Port/service/SMB/network exposure assessment | Phase 5–6 |
| vulnerability | Template/misconfiguration/TLS assessment with intrusive gating | Phase 5–6 |
| osint | Public-source intelligence and metadata | Phase 6+ |
| reporting | Consolidation, deduplication, report formats | Phase 9 |

No module package exists yet. The CLI will not register module commands until
their adapters, parsers, scope checks and tests exist.

## Module contract (planned)

A module will expose typed actions, not free-form shell commands:

```go
type Module interface {
    Name() string
    Actions() []Action
}

type Action interface {
    Name() string
    Description() string
    Intrusive() bool
    Run(ctx context.Context, input Input) (Output, error)
}
```

Actions receive the shared execution runner, scope policy, project/operation
context and result sink from the core. They do not build their own logger,
database, configuration or process runner.