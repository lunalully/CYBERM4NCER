# Tools

These are the external tools with validated manifests in 0.1.0. Detection and
version checks work. Adapters (argument builders and parsers) are added in
Phases 3–6.

| Tool | Category | Min | Tested | Risk | Intrusive |
|---|---|---|---|---|---|
| amass | recon | 4.0.0 | 4.2.0 | low | no |
| dnsx | recon | 1.2.0 | 1.3.1 | low | no |
| feroxbuster | web | 2.10.0 | 2.13.1 | medium | yes |
| ffuf | web | 2.1.0 | 2.1.0 | medium | yes |
| gobuster | web | 3.6.0 | 3.6.0 | medium | yes |
| httpx | recon | 1.6.0 | 1.12.0 | low | no |
| katana | web | 1.1.0 | 1.8.0 | medium | yes |
| naabu | network | 2.3.0 | 2.7.0 | medium | yes |
| nikto | vulnerability | 2.1.5 | 2.1.5 | medium | yes |
| nmap | network | 7.90 | 7.95 | medium | yes |
| nuclei | vulnerability | 3.0.0 | 3.11.1 | high | yes |
| sqlmap | vulnerability | 1.8.0 | 1.9.6 | high | yes |
| sslscan | vulnerability | 2.1.0 | 2.1.5 | low | no |
| subfinder | recon | 2.6.0 | 2.17.0 | low | no |
| testssl | vulnerability | 3.2.0 | 3.2.1 | low | no |

Detailed per-tool pages will be added with each adapter and must contain:

- function and official documentation
- usage and parameters exposed by CYBERM4NCER
- examples
- dependencies and architecture support
- limitations
- risks and confirmation requirements
- parser formats and fixture coverage

Authoritative metadata is in `internal/tools/manifests/<tool>.yaml`. Inspect it
with:

```bash
cyberm4ncer tools info nuclei
cyberm4ncer tools detect
```