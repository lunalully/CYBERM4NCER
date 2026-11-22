# COMO USAR — guia rápido

CYBERM4NCER só corre contra alvos que estejam **declarados num ficheiro de scope**
com uma autorização escrita. Fora do scope, tudo é recusado.

## 0. Compilar e ver se está tudo bem

```bash
cd ~/CYBERM4NCER
make build                 # cria ./dist/cyberm4ncer
./dist/cyberm4ncer doctor  # ambiente, base de dados, ficheiros
```

## 1. Ver as ferramentas externas

```bash
./dist/cyberm4ncer tools list          # as 30 ferramentas conhecidas
./dist/cyberm4ncer tools detect        # instaladas? versão? caminho?
./dist/cyberm4ncer tools info nmap     # tudo o que o manifesto do nmap permite
```

## 2. Criar o scope (obrigatório)

Cria `engagement.yaml`:

```yaml
version: 1
project: acme-web
authorization: "ENG-2026-014, assinado pela Acme, válido até 2026-12-31"

includes:
  - domain: example.com
    subdomains: true
  - ip: 203.0.113.10

excludes:            # opcional, mas tem sempre prioridade
  - domain: billing.example.com
    subdomains: true

ports: [80, 443]     # opcional: se existir, só estas portas são autorizadas
```

Testar o scope antes de correr qualquer coisa:

```bash
./dist/cyberm4ncer scope validate engagement.yaml
./dist/cyberm4ncer scope check example.com --file engagement.yaml
./dist/cyberm4ncer scope check billing.example.com --file engagement.yaml   # deve recusar
```

## 3. O comando principal: `aggressive`

Por omissão **só mostra o plano** — nada é executado.

```bash
# 1) ver o plano (ferramentas, invocações, rondas, o que é saltado)
./dist/cyberm4ncer aggressive example.com -s engagement.yaml --mode all

# 2) executar a sério
./dist/cyberm4ncer aggressive example.com -s engagement.yaml --mode all --execute
```

Flags úteis:

| Flag | Para quê |
|---|---|
| `-s, --scope` | ficheiro de scope |
| `--execute` | executa (sem isto é só plano) |
| `--mode` | `recon` (só descoberta), `enum` (enumeração), `vuln` (scripts/vuln), `all` |
| `--level` | 1 (suave) a 5 (máximo, por omissão) |
| `--repeat` | limita as repetições de cada invocação (0 = valores revistos) |
| `--timeout` | tempo máximo por execução (ex.: `45s`) |
| `--wordlist` | lista de diretórios/ficheiros para ferramentas web |
| `--userlist` / `--passlist` | listas para hydra/medusa (credenciais) |
| `--no-credentials` | não tenta credenciais |
| `--no-intrusive` | salta ferramentas marcadas como intrusivas |
| `--max-steps` | aborta depois de N execuções |
| `-f, --file` | lista de alvos, um por linha (aceita `#` comentários) |
| `--json` | saída em JSON (por cima do comando) |

### Corre um teste controlado na tua máquina

```bash
./dist/cyberm4ncer aggressive 127.0.0.1 -s /tmp/c4n-lab/smbscope.yaml \
  --mode all --repeat 1 --timeout 30s \
  --userlist /tmp/c4n-lab/users.txt --passlist /tmp/c4n-lab/pass.txt \
  --wordlist /tmp/c4n-lab/words/common.txt \
  --execute
```

O que ele faz: os scanners (nmap, masscan, naabu, rustscan) descobrem portas
abertas, cada porta é depois entregue a `nc`, `telnet`, `sslscan`, `testssl`,
hydra, medusa, etc. — cada passo verificado contra o scope primeiro.

## 4. Onde ficam os resultados

```bash
./dist/cyberm4ncer config path        # config + diretório de dados
./dist/cyberm4ncer config show        # configuração resolvida
```

Dentro do diretório de dados:

- `aggressive/<alvo>/<ferramenta>-<invocação>/report` — ficheiro de relatório de cada passo
- saída/erros de cada execução
- base de dados SQLite com as execuções e a cadeia de auditoria

O resumo final no terminal traz `targets / steps / succeeded / failed / skipped /
discovered / hosts / ports / elapsed`, e qualquer match de credenciais aparece
em `credential/success matches:`.

## 5. Como ler a saída

```text
round 1 nc/banner on 127.0.0.1:445 -> -v -w 3 127.0.0.1 445
round 1 ffuf/dir-enum: refused, port 80 is not allowed by scope
round 1 nmap/version-probe: skipped, missing option(s) wordlist
```

- `round N ferramenta/invocação on alvo -> argv` — vai correr (ou correu) assim
- `refused, ...` — o alvo/porta não está no scope; **nunca** corre
- `skipped, missing option(s) ...` — falta uma lista (`--wordlist` etc.)
- `+ port 127.0.0.1:8080` — porta aberta descoberta, entra na ronda seguinte
- `SUCCESS ...` — o regex de sucesso (credenciais) bateu

## 6. Regras de ouro

1. Sem `--execute` nada corre.
2. Alvo fora do scope = recusado, sempre.
3. `excludes` ganha a `includes`.
4. `ports` limitado corta o que sai do âmbito.
5. Só testar o que tens autorização escrita para testar.