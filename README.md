# soc-toolkit

**Small, sharp tools for a Microsoft security operations center.** Five scripts that each do one
SOC job well, quick to run, safe by default (read-only), with no third-party dependencies, and
tested against a simulated Microsoft cloud so every one of them runs offline in demo mode.

[![CI](https://github.com/as70023333/soc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/as70023333/soc-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

| Tool | What it does | Try it |
|---|---|---|
| [**KQL hunting library**](kql/README.md) | 38 Sentinel and Defender XDR hunting queries across 12 MITRE ATT&CK tactics, each with false-positive, tuning and response notes, linted in CI | `kql-catalog lint` |
| [**entra-audit**](docs/entra-audit.md) | Entra ID hygiene: stale accounts, users without MFA, risky app consents, permanent privileged role assignments | `entra-audit --demo` |
| [**ioc-enrich**](docs/ioc-enrich.md) | Pulls IPs, domains, URLs and hashes out of any text and checks them against 9 threat-intel sources in parallel | `ioc-enrich --demo examples/incident-notes.txt` |
| [**mde-health**](docs/mde-health.md) | Defender for Endpoint coverage: offboarded or silent devices, never-onboarded devices, AV off or outdated, network protection off | `mde-health --demo` |
| [**secrets-scan**](docs/secrets-scan.md) | Pre-commit hook and CI scanner for API keys, tokens and credential files, with custom rules for your own key formats | `secrets-scan --all` |

---

## Who this is for

* **SOC analysts** who want answers in seconds: enrich an alert's indicators, run a proven hunt.
* **Security and identity engineers** who own the hygiene that keeps alerts from happening:
  identity posture, EDR coverage, secrets in code.
* **Security leads** who need evidence ("92% of devices onboarded, 3 standing Global Admins") they
  can put in front of management or an auditor.
* **Hiring managers and peers** reading this portfolio: every tool is documented, tested and
  runnable in under a minute with `--demo`.

## What problem it solves

These scripts are the supporting cast of an **Autonomous SOC Analyst**: a multi-agent system that
detects, analyses and contains threats from Microsoft Sentinel within 28 seconds, so the human
on call becomes a strategic overseer instead of the first responder.

An autonomous responder is only as good as the ground it stands on:

| The agent needs... | ...which this toolkit provides |
|---|---|
| Good detections and hunts to investigate | The **KQL library**: the same queries an analyst or the agent runs as evidence |
| Threat-intel verdicts on hashes, IPs, domains and URLs | **ioc-enrich**: the agent's enrichment connectors as a standalone CLI |
| To know which identities are privileged, and fewer weak ones to defend | **entra-audit**: finds standing admins, MFA gaps and risky apps that its guardrails must respect |
| Endpoints it can actually isolate, and indicators that actually block | **mde-health**: finds devices without a working sensor or with network protection off |
| Its own API keys and webhook URLs kept out of git | **secrets-scan**: with rules for `SOC_WEBHOOK_KEY`, `PHISH_API_KEY`, feed keys and signed Logic App URLs |

Each tool is useful on its own, without the agent.

## When to use what

| Moment | Tool |
|---|---|
| An alert fires and it is full of indicators | `ioc-enrich` |
| An incident is in progress and you need to know what happened next | KQL library, next tactic along |
| Monday morning hygiene review (scheduled) | `entra-audit`, `mde-health` |
| Before switching the SOC agent's containment from "recommend" to "autonomous" | `mde-health` (can it isolate?) and `entra-audit` (who is privileged?) |
| Every commit, every pull request | `secrets-scan` |
| Building a new detection | KQL library, then promote the query to an analytics rule |

## Where it runs

Anywhere with **Python 3.11+**: an analyst laptop, a jump host, a CI runner, or an Azure Container
Apps / Automation job with a managed identity. No third-party Python packages, no agents, no
database server. The tools talk only to the Microsoft APIs and threat-intel feeds you configure.

## Why it is built this way

* **Read-only by design.** Nothing here changes your tenant. Audits read, the scanner blocks a
  commit, the enrichment looks up (never submits) indicators. Containment belongs in the SOC agent,
  behind its guardrails.
* **Fails partially, never silently.** A missing permission or license skips one section and the
  report says exactly which permission to grant ("Coverage notes"), instead of crashing or quietly
  reporting less.
* **Zero dependencies.** Standard library only (`urllib`, `sqlite3`, `tomllib`), so there is no
  supply chain to audit and nothing to break on upgrade.
* **Deterministic and tested.** Decisions are pure functions with unit tests: 93 tests run against
  a fake Microsoft Graph, Defender API, Log Analytics and nine fake threat-intel feeds, on Python
  3.11, 3.12 and 3.13.
* **Safe with hostile data.** Attacker-controlled strings (user agents, rule names, file names)
  are escaped in Markdown, neutralised against CSV formula injection, and passed to KQL as JSON
  data, never as code. Bearer tokens are never sent to a host other than the API they were issued
  for. API keys and secrets never appear in output.

## How to use it

### Install

```bash
git clone https://github.com/as70023333/soc-toolkit.git
cd soc-toolkit
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install .
```

Or without cloning: `pip install git+https://github.com/as70023333/soc-toolkit`.

### Try everything offline (no accounts, no keys)

```bash
entra-audit --demo                                   # fictional Contoso tenant
mde-health --demo                                    # fictional device fleet
ioc-enrich --demo examples/incident-notes.txt        # fictional threat intel
kql-catalog lint                                     # checks all 38 queries
secrets-scan --all                                   # scans this repository (clean)
```

Reports land in `./reports` as Markdown, CSV and JSON.

### Connect to your environment

1. `cp .env.example .env` and fill in what you use. Real environment variables override the file.
2. For the Microsoft tools, either `az login` (quickest for `entra-audit`) or create a read-only
   app registration. [docs/azure-setup.md](docs/azure-setup.md) lists the exact permissions per tool
   and how to use a managed identity instead of a secret.
3. For `ioc-enrich`, add whichever free feed keys you have (VirusTotal, AbuseIPDB, OTX, abuse.ch);
   `ioc-enrich --list-providers` shows what is configured.
4. For `secrets-scan`, run `secrets-scan --install-hook` in any repository, or use the
   pre-commit framework (see [docs/secrets-scan.md](docs/secrets-scan.md)).

### Exit codes (all tools)

`0` = nothing at or above the threshold, `1` = findings at or above `--fail-on`, `2` = error. That
makes every tool usable as a gate in CI or a scheduled pipeline.

### Schedule the audits (example: GitHub Actions)

```yaml
on:
  schedule: [{ cron: "0 6 * * 1" }]       # Mondays 06:00 UTC
jobs:
  hygiene:
    runs-on: ubuntu-latest
    steps:
      - run: pip install git+https://github.com/as70023333/soc-toolkit
      - run: entra-audit --fail-on none --out reports
        env: { AZURE_TENANT_ID: "${{ secrets.AZURE_TENANT_ID }}", AZURE_CLIENT_ID: "${{ secrets.AZURE_CLIENT_ID }}",
               AZURE_CLIENT_SECRET: "${{ secrets.AZURE_CLIENT_SECRET }}" }
      - run: mde-health --fail-on none --out reports
        env: { AZURE_TENANT_ID: "${{ secrets.AZURE_TENANT_ID }}", AZURE_CLIENT_ID: "${{ secrets.AZURE_CLIENT_ID }}",
               AZURE_CLIENT_SECRET: "${{ secrets.AZURE_CLIENT_SECRET }}" }
      - uses: actions/upload-artifact@v4
        with: { name: hygiene-reports, path: reports/ }
```

Reports contain user and device names; keep the artifact (or repository) private.

## Repository layout

```
soc-toolkit/
├── kql/                         # KQL hunting library, one folder per ATT&CK tactic (+ catalog README)
├── soc_toolkit/
│   ├── common/                  # HTTP with retries, Entra auth (secret / managed identity / CLI),
│   │                            # Graph / Defender / Log Analytics clients, findings, report writers
│   ├── entra_audit/             # collect.py (Graph) -> analyze.py (rules) -> cli.py; demo tenant
│   ├── mde_health/              # analyze.py (rules) + cli.py (Defender API); demo fleet
│   ├── ioc_enrich/              # extract.py, providers.py (9 feeds), engine.py, cache.py; demo intel
│   ├── secrets_scan/            # rules.py, scanner.py, gitutil.py, default_rules.toml
│   └── kql_catalog/             # KQL linter and catalog generator
├── tests/                       # 93 unit tests with a fake Microsoft cloud and fake feeds
├── docs/                        # one guide per tool + Azure setup
├── examples/incident-notes.txt  # sample analyst notes for ioc-enrich
├── .secrets-scan.toml           # organization rules (SOC agent keys, feed keys, client secrets)
├── .pre-commit-hooks.yaml       # lets other repos use secrets-scan via pre-commit
└── .github/workflows/ci.yml     # tests on 3.11-3.13, KQL lint, secret self-scan, demo runs
```

## Development

```bash
python -m unittest discover -s tests -t .     # 93 tests, ~2 seconds, no network
kql-catalog lint && kql-catalog check         # after editing queries (kql-catalog build to refresh)
secrets-scan --test-rules                     # after editing .secrets-scan.toml
```

Pull requests are welcome. Please keep the zero-dependency rule, add a test for every new rule or
check, and run the demo modes before submitting.

## Related projects

* **Autonomous SOC Analyst for Microsoft Sentinel** (`soc-agent`): the multi-agent responder these
  tools support.
* **Phishing Triage Agent** (`phish-triage`): autonomous triage of user-reported email.

## Disclaimer

These tools are read-only, but they read sensitive data. Run them with least-privilege
credentials, store reports as confidential security evidence, and validate hunting queries in your
own environment before relying on them for detection.

---

Developed by **as70023333, Sr.Security Engineer** · [MIT License](LICENSE)
