# secrets-scan: secrets scanner and pre-commit hook

Stops API keys, tokens, private keys and credential files from reaching git history, with **custom
rules for your organization's own key formats**.

```text
$ git commit -m "add config"
secrets-scan: 2 potential secret(s) found
  .env  [high] env-file: Environment file (.env) - these hold live credentials  file should not be committed
  app/settings.py:14:9  [high] github-token: GitHub token (personal, OAuth, app or refresh)  ghp_****(40 chars)

Fix: remove the secret and ROTATE it - assume anything that reached a commit is exposed.
```

## Who

* **Every engineer and analyst who commits code**, including detection content, scripts and
  automation (where SOC teams leak webhook URLs and API keys most often).
* **Security teams** rolling out a consistent hook across many repositories.
* **Maintainers of this portfolio**: CI runs it against this repository on every push.

## What it detects

**26 built-in content rules**, ordered from specific to generic: private keys; AWS access keys and
secret keys; GitHub, GitLab, Slack, npm, PyPI, Stripe, SendGrid, Google, OpenAI and Anthropic keys;
Slack, Teams and Discord webhooks; **signed Logic Apps / Power Automate / Teams Workflows URLs**
(the `sig=` URLs the SOC agent posts to); Azure Storage keys and SAS tokens; **Entra ID client
secrets**; JWTs; passwords in URLs and database connection strings; and high-entropy values assigned
to secret-looking names.

**4 file-name rules**: `.env` files (not `.env.example`), private-key and keystore files, credential
stores (`.git-credentials`, `.netrc`, `.kdbx`...), and Terraform state.

**Your organization's rules** in `.secrets-scan.toml` run first. This repository's file includes
rules for the SOC agent's own keys (`SOC_WEBHOOK_KEY`, `PHISH_API_KEY`), threat-intel feed keys,
`AZURE_CLIENT_SECRET` assignments, and an example internal key format (`ctso_live_...`).

### Fewer false positives

* Placeholders are ignored: `<your-key>`, `${TOKEN}`, `changeme`, `your-api-key-here`,
  `os.environ[...]`, AWS's documented `...EXAMPLE` keys, and repeated characters.
* Generic rules require high entropy (3.5 bits per character).
* When several rules match the same text, only the most specific one reports it.
* In hook mode only **added lines** are checked, so an old secret already in history does not block
  every commit (clean it up separately with `--all`).
* Binary files get only the file-name rules; files over 2 MB are skipped and listed.

## When it runs

* **On every commit**, as a git pre-commit hook (native or via the pre-commit framework).
* **In CI** on every push or pull request (`secrets-scan --all`), catching commits made with
  `--no-verify` or from machines without the hook.
* **Once, on adoption**, to find and baseline what is already in a repository.

## Where it runs

On developer machines (macOS, Linux, Windows with Git for Windows) and in any CI system. Python 3.11+
and git; no other dependencies and no network access.

## Why it matters

A secret pushed to a repository is effectively public: it lives in history, forks and clones even
after it is deleted, and bots scan public repositories for keys within minutes. Blocking it at the
commit is far cheaper than rotating it, reviewing its use, and explaining the incident.

## How to use it

### Option A: native git hook (one repository, no extra tools)

```bash
pip install git+https://github.com/as70023333/soc-toolkit
cd your-repo
secrets-scan --install-hook        # writes .git/hooks/pre-commit (respects core.hooksPath)
```

It never overwrites a hook it did not write unless you pass `--force`.

### Option B: the pre-commit framework (many repositories)

```yaml
# .pre-commit-config.yaml in your repository
repos:
  - repo: https://github.com/as70023333/soc-toolkit
    rev: v1.0.0
    hooks:
      - id: secrets-scan
```

```bash
pip install pre-commit && pre-commit install
```

### Option C: CI

```yaml
# GitHub Actions
- run: pip install git+https://github.com/as70023333/soc-toolkit
- run: secrets-scan --all
# Optional: show results in the Security tab
- run: secrets-scan --all --format sarif --output secrets.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: secrets.sarif
```

### Commands

| Command | What it does |
|---|---|
| `secrets-scan FILE\|DIR ...` | Scan files or folders (what pre-commit passes) |
| `secrets-scan --staged` | Scan only lines added in staged changes (native hook) |
| `secrets-scan --all` | Scan every git-tracked file |
| `secrets-scan --all --update-baseline` | Accept current findings into `.secrets-baseline.json` |
| `secrets-scan --install-hook [--force]` | Install the native hook |
| `secrets-scan --list-rules` | Show active rules and where they come from |
| `secrets-scan --test-rules` | Check the `examples` / `not_examples` of your custom rules |
| `--format text\|json\|sarif`, `--output FILE` | Report format and destination |
| `--config FILE` | Rules file (default `.secrets-scan.toml` in the repo root) |
| `--no-default-rules` | Use only your rules |

Exit codes: `0` clean, `1` secrets found, `2` error (bad config, not a git repository, missing path).

### When it blocks a commit

1. **Real secret**: remove it, **rotate it** (assume it is exposed), and load it from the
   environment, a git-ignored `.env`, or a vault.
2. **False positive**: add a comment containing `secrets-scan: allow` on that line
   (`pragma: allowlist secret` and `gitleaks:allow` also work), or accept it into the baseline with
   `secrets-scan --all --update-baseline`. The baseline stores only fingerprints (hashes), never the
   secret.
3. **Emergency**: `git commit --no-verify` skips the hook; CI will still catch it.

## Writing rules for your organization

Create `.secrets-scan.toml` in the repository root (copy this repository's as a start):

```toml
# Top-level keys first: TOML assigns keys after a [[rule]] to that rule.
disable = ["jwt"]                  # built-in rules to switch off

[[rule]]
id = "acme-api-key"
description = "Acme internal API key"
regex = '''\b(acme_(?:live|test)_[A-Za-z0-9]{32})\b'''   # group 1 is the secret
severity = "high"                  # critical | high | medium | low
keywords = ["acme_"]               # fast pre-filter, lowercase
# Optional: entropy = 3.5, require_any = ["..."], paths = ["*.env"], secret_group = 1
examples = ["key = 'acme_live_8fJ2kL9mN3pQ7rS1tU5vW0xY4zA6bC2d'"]
not_examples = ["acme_live_short"]

[[file_rule]]
id = "acme-vpn-profile"
description = "VPN profile with embedded credentials"
globs = ["*.ovpn"]
severity = "high"

[allowlist]
paths = ["tests/fixtures/**"]      # never scanned
regexes = []                       # candidate secrets matching these are ignored
stopwords = []                     # candidate secrets containing these are ignored
```

Then run `secrets-scan --test-rules`. The configuration is validated strictly: an unknown key, an
invalid regex, an unknown severity or a duplicate id stops the scan with a clear error instead of
silently scanning less. The config file and the baseline are never scanned themselves, so rule
examples do not trigger findings.

## Security notes

* Secrets never leave the process unredacted: output shows the first four characters and the
  length; JSON, SARIF and baseline files hold only redacted values and fingerprints.
* No network access, no telemetry.
* The test suite builds its sample secrets at runtime, so the repository contains no literal
  secrets for this or any other scanner (including GitHub push protection) to find.
