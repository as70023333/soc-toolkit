# ioc-enrich: bulk IOC enrichment

Paste in analyst notes, an alert, a threat report or a list, and get every IP, domain, URL and file
hash checked against **nine threat-intel sources in parallel**, with one clear verdict per
indicator.

```bash
ioc-enrich --demo examples/incident-notes.txt     # offline demo, no API keys
```

```
VERDICT     SCORE  TYPE    INDICATOR                         WHY
malicious     100  ipv4    203[.]0[.]113[.]66                abuseipdb: confidence 100%, 412 report(s) in 90 days; threatfox: botnet_cc for LockBit; ...
malicious     100  sha256  5f2b8c3e9d1a7f4b...               virustotal: 58/72 engines malicious (ransomware.lockbit/encoder); malwarebazaar: ...
suspicious     62  ipv4    192[.]0[.]2[.]10                  abuseipdb: confidence 62%, 148 report(s) in 90 days; greynoise: opportunistic internet scanner
harmless        0  ipv4    198[.]51[.]100[.]200              virustotal: 0/94 engines malicious; abuseipdb: no abuse reports
unknown         0  ipv4    10[.]10[.]4[.]17                  skipped: private or non-routable address
```

## Who

* **SOC analysts** triaging an alert with a dozen indicators in it.
* **Incident responders** checking an IOC list from a partner, ISAC or vendor report.
* **Threat hunters** validating the results of a KQL hunt (pipe the IPs straight in).
* **Automation**: the same connectors serve the autonomous SOC agent's threat-intel step; this CLI
  is the standalone, scriptable version.

## What it does

1. **Extracts** indicators from any text: refangs `hxxp://`, `[.]`, `(.)`, `[:]`; finds URLs,
   IPv4/IPv6, domains, MD5, SHA-1 and SHA-256; ignores file names that look like domains
   (`script.py`, `notes.md`), times, and code. One indicator per line also works, including `.zip`
   and `.mov` domains.
2. **Filters**: private and non-routable IPs are skipped, allowlisted domains are reported but not
   looked up, and your internal domains are only checked against your own Microsoft threat intel,
   never sent to an external service.
3. **Enriches** in parallel, within each feed's rate limit, with a local cache so repeat runs do not
   spend quota.
4. **Decides** one verdict per indicator: `malicious`, `suspicious`, `harmless` or `unknown`, with a
   0-100 score and the reasons.

### Feeds

| Feed | Types | Key (`.env`) | Free tier |
|---|---|---|---|
| VirusTotal | IP, domain, URL, hashes | `VIRUSTOTAL_API_KEY` | 4 lookups/min, 500/day (rate-limited automatically; `VT_RATE_PER_MIN` for premium) |
| AbuseIPDB | IP | `ABUSEIPDB_API_KEY` | 1,000/day |
| AlienVault OTX | IP, domain, URL, hashes | `OTX_API_KEY` | Free |
| GreyNoise Community | IPv4 | `GREYNOISE_API_KEY` (optional) | Works without a key, lower limit |
| MalwareBazaar | hashes | `ABUSECH_AUTH_KEY` | Free |
| URLhaus | URL, domain, IP, MD5/SHA-256 | `ABUSECH_AUTH_KEY` | Free |
| ThreatFox | IP, domain, URL, MD5/SHA-256 | `ABUSECH_AUTH_KEY` | Free |
| Sentinel threat intelligence | all | `SENTINEL_WORKSPACE_ID` + Azure sign-in | Your Defender TI, TAXII and MISP indicators, one query per run |
| Defender custom indicators | all | `DEFENDER_INDICATORS=true` + Azure sign-in | Is it already blocked or allowed in your tenant? |

`ioc-enrich --list-providers` shows which feeds are configured.

### How the verdict is computed

Each feed's answer is normalised to a 0-100 maliciousness score:

* The **strongest** single opinion sets the score.
* **Two or more** feeds saying malicious add 10.
* A **known benign service** (GreyNoise RIOT, an OTX allowlist entry, AbuseIPDB allowlist, or your
  own Defender *Allowed* indicator) caps the score at 20 unless a feed says malicious.
* Score 70+ is `malicious`, 35+ `suspicious`; below that `harmless` if any feed said so, else
  `unknown`.

Examples of the mapping: VirusTotal with 3+ engines flagging = malicious (70 + 2 per engine);
AbuseIPDB confidence 75%+ = malicious, 25%+ = suspicious; OTX pulses alone are never more than
suspicious (OTX lists plenty of shared infrastructure); MalwareBazaar, ThreatFox and online URLhaus
hits are malicious.

## When to use it

* **First five minutes of triage**: paste the alert body, get the verdicts.
* **When a threat report lands**: check its IOC appendix against your feeds and Sentinel TI.
* **After a hunt**: enrich the destinations from KQL-TA0011-001 (beaconing) or the senders from a
  phishing campaign.
* **In a pipeline**: `--fail-on malicious` makes it a gate (exit 1 when anything is malicious).

## Where it runs

Anywhere with Python 3.11+ and HTTPS to the feeds you configured. The cache lives in
`~/.cache/soc-toolkit/ioc-cache.sqlite3` (file mode 600 because it lists what you investigated);
`--no-cache` disables it.

## Why it matters

Checking twelve indicators by hand across five websites takes twenty minutes and produces a
judgement nobody wrote down. This takes seconds, applies the same rules every time, links to the
evidence, and produces a report you can paste into the ticket, defanged.

## How to use it

```bash
cp .env.example .env              # add whichever feed keys you have
ioc-enrich notes.txt              # file(s) of any text
cat alert.txt | ioc-enrich -      # stdin
ioc-enrich --ioc 203.0.113.66 --ioc bad.example
ioc-enrich iocs.txt --out report.md --defang     # shareable Markdown
ioc-enrich iocs.txt --out results.csv            # spreadsheet
ioc-enrich iocs.txt --format json > results.json # automation
ioc-enrich notes.txt --extract-only              # just list what was found
ioc-enrich iocs.txt --providers virustotal,threatfox
```

| Option | Meaning |
|---|---|
| `FILE ...` / `-` | Text to read; `-` is stdin (stdin is also read automatically when piped) |
| `--ioc VALUE` | An indicator on the command line (repeatable) |
| `--providers LIST` | Only these feeds (see `--list-providers`) |
| `--url-hosts` | Also enrich each URL's host |
| `--include-private` | Look up private/non-routable IPs too |
| `--format table\|json\|csv\|md`, `--out FILE` | Output; the format follows the file extension |
| `--defang` | Defang indicators in the output |
| `--fail-on malicious\|suspicious\|none` | Exit 1 when an indicator reaches this verdict (default none) |
| `--no-cache`, `--cache-ttl HOURS` | Cache control (default 24 h; "not found" answers are kept for a quarter of that) |
| `--workers N` | Parallel requests (default 8) |

Exit codes: `0` ok, `1` an indicator reached `--fail-on`, `2` error.

### Using the connectors from Python

```python
from soc_toolkit.common.http import HttpClient
from soc_toolkit.ioc_enrich.engine import enrich
from soc_toolkit.ioc_enrich.extract import extract
from soc_toolkit.ioc_enrich.providers import ThreatFox, VirusTotal

http = HttpClient()
results = enrich(extract(alert_text), [VirusTotal(http, vt_key), ThreatFox(http, abusech_key)])
for r in results:
    print(r.indicator.value, r.verdict, r.score)
```

To add a feed, subclass `Provider`, implement `lookup(indicator) -> ProviderResult`, and add it to
`EXTERNAL_PROVIDERS` in `providers.py`.

## Privacy and safety

* Only lookups are made. Nothing is ever *submitted* or *scanned*, so a URL with a victim's address
  in it is not shared with a feed's public corpus.
* URLs can still contain personal data: leave a feed's key unset if that concern applies to it,
  and list your domains in `IOC_INTERNAL_DOMAINS`.
* API keys are sent only in request headers and never appear in error messages or reports.

## Troubleshooting

| Message | Fix |
|---|---|
| `no threat-intel feed is configured` | Add at least one key to `.env`, or run `--demo` |
| `virustotal quota exhausted or rate limited` | Free daily quota used; results resume tomorrow, cached results still show |
| `<feed> rejected the API key or permission` | Check the key; abuse.ch keys come from https://auth.abuse.ch/ |
| `sentinel_ti: ... 403` | Assign Log Analytics Reader on the workspace |
| A domain in your notes was not extracted | Put it on its own line, or check `--extract-only`; free-text extraction ignores file-like TLDs |
