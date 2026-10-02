# mde-health: Defender for Endpoint device-health report

Finds the devices your EDR cannot protect: **devices that stopped reporting or were offboarded,
devices that were never onboarded, unhealthy sensors, antivirus that is off or out of date, and
network protection turned off**.

```bash
mde-health --demo           # try it now on a built-in fictional fleet
```

## Who

* **SOC and endpoint security engineers** responsible for EDR coverage.
* **IT operations / desktop engineering**, who fix the broken agents.
* **Security leadership**, for a coverage number they can trust ("92% onboarded, 2 sensors broken").
* **The autonomous SOC agent**, whose containment (device isolation, IP/URL blocks) only works on
  healthy, onboarded devices with network protection on.

## What it checks

| Check id | Finds | Default severity |
|---|---|---|
| `not_onboarded` | Devices Defender discovered on your network that can be onboarded but are not | high |
| `unsupported_device` | Discovered devices Defender cannot protect (IoT, printers, old OS) | low |
| `insufficient_info` | Discovered devices Defender could not classify | info |
| `inactive_device` | Onboarded devices inactive or silent for 7+ days; "likely offboarded or retired" after 30 | medium |
| `sensor_unhealthy` | Sensors with impaired communication or no sensor data | high |
| `av_not_active` | Defender Antivirus not in active mode (passive or disabled) | high |
| `realtime_protection_off` | Real-time protection off (Windows, macOS, Linux) | high |
| `av_signatures_outdated` | Security intelligence out of date (Windows, macOS, Linux) | medium |
| `network_protection_off` | Network protection off, so Defender IP/URL/domain indicators do not block | medium |
| `tamper_protection_off` | Tamper protection off | medium |
| `cloud_protection_off` | Cloud-delivered protection off | medium |

Devices with **Device value: High** in Defender (domain controllers, key servers) are raised one
severity level. Antivirus and network-protection checks run only on active devices, because the
configuration data of a silent device is stale.

Also written: a per-device CSV (`mde-health-<date>-devices.csv`) with every device and its issues,
which is what IT usually wants as a work list.

## When to run it

* **Weekly** as a scheduled job, report to the endpoint team.
* **Before switching the SOC agent's containment to autonomous**: isolation only works on healthy
  onboarded devices, and indicator blocks only work with network protection on.
* **After a big rollout or OS upgrade wave**, to catch devices that dropped off.
* **During an incident**, to know which devices you are blind on.

## Where it runs

Python 3.11+ with HTTPS to `api.securitycenter.microsoft.com`. Use an app registration or a managed
identity (the Azure CLI cannot get Defender API tokens). Runs on a laptop, a build agent, or an
Azure Container Apps / Automation job.

## Why it matters

An EDR you think you have is worse than one you know you lack. Attackers favour the machine whose
sensor broke last month, the server that was re-imaged without onboarding, and the workstation
where someone set an antivirus exclusion or turned real-time protection off. This report finds those
gaps before an attacker or an auditor does.

## How to use it

### 1. Grant read access

App registration (or managed identity) with **WindowsDefenderATP** application permissions
`Machine.Read.All` and `AdvancedQuery.Read.All`. See [Azure setup](azure-setup.md).

### 2. Run

```bash
mde-health                                     # reports in ./reports
mde-health --inactive-days 14 --retire-days 60
mde-health --exclude-tag retired --exclude-tag lab
mde-health --fail-on critical                  # for a scheduled pipeline
mde-health --save-raw raw.json && mde-health --raw raw.json --inactive-days 3
```

| Option | Default | Meaning |
|---|---|---|
| `--inactive-days` | 7 | Days without a full report before a device counts as inactive (`MDE_INACTIVE_DAYS`) |
| `--retire-days` | 30 | Days after which an inactive device is called likely retired (`MDE_RETIRE_DAYS`) |
| `--exclude-tag` | none | Skip devices with this Defender tag; repeatable (`MDE_EXCLUDE_TAGS`) |
| `--out`, `--format`, `--fail-on` | `reports`, `md,csv,json`, `high` | As in the other tools |
| `--save-raw` / `--raw` | | Save API data / analyse saved data offline |
| `--demo` | | Built-in fictional fleet |

Exit codes: `0` nothing at or above `--fail-on`, `1` findings at or above it, `2` error.

### 3. Read the report

The Markdown summary gives onboarding coverage (onboarded / (onboarded + discoverable)), active
devices, devices with no issue, and a section per issue type with the fix. The device CSV is the
work list.

## How it works

1. `GET /api/machines` (all pages): onboarding status, health status, last seen, OS, device value
   and tags.
2. Six advanced-hunting queries against `DeviceTvmSecureConfigurationAssessment`, one per setting,
   each far below the 100,000-row result limit: antivirus mode (scid-2010), real-time protection
   (scid-2012 / 5090 / 6090), signatures (scid-2011 / 5095 / 6095), network protection (scid-96),
   tamper protection (scid-2003) and cloud protection (scid-2016).
3. Rules in `soc_toolkit/mde_health/analyze.py` combine both. They are pure functions with unit
   tests, so you can adjust severities with confidence.

Note: the API's `lastSeen` is the last *full device report* (normally daily), not the last
heartbeat shown in the portal, which is why the default inactivity threshold is 7 days.

## False positives and tuning

| Situation | What to do |
|---|---|
| Decommissioned devices still listed | Tag them `retired` in Defender and use `--exclude-tag retired` |
| Laptops off for a vacation | Raise `--inactive-days`; they recover when they come back |
| Servers with a third-party AV (Defender in passive mode on purpose) | Expected `av_not_active`; tag the group and exclude, or accept the finding |
| "no secure-configuration assessment yet" note | New devices take up to a day to be assessed |

## Troubleshooting

| Message | Fix |
|---|---|
| `HTTP 403 ... grant WindowsDefenderATP Machine.Read.All` | Add the permission and grant admin consent |
| Note: `config_assessments: ... AdvancedQuery.Read.All` | Add that permission; AV and network-protection checks were skipped |
| Note: `no secure-configuration data returned` | Needs Defender Vulnerability Management data (MDE P2 or the add-on) |
| `Azure CLI could not get a token` | Use an app registration or managed identity for this tool |
