# Changelog

## 1.0.0 - 2026-10-01

First release.

* **KQL hunting library**: 38 queries across 12 ATT&CK tactics for Sentinel and Defender XDR, each
  with description, false positives, tuning and response guidance; `kql-catalog` linter and catalog
  generator.
* **entra-audit**: stale accounts, MFA gaps, risky app consents and standing privileged roles, with
  graceful fallbacks when a permission or license is missing.
* **ioc-enrich**: indicator extraction from free text and parallel enrichment against VirusTotal,
  AbuseIPDB, AlienVault OTX, GreyNoise, MalwareBazaar, URLhaus, ThreatFox, Sentinel threat
  intelligence and Defender custom indicators, with caching and rate limiting.
* **mde-health**: Defender for Endpoint coverage and health report (onboarding, sensor health,
  antivirus mode, real-time protection, signatures, network, tamper and cloud protection).
* **secrets-scan**: 26 content rules and 4 file-name rules, organization rules with self-tests,
  staged-diff hook mode, baseline, SARIF output, pre-commit framework support.
* Offline demo mode for every tool; 92 unit tests on Python 3.11 to 3.13.
