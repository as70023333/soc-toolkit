# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's
**Security > Report a vulnerability** (private advisory) on this repository. You can expect an
acknowledgement within a few days.

## What these tools do with your data

| Tool | Reads | Sends | Writes |
|---|---|---|---|
| entra-audit | Microsoft Graph (users, MFA registration, apps, role assignments) | Nothing outside Microsoft Graph | Reports in `--out` (contain user and app names) |
| mde-health | Defender for Endpoint API (devices, advanced hunting) | Nothing outside the Defender API | Reports in `--out` (contain device names) |
| ioc-enrich | Your input text | Indicator values to the feeds you configured (lookups only, never submissions); internal domains only to your own Sentinel / Defender | A local cache of results (file mode 600) and the report you ask for |
| secrets-scan | Files or staged changes in the repository | Nothing (no network access) | Optional reports and baseline, holding only redacted values and fingerprints |
| kql-catalog | Files under `kql/` | Nothing | `kql/README.md` when you run `build` |

No tool changes anything in your Microsoft tenant.

## Hardening built in

* Least-privilege, read-only permissions are documented per tool (`docs/azure-setup.md`).
* Bearer tokens are only sent to the API host they were issued for.
* Query strings (which can carry keys or SAS signatures) are stripped from error messages.
* Attacker-controlled strings are escaped in Markdown, neutralised against CSV formula injection,
  and passed to KQL as JSON data.
* No third-party dependencies.
