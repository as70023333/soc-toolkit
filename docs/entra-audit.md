# entra-audit: Entra ID hygiene audit

A read-only audit of the four identity weaknesses attackers use most against Microsoft 365
tenants: **stale accounts, users without MFA, risky app consents, and standing (permanent)
privileged role assignments**. It turns them into a prioritised report you can hand to the
identity team.

```bash
entra-audit --demo          # try it now on a built-in fictional tenant
```

## Who

* **Security engineers and SOC leads** who own identity hygiene and need evidence for it.
* **Identity / IAM administrators** cleaning up accounts, MFA gaps and admin sprawl.
* **Auditors and consultants** who want a repeatable, read-only check of a tenant.
* **The autonomous SOC agent**: identity findings feed its guardrails (who is privileged, which apps
  are risky), so a compromised standing admin pages a human instead of being auto-contained.

## What it checks

| Check id | Finds | Default severity |
|---|---|---|
| `stale_account` | Enabled member accounts with no successful sign-in for 90 days | medium (high if privileged) |
| `stale_guest` | Enabled guests with no sign-in for 90 days | medium (high if privileged) |
| `never_signed_in` | Enabled accounts created 90+ days ago that never signed in | medium (high if privileged) |
| `pending_guest_invite` | Guest invitations never accepted after 30 days | low |
| `no_mfa` | Enabled members with no MFA method registered | high (critical if privileged) |
| `weak_mfa_only` | Members whose only methods are SMS, voice, email or security questions | medium (high if privileged) |
| `admin_not_phishing_resistant` | Privileged users without a FIDO2 key, passkey, Windows Hello or certificate | high |
| `risky_app_permission` | Apps holding application permissions that expose mail, files or chats, or that can take over the tenant (RoleManagement.ReadWrite.Directory, Application.ReadWrite.All...) | medium to critical: third-party + unverified publisher + takeover = critical |
| `risky_delegated_consent` | Tenant-wide admin consent, or individual user consent, to high-risk delegated scopes | low to high |
| `standing_privileged_role` | Permanent (non-PIM) assignments of privileged roles | high (critical for Global Administrator) |
| `guest_privileged_role` | Guests holding admin roles | critical |
| `synced_privileged_account` | Admin roles on accounts synchronized from on-prem AD | high |
| `service_principal_privileged_role` | Apps holding directory admin roles | high |
| `group_privileged_role` | Roles assigned through role-assignable groups | medium |
| `disabled_user_with_role` | Disabled accounts still holding admin roles | low |
| `too_many_global_admins` / `too_few_global_admins` | Fewer than 2 or more than 5 Global Administrators | medium |
| `break_glass_account` | Your declared emergency-access accounts (informational) | info |

Roles scoped to an administrative unit are reported one severity lower than tenant-wide ones.
Microsoft first-party apps (owned by Microsoft's tenants) are skipped in the consent checks: they
are not consents your people made.

## When to run it

* **Monthly**, as a scheduled job, with the report sent to the identity team (`--fail-on none`).
* **Before an audit or insurance renewal**, to produce evidence.
* **After an incident**, to check the attacker did not leave a standing admin or a rogue app consent.
* **In CI for a tenant-as-code repo**, with `--fail-on critical` to stop regressions.

## Where it runs

Anywhere with Python 3.11+ and HTTPS to `graph.microsoft.com`: an admin laptop (`az login`), a
build agent, an Azure Container Apps job or Azure Automation with a managed identity. It sends
nothing anywhere else and writes reports only to `--out`.

## Why it matters

Most Microsoft 365 breaches start with an identity: a stale account nobody watches, a user with
no MFA, an OAuth app a user consented to, or an admin account that is admin 24/7. Each check maps
to a common attack path (password spray into stale accounts, consent phishing, standing-privilege
abuse). Fixing them shrinks what an attacker can reach and what the SOC has to watch at night.

## How to use it

### 1. Install

```bash
pip install git+https://github.com/as70023333/soc-toolkit
# or, from a clone:  pip install .
```

### 2. Grant read access

See [Azure setup](azure-setup.md). Fastest path for a one-off run: `az login` as a Global Reader.
For scheduled runs: an app registration with `User.Read.All`, `AuditLog.Read.All`,
`Directory.Read.All`, `Application.Read.All` and `RoleManagement.Read.Directory`.

### 3. Run

```bash
entra-audit                                        # all checks, reports in ./reports
entra-audit --break-glass bg01@contoso.com,bg02@contoso.com
entra-audit --checks mfa,roles --fail-on critical
entra-audit --stale-days 60 --exclude sync_svc@contoso.com
entra-audit --save-snapshot snap.json              # keep raw data; re-run analysis offline:
entra-audit --snapshot snap.json --stale-days 30
```

| Option | Default | Meaning |
|---|---|---|
| `--checks` | `stale,mfa,consent,roles` | Subset of checks to run |
| `--stale-days` / `--guest-stale-days` | 90 / 90 | Inactivity thresholds (`ENTRA_STALE_DAYS`, `ENTRA_GUEST_STALE_DAYS`) |
| `--break-glass` | none | Emergency-access UPNs (`ENTRA_BREAK_GLASS_UPNS`) |
| `--exclude` | none | UPNs skipped in stale and MFA checks (`ENTRA_EXCLUDE_UPNS`) |
| `--out` | `reports` | Report folder |
| `--format` | `md,csv,json` | Report formats |
| `--fail-on` | `high` | Exit 1 when any finding is at or above this severity (`none` to always exit 0) |
| `--save-snapshot` / `--snapshot` | | Save raw Graph data / analyse saved data offline |
| `--demo` | | Use the built-in fictional tenant |

Exit codes: `0` nothing at or above `--fail-on`, `1` findings at or above it, `2` error.

### 4. Read the report

* `entra-audit-<date>.md`: summary table, then one section per finding type with the
  recommendation and every affected account or app. Paste it into a ticket or wiki.
* `entra-audit-<date>.csv`: one row per finding, for Excel or a tracker.
* `entra-audit-<date>.json`: everything, for automation (`findings[].check`, `severity`, `target`,
  `evidence`).

**Coverage notes** at the bottom list anything that could not be checked (a missing permission or
license) and what to grant. A clean report with coverage notes is not a clean tenant.

## How it decides

* **Stale** uses `signInActivity.lastSuccessfulSignInDateTime` when Graph returns it, otherwise the
  later of the interactive and non-interactive last sign-in.
* **Privileged** means a role Microsoft marks `isPrivileged`, or one of 24 well-known admin role
  templates (Global Admin, Privileged Role Admin, Exchange Admin, ...), held through an active
  assignment.
* **Permanent** means a PIM schedule instance of type `Assigned` with no end date. Without PIM data
  (no P2 license) every active assignment counts as permanent and the report says so.
* **Third-party** means the app is owned by another tenant that is not Microsoft. An unverified
  publisher raises the severity one level.

## False positives and tuning

| Situation | What to do |
|---|---|
| Directory-sync or scanner accounts flagged as stale / no MFA | `--exclude` them; better, convert them to workload identities |
| Break-glass accounts flagged as standing Global Admins | Declare them with `--break-glass` (they become `info`) |
| Your own automation app flagged for a takeover permission | Correct but expected: confirm the owner, protect its credentials, keep the finding as an accepted risk |
| Service accounts that sign in only non-interactively | Already handled: non-interactive sign-ins count when successful-sign-in data is unavailable |

## Troubleshooting

| Message | Fix |
|---|---|
| `could not list users: HTTP 403` | Grant `User.Read.All` (and admin consent) |
| Note: `sign_in_activity ... unavailable` | Grant `AuditLog.Read.All`; the tenant needs Entra ID P1 |
| Note: `registration: HTTP 403` | Grant `AuditLog.Read.All`; MFA registration details need Entra ID P1 |
| Note: `pim: PIM schedule data unavailable` | Grant `RoleManagement.Read.Directory`; PIM needs Entra ID P2 |
| `Azure CLI could not get a token` | Run `az login --tenant <tenant id>` |

## Security notes

* Read-only: every request is a `GET`, except `directoryObjects/getByIds`, a read expressed as POST.
* Reports contain user names and app names: store them like any other internal security evidence
  (the repo's `.gitignore` excludes `reports/` and snapshots).
* Bearer tokens are never sent to a host other than Microsoft Graph, even if a paging link points
  elsewhere.
