# Azure setup for soc-toolkit

`entra-audit`, `mde-health` and the Microsoft feeds of `ioc-enrich` call Microsoft APIs. They
only **read**: no tool in this repository changes anything in your tenant. This page explains how
to give them access with the least privilege. Allow 15 minutes.

`secrets-scan`, `kql-catalog` and the external threat-intel feeds of `ioc-enrich` need no Azure
access at all.

## 1. Choose how the tools sign in

| Option | Best for | Settings in `.env` |
|---|---|---|
| **Azure CLI** (`az login`) | An admin running an audit by hand | nothing; leave `AZURE_CLIENT_SECRET` empty |
| **App registration + client secret** | Scheduled runs from a server or CI | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| **Managed identity** | Runs inside Azure (Container Apps job, Functions, Automation, VM) | `USE_MANAGED_IDENTITY=true` (plus `AZURE_CLIENT_ID` for a user-assigned identity) |

Force a mode with `AZURE_AUTH=cli|secret|managed_identity`.

**Azure CLI caveat:** the CLI signs in as you with the CLI's own app, which is pre-authorized for
Microsoft Graph but not for the Defender for Endpoint API. Use it for `entra-audit`; use an app
registration or managed identity for `mde-health` and Defender indicators. Your account still
needs a directory role that can read the data (Global Reader is enough for the audit).

## 2. Create the app registration (for secret or as the template for a managed identity)

1. Entra admin center > **App registrations > New registration** > name `soc-toolkit-reader`,
   single tenant, no redirect URI.
2. **Certificates & secrets > New client secret** (6 or 12 months). Copy the value into `.env`.
3. **API permissions > Add a permission**, choose **Application permissions**, add only what you
   use (table below), then **Grant admin consent**.

| Tool | API | Application permission | Why |
|---|---|---|---|
| entra-audit | Microsoft Graph | `User.Read.All` | List users |
| entra-audit | Microsoft Graph | `AuditLog.Read.All` | Sign-in activity and MFA registration details (needs Entra ID P1) |
| entra-audit | Microsoft Graph | `Directory.Read.All` | Organization, consent grants, role-assignable groups |
| entra-audit | Microsoft Graph | `Application.Read.All` | Service principals and their application permissions |
| entra-audit | Microsoft Graph | `RoleManagement.Read.Directory` | Role definitions, assignments and PIM schedules (PIM needs Entra ID P2) |
| mde-health | WindowsDefenderATP | `Machine.Read.All` | Device inventory and health |
| mde-health | WindowsDefenderATP | `AdvancedQuery.Read.All` | Antivirus and network-protection configuration (advanced hunting) |
| ioc-enrich | WindowsDefenderATP | `Ti.Read.All` | Optional: check your Defender custom indicators (`DEFENDER_INDICATORS=true`) |

WindowsDefenderATP is under **APIs my organization uses**.

For `ioc-enrich`'s Sentinel threat-intelligence feed, assign the app (or identity) the Azure role
**Log Analytics Reader** on the Sentinel workspace and set `SENTINEL_WORKSPACE_ID` to the
workspace ID (a GUID, on the workspace's Overview page).

## 3. Managed identity instead of a secret

Managed identities have no consent screen. Grant the same application permissions with
PowerShell (Microsoft Graph PowerShell SDK):

```powershell
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All"
$mi       = Get-MgServicePrincipal -Filter "displayName eq '<your managed identity name>'"
$graph    = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$defender = Get-MgServicePrincipal -Filter "appId eq 'fc780465-2017-40d4-a0c5-307022471b92'"
foreach ($p in "User.Read.All","AuditLog.Read.All","Directory.Read.All","Application.Read.All","RoleManagement.Read.Directory") {
  $role = $graph.AppRoles | Where-Object Value -eq $p
  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id -PrincipalId $mi.Id -ResourceId $graph.Id -AppRoleId $role.Id
}
foreach ($p in "Machine.Read.All","AdvancedQuery.Read.All") {
  $role = $defender.AppRoles | Where-Object Value -eq $p
  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id -PrincipalId $mi.Id -ResourceId $defender.Id -AppRoleId $role.Id
}
```

## 4. Check it works

```bash
entra-audit --checks stale --format md      # needs only User.Read.All + AuditLog.Read.All
mde-health --format md
```

If a permission is missing, the tools do not crash: the affected section is skipped and the
report's **Coverage notes** say which permission to grant.

## Licensing that changes the results

| Data | Requires | Without it |
|---|---|---|
| Sign-in activity on users | Entra ID P1 | Stale-account checks are skipped (noted in the report) |
| MFA registration details | Entra ID P1 | MFA checks are skipped |
| PIM schedules | Entra ID P2 | Every active role assignment is reported as permanent |
| Secure configuration assessment | Defender for Endpoint P2 / Defender Vulnerability Management | AV and network-protection checks are skipped |
| Email and URL-click tables (KQL library) | Defender for Office 365 P2 | Those queries return nothing |
