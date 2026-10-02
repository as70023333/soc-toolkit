# KQL Hunting Library

38 threat-hunting queries for **Microsoft Sentinel** and **Microsoft Defender XDR advanced hunting**,
organized by MITRE ATT&CK tactic. Every query explains, in its header, what it finds, when it fires
on benign activity, how to tune it, and what to do when it hits.

## Who it is for

* **SOC analysts (Tier 1 and 2)** who need a proven starting query instead of a blank editor.
* **Threat hunters** running hypothesis-driven hunts by tactic ("are we seeing credential access?").
* **Detection engineers** promoting hunts to scheduled analytics rules or Defender custom detections.
* **The Autonomous SOC agent**, which can run the same queries as evidence-gathering steps.

## What is in it

Each `.kql` file is self-contained and starts with a structured header:

```kql
// Title: Password spray against Entra ID
// Id: KQL-TA0006-001
// Tactic: TA0006 Credential Access
// Techniques: T1110.003
// Platform: Sentinel                <- where to run it: Sentinel, Defender XDR or Both
// Tables: SigninLogs
// Severity: Medium                  <- suggested severity if promoted to a detection
// Lookback: 1d
// Description: What the query finds and why it matters.
// False positives: When it fires on benign activity and how to tell the difference.
// Tuning: Thresholds and allowlists to adjust for your environment.
// Response: What to do when it fires.
// References: Links to ATT&CK or Microsoft documentation.
```

Thresholds (`let MinAccounts = 15;`) and allowlists (`let KnownGood = dynamic([...]);`) sit at the
top of the query body so you can tune them without reading the logic.

### Where each query runs

| Platform in the header | Run it in | Notes |
|---|---|---|
| **Defender XDR** | Defender portal > Hunting > Advanced hunting | Uses `Device*`, `Email*`, `UrlClickEvents` tables. Also runs in Sentinel if the Defender XDR connector streams those tables to your workspace. |
| **Sentinel** | Sentinel > Logs (or Hunting) | Uses `SigninLogs`, `AuditLogs`, `OfficeActivity`, `SecurityEvent`. Also runs in the unified Defender portal when Sentinel is onboarded to it. |

Defender XDR tables keep a `Timestamp` column even when streamed to Sentinel, so the queries work
unchanged in both places.

### Data you need

| Tables | Connector / license |
|---|---|
| `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceEvents` | Defender for Endpoint P2 (or Defender for Business) |
| `EmailEvents`, `EmailAttachmentInfo`, `UrlClickEvents` | Defender for Office 365 Plan 2 |
| `SigninLogs`, `AuditLogs` | Microsoft Entra ID connector in Sentinel (Entra ID P1/P2 for sign-in logs) |
| `OfficeActivity` | Microsoft 365 (Office 365) connector in Sentinel |
| `SecurityEvent` | Windows Security Events via AMA connector, with the right audit policy on domain controllers |

## When to use it

* **Daily**: run the High-severity queries in Initial Access, Credential Access and Impact as a
  morning sweep, or let the SOC agent run them.
* **During an incident**: jump to the tactic you suspect is next (an Initial Access hit means you
  check Execution, Persistence and Credential Access on the same device and account).
* **After new threat intel**: re-run the relevant tactic over a longer lookback (change `Lookback`).
* **When building detections**: promote a query to a Sentinel scheduled analytics rule or a
  Defender custom detection once its false-positive rate is acceptable (see below).

## How to use it

1. Open the query file, copy everything, and paste it into Advanced hunting or Sentinel Logs.
   The header is KQL comments, so it can stay in.
2. Run it. If it returns too much, read the **Tuning** line and adjust the `let` values at the top.
3. When it fires, follow the **Response** line.

### Turning a hunt into a detection

* **Defender custom detection** (Defender XDR queries): the query must return `Timestamp`,
  `DeviceId` and `ReportId`; the event-level queries in this library already project them.
* **Sentinel analytics rule**: create a scheduled rule, paste the query, set the frequency to match
  `Lookback`, and map entities (Account, Host, IP, URL, FileHash) to the projected columns.
* Use `kql-catalog export` to get every query and its metadata as JSON for an import script.

### Checking the library

The library is linted in CI with `kql-catalog`, which ships in this repository:

```bash
kql-catalog lint      # header fields, ATT&CK ids, table/platform consistency, bracket and string
                      # balance, smart quotes or dashes, dangling pipes, missing time filters
kql-catalog build     # regenerate the catalog below after adding a query
kql-catalog check     # CI fails if the catalog is out of date
kql-catalog export    # JSON index of every query
```

The linter checks structure, not semantics: it cannot connect to your workspace to verify column
names. Test a new query in your own environment before relying on it.

### Adding a query

1. Put it in the folder for its tactic (`TA0006-credential-access/`), with a kebab-case file name.
2. Copy the header from a neighbour, use the next free `Id` in that tactic, and fill in every field.
3. Run `kql-catalog lint` and `kql-catalog build`, then open a pull request.

## Catalog

<!-- catalog:start -->

_38 queries across 12 tactics. Generated by `kql-catalog build`; do not edit by hand._

### TA0001 Initial Access

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0001-001 | [User clicked through to a URL from a phishing or malware email](TA0001-initial-access/phish-url-clicked-through.kql) | [T1566.002](https://attack.mitre.org/techniques/T1566/002/), [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Defender XDR | High | EmailEvents, UrlClickEvents |
| KQL-TA0001-002 | [Malicious email attachment written to or run on a device](TA0001-initial-access/malicious-attachment-on-endpoint.kql) | [T1566.001](https://attack.mitre.org/techniques/T1566/001/), [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Defender XDR | High | EmailAttachmentInfo, DeviceFileEvents, DeviceProcessEvents |
| KQL-TA0001-003 | [Successful sign-in from an IP that was password spraying](TA0001-initial-access/spray-then-successful-signin.kql) | [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Sentinel | High | SigninLogs |
| KQL-TA0001-004 | [Successful sign-in over a legacy authentication protocol](TA0001-initial-access/legacy-auth-signin.kql) | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Sentinel | Medium | SigninLogs |
| KQL-TA0001-005 | [Web server process spawning a shell or recon tool (web shell / exploitation)](TA0001-initial-access/web-server-spawns-shell.kql) | [T1190](https://attack.mitre.org/techniques/T1190/), [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Defender XDR | High | DeviceProcessEvents |

### TA0002 Execution

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0002-001 | [Office application spawning a shell, script host or LOLBin](TA0002-execution/office-spawns-shell.kql) | [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Defender XDR | High | DeviceProcessEvents |
| KQL-TA0002-002 | [Encoded or download-cradle PowerShell](TA0002-execution/encoded-powershell.kql) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027.010](https://attack.mitre.org/techniques/T1027/010/), [T1105](https://attack.mitre.org/techniques/T1105/) | Defender XDR | Medium | DeviceProcessEvents |
| KQL-TA0002-003 | [Script host running a script from Downloads, Temp or a URL](TA0002-execution/script-host-from-user-folders.kql) | [T1059.005](https://attack.mitre.org/techniques/T1059/005/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Defender XDR | Medium | DeviceProcessEvents |

### TA0003 Persistence

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0003-001 | [Run key pointing at a user-writable path or script interpreter](TA0003-persistence/run-key-user-writable-path.kql) | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Defender XDR | Medium | DeviceRegistryEvents |
| KQL-TA0003-002 | [Scheduled task created to run a script, LOLBin or user-writable binary](TA0003-persistence/suspicious-scheduled-task.kql) | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Defender XDR | Medium | DeviceProcessEvents, DeviceEvents |
| KQL-TA0003-003 | [Service installed with a binary in a user-writable path or a script command](TA0003-persistence/service-user-writable-path.kql) | [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Defender XDR | High | DeviceRegistryEvents |
| KQL-TA0003-004 | [New credential added to an app registration or service principal](TA0003-persistence/app-credential-added.kql) | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Sentinel | Medium | AuditLogs |

### TA0004 Privilege Escalation

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0004-001 | [Privileged Entra ID role assigned](TA0004-privilege-escalation/entra-privileged-role-assigned.kql) | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | Sentinel | High | AuditLogs |
| KQL-TA0004-002 | [Member added to a sensitive Active Directory group](TA0004-privilege-escalation/ad-sensitive-group-member-added.kql) | [T1098.007](https://attack.mitre.org/techniques/T1098/007/) | Sentinel | High | SecurityEvent |
| KQL-TA0004-003 | [UAC bypass through an auto-elevating binary](TA0004-privilege-escalation/uac-bypass-auto-elevate.kql) | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Defender XDR | High | DeviceProcessEvents, DeviceRegistryEvents |

### TA0005 Defense Evasion

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0005-001 | [Microsoft Defender Antivirus tampering](TA0005-defense-evasion/defender-av-tampering.kql) | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Defender XDR | High | DeviceProcessEvents |
| KQL-TA0005-002 | [Windows event log cleared](TA0005-defense-evasion/event-log-cleared.kql) | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Defender XDR | High | DeviceProcessEvents, DeviceEvents |
| KQL-TA0005-003 | [Renamed system or attack tool binary (masquerading)](TA0005-defense-evasion/renamed-system-binary.kql) | [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Defender XDR | Medium | DeviceProcessEvents |

### TA0006 Credential Access

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0006-001 | [Password spray against Entra ID](TA0006-credential-access/entra-password-spray.kql) | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Sentinel | Medium | SigninLogs |
| KQL-TA0006-002 | [MFA fatigue - repeated MFA denials, possibly followed by an approval](TA0006-credential-access/mfa-fatigue.kql) | [T1621](https://attack.mitre.org/techniques/T1621/) | Sentinel | High | SigninLogs |
| KQL-TA0006-003 | [LSASS memory dumping](TA0006-credential-access/lsass-memory-dump.kql) | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Defender XDR | High | DeviceProcessEvents |
| KQL-TA0006-004 | [Kerberoasting - many RC4 service tickets requested by one account](TA0006-credential-access/kerberoasting-rc4-tickets.kql) | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Sentinel | High | SecurityEvent |

### TA0007 Discovery

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0007-001 | [Burst of domain reconnaissance commands](TA0007-discovery/domain-recon-command-burst.kql) | [T1087.002](https://attack.mitre.org/techniques/T1087/002/), [T1069.002](https://attack.mitre.org/techniques/T1069/002/), [T1482](https://attack.mitre.org/techniques/T1482/), [T1016](https://attack.mitre.org/techniques/T1016/), [T1033](https://attack.mitre.org/techniques/T1033/) | Defender XDR | Medium | DeviceProcessEvents |
| KQL-TA0007-002 | [Active Directory enumeration tools (AdFind, SharpHound, PowerView)](TA0007-discovery/ad-enumeration-tools.kql) | [T1087.002](https://attack.mitre.org/techniques/T1087/002/), [T1069.002](https://attack.mitre.org/techniques/T1069/002/), [T1482](https://attack.mitre.org/techniques/T1482/) | Defender XDR | High | DeviceProcessEvents |

### TA0008 Lateral Movement

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0008-001 | [Remote execution through PsExec-style services and Impacket](TA0008-lateral-movement/psexec-and-impacket-execution.kql) | [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Defender XDR | High | DeviceProcessEvents |
| KQL-TA0008-002 | [WMI process creation spawning shells or LOLBins](TA0008-lateral-movement/wmi-remote-process.kql) | [T1047](https://attack.mitre.org/techniques/T1047/) | Defender XDR | Medium | DeviceProcessEvents |
| KQL-TA0008-003 | [One device opening RDP connections to many internal hosts](TA0008-lateral-movement/rdp-fan-out.kql) | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Defender XDR | Medium | DeviceNetworkEvents |

### TA0009 Collection

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0009-001 | [Inbox rule that forwards, redirects or hides mail](TA0009-collection/inbox-rule-forward-or-hide.kql) | [T1114.003](https://attack.mitre.org/techniques/T1114/003/), [T1564.008](https://attack.mitre.org/techniques/T1564/008/) | Sentinel | High | OfficeActivity |
| KQL-TA0009-002 | [Unusual mass download from SharePoint or OneDrive](TA0009-collection/mass-cloud-file-download.kql) | [T1530](https://attack.mitre.org/techniques/T1530/), [T1213.002](https://attack.mitre.org/techniques/T1213/002/) | Sentinel | Medium | OfficeActivity |
| KQL-TA0009-003 | [Password-protected archive created with 7-Zip or WinRAR](TA0009-collection/password-protected-archive.kql) | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Defender XDR | Medium | DeviceProcessEvents |

### TA0011 Command and Control

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0011-001 | [Beaconing to a rare public IP](TA0011-command-and-control/beaconing-rare-destination.kql) | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1573](https://attack.mitre.org/techniques/T1573/) | Defender XDR | Medium | DeviceNetworkEvents |
| KQL-TA0011-002 | [LOLBin making outbound internet connections](TA0011-command-and-control/lolbin-outbound-connection.kql) | [T1218](https://attack.mitre.org/techniques/T1218/), [T1105](https://attack.mitre.org/techniques/T1105/) | Defender XDR | Medium | DeviceNetworkEvents |
| KQL-TA0011-003 | [Tunneling and remote-access tools](TA0011-command-and-control/tunneling-and-remote-access-tools.kql) | [T1572](https://attack.mitre.org/techniques/T1572/), [T1219](https://attack.mitre.org/techniques/T1219/), [T1090](https://attack.mitre.org/techniques/T1090/) | Defender XDR | Medium | DeviceProcessEvents, DeviceNetworkEvents |

### TA0010 Exfiltration

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0010-001 | [Rclone, MEGA or file-sharing service used to move data out](TA0010-exfiltration/rclone-and-file-sharing-exfil.kql) | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1048](https://attack.mitre.org/techniques/T1048/) | Defender XDR | High | DeviceProcessEvents, DeviceNetworkEvents |
| KQL-TA0010-002 | [File upload from the command line (curl, PowerShell, BITS)](TA0010-exfiltration/command-line-file-upload.kql) | [T1048.002](https://attack.mitre.org/techniques/T1048/002/), [T1567](https://attack.mitre.org/techniques/T1567/) | Defender XDR | Medium | DeviceProcessEvents |

### TA0040 Impact

| Id | Query | Techniques | Platform | Severity | Tables |
|---|---|---|---|---|---|
| KQL-TA0040-001 | [Shadow copy and backup deletion (inhibit system recovery)](TA0040-impact/shadow-copy-and-backup-deletion.kql) | [T1490](https://attack.mitre.org/techniques/T1490/) | Defender XDR | High | DeviceProcessEvents |
| KQL-TA0040-002 | [Mass file renaming with a new extension (ransomware encryption)](TA0040-impact/mass-file-rename-encryption.kql) | [T1486](https://attack.mitre.org/techniques/T1486/) | Defender XDR | High | DeviceFileEvents |
| KQL-TA0040-003 | [Mass file deletion in SharePoint or OneDrive](TA0040-impact/mass-cloud-file-deletion.kql) | [T1485](https://attack.mitre.org/techniques/T1485/) | Sentinel | Medium | OfficeActivity |

<!-- catalog:end -->
