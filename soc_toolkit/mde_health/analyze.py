"""Device-health rules. Pure functions over the collected fleet data."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from soc_toolkit.common.findings import Finding, raise_severity, sort_findings
from soc_toolkit.common.timeutil import days_between, parse_time

# Microsoft Defender Vulnerability Management secure-configuration IDs used by this report.
# check id, severity, title, recommendation
CONFIG_CHECKS: dict[str, tuple[str, str, str, str]] = {
    "scid-2010": ("av_not_active", "high", "Defender Antivirus is not in active mode",
                  "Make Defender Antivirus the active AV (or confirm the third-party AV is healthy) and "
                  "remove ForceDefenderPassiveMode if it is set by mistake."),
    "scid-2012": ("realtime_protection_off", "high", "Real-time protection is off",
                  "Turn real-time protection back on through Intune or Group Policy and find out who disabled it."),
    "scid-5090": ("realtime_protection_off", "high", "Real-time protection is off",
                  "Turn real-time protection back on in the macOS Defender configuration profile."),
    "scid-6090": ("realtime_protection_off", "high", "Real-time protection is off",
                  "Set real_time_protection_enabled to true in the Linux Defender managed configuration."),
    "scid-2011": ("av_signatures_outdated", "medium", "Antivirus security intelligence is out of date",
                  "Check that the device can reach the update source (WSUS, Microsoft Update or a file share)."),
    "scid-5095": ("av_signatures_outdated", "medium", "Antivirus security intelligence is out of date",
                  "Run 'mdatp definitions update' and check that the device can reach the update endpoints."),
    "scid-6095": ("av_signatures_outdated", "medium", "Antivirus security intelligence is out of date",
                  "Run 'mdatp definitions update' and check that the device can reach the update endpoints."),
    "scid-96": ("network_protection_off", "medium", "Network protection is off",
                "Set network protection to block mode; without it, Defender IP, URL and domain indicators "
                "do not block anything on this device."),
    "scid-2003": ("tamper_protection_off", "medium", "Tamper protection is off",
                  "Turn on tamper protection tenant-wide in the Defender portal (Settings > Endpoints > Advanced "
                  "features)."),
    "scid-2016": ("cloud_protection_off", "medium", "Cloud-delivered protection is off",
                  "Turn on cloud-delivered protection (MAPS) so new threats are blocked in seconds."),
}

# Hunting queries are split by setting so each stays far below the 100,000-row result limit.
CONFIG_QUERY_GROUPS: tuple[tuple[str, ...], ...] = (
    ("scid-2010",), ("scid-2012", "scid-5090", "scid-6090"), ("scid-2011", "scid-5095", "scid-6095"),
    ("scid-96",), ("scid-2003",), ("scid-2016",),
)

UNHEALTHY_SENSOR = {"impairedcommunication": "impaired communication",
                    "nosensordata": "no sensor data",
                    "nosensordataimpairedcommunication": "no sensor data and impaired communication"}


def config_query(ids: tuple[str, ...]) -> str:
    quoted = ", ".join(f'"{i}"' for i in ids)
    return ("DeviceTvmSecureConfigurationAssessment\n"
            f"| where ConfigurationId in ({quoted})\n"
            "| summarize arg_max(Timestamp, IsCompliant, IsApplicable) by DeviceId, ConfigurationId\n"
            "| project DeviceId, ConfigurationId, IsCompliant, IsApplicable, Timestamp")


@dataclass
class HealthConfig:
    inactive_days: int = 7
    retire_days: int = 30
    exclude_tags: set[str] = field(default_factory=set)
    now: datetime | None = None

    def __post_init__(self) -> None:
        if self.inactive_days < 1 or self.retire_days < self.inactive_days:
            raise ValueError("inactive_days must be >= 1 and retire_days >= inactive_days")
        self.exclude_tags = {t.lower() for t in self.exclude_tags}


@dataclass
class HealthResult:
    findings: list[Finding]
    devices: list[dict[str, Any]]
    stats: dict[str, Any]
    notes: list[str]


def _truthy(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("1", "true", "yes"):
        return True
    if text in ("0", "false", "no"):
        return False
    return None


def analyze(fleet: dict[str, Any], cfg: HealthConfig) -> HealthResult:
    now = cfg.now or parse_time(fleet.get("captured_at"))
    if now is None:
        raise ValueError("fleet data has no captured_at and no 'now' was given")
    config_rows: dict[str, dict[str, dict]] = defaultdict(dict)
    for row in fleet.get("config_assessments", []):
        config_rows[row.get("DeviceId", "")][row.get("ConfigurationId", "")] = row
    have_config = bool(fleet.get("config_assessments"))

    findings: list[Finding] = []
    devices: list[dict[str, Any]] = []
    onboarding_counts: Counter[str] = Counter()
    platform_counts: Counter[str] = Counter()
    active = excluded = no_config = 0

    for m in fleet.get("machines", []):
        tags = {t.lower() for t in (m.get("machineTags") or [])}
        if tags & cfg.exclude_tags:
            excluded += 1
            continue
        name = m.get("computerDnsName") or m.get("id") or "unknown"
        platform = m.get("osPlatform") or "Unknown"
        onboarding = (m.get("onboardingStatus") or "").lower()
        health = (m.get("healthStatus") or "").lower()
        last_seen = parse_time(m.get("lastSeen"))
        age = days_between(now, last_seen) if last_seen else None
        high_value = (m.get("deviceValue") or "").lower() == "high"
        issues: list[str] = []
        onboarding_counts[onboarding or "unknown"] += 1
        platform_counts[platform] += 1
        base_evidence = {"device_id": m.get("id"), "platform": platform, "os_version": m.get("version"),
                         "health": m.get("healthStatus"), "last_seen": m.get("lastSeen"),
                         "device_group": m.get("rbacGroupName"), "device_value": m.get("deviceValue")}
        value_note = " High-value device." if high_value else ""

        def add(check: str, severity: str, title: str, detail: str, rec: str) -> None:
            sev = raise_severity(severity) if high_value and severity != "info" else severity
            findings.append(Finding(check, sev, title, name, detail + value_note, rec, dict(base_evidence)))
            issues.append(title)

        if onboarding == "canbeonboarded":
            add("not_onboarded", "high", "Device seen on the network but not onboarded",
                f"{platform} device discovered by Defender device discovery; it has no EDR coverage.",
                "Onboard it (Intune, GPO, script or Azure Arc) or tag it as an approved exception.")
        elif onboarding == "unsupported":
            add("unsupported_device", "low", "Device platform cannot be onboarded",
                f"{platform} device discovered on the network; Defender for Endpoint does not support it.",
                "Isolate unsupported devices on their own network segment and monitor them with network controls.")
        elif onboarding == "insufficientinfo":
            add("insufficient_info", "info", "Discovered device with too little information",
                "Defender could not classify this discovered device.",
                "No action needed unless it keeps appearing; then identify the owner.")
        elif onboarding == "onboarded":
            if health == "inactive" or (age is not None and age >= cfg.inactive_days):
                seen = f"last report {age} days ago" if age is not None else "no last-seen time"
                retired = age is not None and age >= cfg.retire_days
                add("inactive_device", "medium",
                    "Onboarded device stopped reporting (inactive or offboarded)",
                    f"Health status {m.get('healthStatus') or 'unknown'}, {seen}."
                    + (" Likely offboarded, re-imaged or retired." if retired else ""),
                    "Confirm the device still exists. If it does, check the Sense service and connectivity "
                    "to the Defender endpoints; if not, remove it from inventory or tag it as retired.")
            else:
                active += 1
                if health in UNHEALTHY_SENSOR:
                    add("sensor_unhealthy", "high", "Defender sensor is not reporting correctly",
                        f"Health status: {UNHEALTHY_SENSOR[health]}.",
                        "Run the Defender Client Analyzer on the device and check proxy and firewall access "
                        "to the Defender service URLs.")
                rows = config_rows.get(m.get("id", ""), {})
                if have_config and not rows and platform.lower().startswith(("windows", "macos", "linux")):
                    no_config += 1
                for scid, row in sorted(rows.items()):
                    rule = CONFIG_CHECKS.get(scid)
                    if not rule or _truthy(row.get("IsApplicable")) is False:
                        continue
                    if _truthy(row.get("IsCompliant")) is False:
                        check, severity, title, rec = rule
                        add(check, severity, title, f"{platform}: secure configuration {scid} is not compliant.",
                            rec)
        devices.append({"device": name, "device_id": m.get("id"), "platform": platform,
                        "os_version": m.get("version"), "onboarding": m.get("onboardingStatus"),
                        "health": m.get("healthStatus"), "last_seen": m.get("lastSeen"),
                        "device_value": m.get("deviceValue"), "device_group": m.get("rbacGroupName"),
                        "issues": issues})

    onboarded = onboarding_counts.get("onboarded", 0)
    discoverable = onboarded + onboarding_counts.get("canbeonboarded", 0)
    by_check = Counter(f.check for f in findings)
    stats = {
        "devices_total": len(devices),
        "devices_excluded_by_tag": excluded,
        "onboarded": onboarded,
        "not_onboarded": onboarding_counts.get("canbeonboarded", 0),
        "onboarding_coverage_pct": round(100 * onboarded / discoverable, 1) if discoverable else None,
        "active_onboarded": active,
        "healthy_active_devices": sum(1 for d in devices if d["onboarding"] and d["onboarding"].lower() == "onboarded"
                                      and not d["issues"]),
        "devices_without_config_data": no_config,
        "by_check": dict(sorted(by_check.items())),
        "by_platform": dict(sorted(platform_counts.items())),
    }
    notes = [f"{k}: {v}" for k, v in sorted((fleet.get("errors") or {}).items())]
    if not have_config and "config_assessments" not in (fleet.get("errors") or {}):
        notes.append("config_assessments: no secure-configuration data returned; antivirus and network "
                     "protection checks did not run (needs Defender Vulnerability Management data).")
    if no_config:
        notes.append(f"{no_config} active device(s) had no secure-configuration assessment yet; their AV "
                     "and network-protection state is unknown.")
    return HealthResult(sort_findings(findings), devices, stats, notes)
