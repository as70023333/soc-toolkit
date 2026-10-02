"""Threat-intel feed connectors.

Each provider answers ``lookup(indicator) -> ProviderResult``; batch providers (Sentinel TI) also
implement ``lookup_many``. The interface mirrors the soc-agent's ``ThreatIntelProvider`` so the same
connectors serve the autonomous SOC analyst and this standalone CLI.

Every request is a lookup. Nothing is ever submitted or scanned, so an indicator is never shared
with a feed beyond the lookup itself.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from soc_toolkit.common.http import HttpClient, HttpError, Response
from soc_toolkit.common.msapi import DefenderApi, LogAnalyticsApi
from soc_toolkit.ioc_enrich.extract import HASH_TYPES, Indicator
from soc_toolkit.ioc_enrich.models import ProviderResult

ALL_TYPES = frozenset({"ipv4", "ipv6", "domain", "url", *HASH_TYPES})


class RateLimiter:
    """Spaces calls evenly so a free-tier quota (e.g. 4/minute) is never exceeded."""

    def __init__(self, per_minute: float | None, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.interval = 60.0 / per_minute if per_minute else 0.0
        self._next = 0.0
        self._lock = threading.Lock()
        self._clock = clock
        self._sleep = sleep

    def acquire(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = self._clock()
            start = max(now, self._next)
            self._next = start + self.interval
        if start > now:
            self._sleep(start - now)


def _epoch_iso(value: Any) -> str:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


class Provider:
    name = "provider"
    types: frozenset[str] = ALL_TYPES
    key_env = ""
    default_per_minute: float | None = None
    batch = False

    def __init__(self, http: HttpClient, key: str = "", per_minute: float | None = None) -> None:
        self.http = http
        self.key = key
        self.limiter = RateLimiter(per_minute if per_minute is not None else self.default_per_minute)

    def supports(self, ind: Indicator) -> bool:
        return ind.type in self.types

    def lookup(self, ind: Indicator) -> ProviderResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def lookup_many(self, inds: list[Indicator]) -> dict[Indicator, ProviderResult]:
        return {ind: self.lookup(ind) for ind in inds}

    # helpers -------------------------------------------------------------------------------
    def _result(self, status: str, verdict: str = "unknown", score: int | None = None, summary: str = "",
                **extra: Any) -> ProviderResult:
        return ProviderResult(self.name, status, verdict, score, summary, **extra)

    def not_found(self, summary: str = "not in this feed") -> ProviderResult:
        return self._result("not_found", summary=summary)

    def _request(self, method: str, url: str, **kwargs: Any) -> Response:
        self.limiter.acquire()
        try:
            return self.http.request(method, url, **kwargs)
        except HttpError as exc:
            if exc.status in (401, 403):
                raise HttpError(exc.status, f"{self.name} rejected the API key or permission") from exc
            if exc.status == 429:
                raise HttpError(429, f"{self.name} quota exhausted or rate limited") from exc
            raise


# --------------------------------------------------------------------------------------------- VirusTotal

class VirusTotal(Provider):
    name = "virustotal"
    key_env = "VIRUSTOTAL_API_KEY"
    default_per_minute = 4  # public API; set VT_RATE_PER_MIN for a premium key
    BASE = "https://www.virustotal.com/api/v3"

    def lookup(self, ind: Indicator) -> ProviderResult:
        value = ind.value
        if ind.is_hash:
            path, gui = f"files/{value}", f"file/{value}"
        elif ind.is_ip:
            path, gui = f"ip_addresses/{value}", f"ip-address/{value}"
        elif ind.type == "domain":
            path, gui = f"domains/{value}", f"domain/{value}"
        else:
            url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
            path, gui = f"urls/{url_id}", f"url/{hashlib.sha256(value.encode('utf-8')).hexdigest()}"
        resp = self._request("GET", f"{self.BASE}/{path}", headers={"x-apikey": self.key}, ok=(200,), allow=(404,))
        link = f"https://www.virustotal.com/gui/{gui}"
        if resp.status == 404:
            return self.not_found("never seen by VirusTotal")
        attrs = ((resp.json() or {}).get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious", 0) or 0)
        sus = int(stats.get("suspicious", 0) or 0)
        engines = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
        label = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")) or ""
        tags = ([label] if label else []) + [str(t) for t in (attrs.get("tags") or [])[:5]]
        details = {"malicious": mal, "suspicious": sus, "engines": engines,
                   "reputation": attrs.get("reputation"),
                   "first_seen": _epoch_iso(attrs.get("first_submission_date") or attrs.get("creation_date")),
                   "name": attrs.get("meaningful_name") or "", "as_owner": attrs.get("as_owner") or "",
                   "country": attrs.get("country") or ""}
        summary = f"{mal}/{engines} engines malicious" + (f", {sus} suspicious" if sus else "")
        if label:
            summary += f" ({label})"
        if mal >= 3:
            return self._result("hit", "malicious", min(100, 70 + 2 * mal), summary, tags=tags, link=link, details=details)
        if mal >= 1 or sus >= 2:
            return self._result("hit", "suspicious", min(65, 40 + 10 * mal + 5 * sus), summary, tags=tags,
                                link=link, details=details)
        if engines:
            return self._result("clean", "harmless", 0, summary, tags=tags, link=link, details=details)
        return self._result("clean", "unknown", None, "known to VirusTotal, not yet analysed", link=link,
                            details=details)


# --------------------------------------------------------------------------------------------- AbuseIPDB

class AbuseIPDB(Provider):
    name = "abuseipdb"
    types = frozenset({"ipv4", "ipv6"})
    key_env = "ABUSEIPDB_API_KEY"
    default_per_minute = 60

    def lookup(self, ind: Indicator) -> ProviderResult:
        resp = self._request("GET", "https://api.abuseipdb.com/api/v2/check",
                             params={"ipAddress": ind.value, "maxAgeInDays": "90"},
                             headers={"Key": self.key}, ok=(200,))
        data = (resp.json() or {}).get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        tags = [t for t in (data.get("usageType"), "tor" if data.get("isTor") else None) if t]
        details = {"abuse_confidence": score, "reports": reports, "country": data.get("countryCode") or "",
                   "isp": data.get("isp") or "", "domain": data.get("domain") or "",
                   "last_reported": data.get("lastReportedAt") or "", "tor": bool(data.get("isTor")),
                   "benign_service": bool(data.get("isWhitelisted"))}
        link = f"https://www.abuseipdb.com/check/{urllib.parse.quote(ind.value)}"
        summary = f"confidence {score}%, {reports} report(s) in 90 days"
        if data.get("isWhitelisted"):
            return self._result("clean", "harmless", 0, summary + ", allowlisted", tags=tags, link=link, details=details)
        if score >= 75:
            return self._result("hit", "malicious", score, summary, tags=tags, link=link, details=details)
        if score >= 25:
            return self._result("hit", "suspicious", max(35, score), summary, tags=tags, link=link, details=details)
        if reports == 0:
            return self._result("clean", "unknown", None, "no abuse reports", tags=tags, link=link, details=details)
        return self._result("clean", "unknown", score, summary, tags=tags, link=link, details=details)


# --------------------------------------------------------------------------------------------- AlienVault OTX

class OTX(Provider):
    name = "otx"
    key_env = "OTX_API_KEY"
    default_per_minute = 100
    SECTIONS = {"ipv4": ("IPv4", "ip"), "ipv6": ("IPv6", "ip"), "domain": ("domain", "domain"),
                "url": ("url", "url"), "md5": ("file", "file"), "sha1": ("file", "file"), "sha256": ("file", "file")}

    def lookup(self, ind: Indicator) -> ProviderResult:
        section, gui = self.SECTIONS[ind.type]
        value = urllib.parse.quote(ind.value, safe="") if ind.type == "url" else ind.value
        resp = self._request("GET", f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
                             headers={"X-OTX-API-KEY": self.key}, ok=(200,), allow=(400, 404))
        link = f"https://otx.alienvault.com/indicator/{gui}/{urllib.parse.quote(ind.value, safe='')}"
        if resp.status != 200:
            return self.not_found()
        data = resp.json() or {}
        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        count = int(pulse_info.get("count") or len(pulses))
        families = sorted({(f.get("display_name") or f.get("id") or "") for p in pulses
                           for f in (p.get("malware_families") or []) if isinstance(f, dict)} - {""})
        names = [p.get("name", "") for p in pulses[:3] if p.get("name")]
        details = {"pulses": count, "pulse_names": names, "malware_families": families}
        if data.get("validation"):
            details["benign_service"] = True
            return self._result("clean", "harmless", 0, "on OTX's allowlist", link=link, details=details)
        if count == 0:
            return self._result("clean", "unknown", None, "in no OTX pulse", link=link, details=details)
        summary = f"in {count} pulse(s)" + (f"; families: {', '.join(families[:3])}" if families else "")
        return self._result("hit", "suspicious", 55 if count >= 5 else 40, summary, tags=families[:5],
                            link=link, details=details)


# --------------------------------------------------------------------------------------------- GreyNoise

class GreyNoise(Provider):
    name = "greynoise"
    types = frozenset({"ipv4"})
    key_env = "GREYNOISE_API_KEY"
    default_per_minute = 30
    key_optional = True

    def lookup(self, ind: Indicator) -> ProviderResult:
        headers = {"key": self.key} if self.key else {}
        resp = self._request("GET", f"https://api.greynoise.io/v3/community/{ind.value}",
                             headers=headers, ok=(200,), allow=(404,))
        link = f"https://viz.greynoise.io/ip/{ind.value}"
        if resp.status == 404:
            return self.not_found("not seen scanning the internet")
        data = resp.json() or {}
        classification = (data.get("classification") or "unknown").lower()
        name = data.get("name") or ""
        details = {"classification": classification, "noise": bool(data.get("noise")), "riot": bool(data.get("riot")),
                   "name": name, "last_seen": data.get("last_seen") or ""}
        tags = [t for t in (name if name and name.lower() != "unknown" else "",
                            "riot" if data.get("riot") else "") if t]
        if classification == "malicious":
            return self._result("hit", "malicious", 75, "classified malicious (mass scanning/exploitation)",
                                tags=tags, link=link, details=details)
        if data.get("riot") or classification == "benign":
            details["benign_service"] = bool(data.get("riot"))
            what = f"known business service ({name})" if data.get("riot") else f"benign scanner ({name})"
            return self._result("clean", "harmless", 0, what, tags=tags, link=link, details=details)
        if data.get("noise"):
            return self._result("hit", "suspicious", 35, "opportunistic internet scanner", tags=tags,
                                link=link, details=details)
        return self._result("clean", "unknown", None, "no classification", link=link, details=details)


# --------------------------------------------------------------------------------------------- abuse.ch

class MalwareBazaar(Provider):
    name = "malwarebazaar"
    types = frozenset(HASH_TYPES)
    key_env = "ABUSECH_AUTH_KEY"
    default_per_minute = 60

    def lookup(self, ind: Indicator) -> ProviderResult:
        resp = self._request("POST", "https://mb-api.abuse.ch/api/v1/", form={"query": "get_info", "hash": ind.value},
                             headers={"Auth-Key": self.key}, ok=(200,))
        data = resp.json() or {}
        status = data.get("query_status")
        if status in ("hash_not_found", "no_results", "illegal_hash"):
            return self.not_found()
        if status != "ok" or not data.get("data"):
            return self._result("error", summary=f"unexpected answer: {status}")
        sample = data["data"][0]
        signature = sample.get("signature") or ""
        tags = ([signature] if signature else []) + [str(t) for t in (sample.get("tags") or [])[:5]]
        details = {"signature": signature, "file_type": sample.get("file_type") or "",
                   "file_name": sample.get("file_name") or "", "first_seen": sample.get("first_seen") or ""}
        summary = "known malware sample" + (f" ({signature})" if signature else "")
        return self._result("hit", "malicious", 95, summary, tags=tags,
                            link=f"https://bazaar.abuse.ch/sample/{sample.get('sha256_hash', ind.value)}/",
                            details=details)


class URLhaus(Provider):
    name = "urlhaus"
    types = frozenset({"url", "domain", "ipv4", "md5", "sha256"})
    key_env = "ABUSECH_AUTH_KEY"
    default_per_minute = 60
    BASE = "https://urlhaus-api.abuse.ch/v1"

    def lookup(self, ind: Indicator) -> ProviderResult:
        headers = {"Auth-Key": self.key}
        if ind.type == "url":
            data = self._request("POST", f"{self.BASE}/url/", form={"url": ind.value}, headers=headers, ok=(200,)).json() or {}
            if data.get("query_status") != "ok":
                return self.not_found()
            online = data.get("url_status") == "online"
            tags = [t for t in [data.get("threat")] + list(data.get("tags") or []) if t]
            details = {"url_status": data.get("url_status"), "threat": data.get("threat"),
                       "date_added": data.get("date_added")}
            summary = f"malware distribution URL ({data.get('url_status')})"
            return self._result("hit", "malicious", 95 if online else 80, summary, tags=tags[:6],
                                link=data.get("urlhaus_reference") or "", details=details)
        if ind.is_hash:
            field = "md5_hash" if ind.type == "md5" else "sha256_hash"
            data = self._request("POST", f"{self.BASE}/payload/", form={field: ind.value}, headers=headers, ok=(200,)).json() or {}
            if data.get("query_status") != "ok":
                return self.not_found()
            signature = data.get("signature") or ""
            details = {"signature": signature, "file_type": data.get("file_type"), "first_seen": data.get("firstseen"),
                       "url_count": data.get("url_count")}
            sha = data.get("sha256_hash") or ""
            return self._result("hit", "malicious", 90, "payload distributed by malware URLs"
                                + (f" ({signature})" if signature else ""), tags=[signature] if signature else [],
                                link=f"https://urlhaus.abuse.ch/sample/{sha}/" if sha else "", details=details)
        data = self._request("POST", f"{self.BASE}/host/", form={"host": ind.value}, headers=headers, ok=(200,)).json() or {}
        if data.get("query_status") != "ok":
            return self.not_found()
        urls = data.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        total = int(data.get("url_count") or len(urls))
        listed = [name for name, state in (data.get("blacklists") or {}).items() if state and state != "not listed"]
        details = {"url_count": total, "online": online, "blocklists": listed}
        link = data.get("urlhaus_reference") or f"https://urlhaus.abuse.ch/host/{ind.value}/"
        summary = f"{total} malware URL(s) on this host, {online} online" + (f"; listed on {', '.join(listed)}" if listed else "")
        if total > 500 and not listed:
            return self._result("hit", "suspicious", 40, summary + " (large shared host)", link=link, details=details)
        if listed or online:
            return self._result("hit", "malicious", 85 if listed else 75, summary, link=link, details=details)
        return self._result("hit", "suspicious", 50, summary, link=link, details=details)


class ThreatFox(Provider):
    name = "threatfox"
    types = frozenset({"ipv4", "domain", "url", "md5", "sha256"})
    key_env = "ABUSECH_AUTH_KEY"
    default_per_minute = 60

    def lookup(self, ind: Indicator) -> ProviderResult:
        exact = ind.type != "ipv4"  # ThreatFox stores IPs as ip:port
        data = self._request("POST", "https://threatfox-api.abuse.ch/api/v1/",
                             json_body={"query": "search_ioc", "search_term": ind.value, "exact_match": exact},
                             headers={"Auth-Key": self.key}, ok=(200,)).json() or {}
        if data.get("query_status") != "ok" or not isinstance(data.get("data"), list):
            return self.not_found()
        rows = data["data"]
        if ind.type == "ipv4":
            rows = [r for r in rows if str(r.get("ioc", "")).split(":")[0] == ind.value]
        if not rows:
            return self.not_found()
        families = sorted({r.get("malware_printable") for r in rows if r.get("malware_printable")})
        threats = sorted({r.get("threat_type") for r in rows if r.get("threat_type")})
        confidence = max(int(r.get("confidence_level") or 0) for r in rows)
        details = {"malware": families, "threat_types": threats, "confidence": confidence,
                   "first_seen": min(str(r.get("first_seen") or "") for r in rows)}
        summary = f"{', '.join(threats) or 'IOC'} for {', '.join(families) or 'unknown malware'}"
        return self._result("hit", "malicious", max(70, min(100, confidence)), summary, tags=families[:5],
                            link=f"https://threatfox.abuse.ch/ioc/{rows[0].get('id')}/", details=details)


# --------------------------------------------------------------------------------------------- Microsoft

class SentinelTI(Provider):
    """Your Sentinel threat-intelligence indicators (Defender TI, TAXII and MISP feeds you connected).

    One KQL query covers every indicator in the run.
    """

    name = "sentinel_ti"
    batch = True
    LOOKBACK = "90d"

    def __init__(self, http: HttpClient, api: LogAnalyticsApi, workspace_id: str, table: str = "ThreatIntelIndicators") -> None:
        super().__init__(http)
        if table not in ("ThreatIntelIndicators", "ThreatIntelligenceIndicator"):
            raise ValueError("SENTINEL_TI_TABLE must be ThreatIntelIndicators or ThreatIntelligenceIndicator")
        self.api = api
        self.workspace_id = workspace_id
        self.table = table

    def query(self, values: Iterable[str]) -> str:
        literal = json.dumps(sorted({v.lower() for v in values}))  # JSON string escaping keeps values as data
        if self.table == "ThreatIntelIndicators":
            return (f"let iocs = dynamic({literal});\n"
                    "ThreatIntelIndicators\n"
                    f"| where TimeGenerated > ago({self.LOOKBACK})\n"
                    "| where IsActive == true and coalesce(IsDeleted, false) == false and coalesce(Revoked, false) == false\n"
                    "| where isnull(ValidUntil) or ValidUntil > now()\n"
                    "| extend Value = tolower(ObservableValue)\n"
                    "| where Value in (iocs)\n"
                    "| summarize arg_max(TimeGenerated, ObservableKey, Confidence, SourceSystem, Data) by Id, Value\n"
                    "| project Value, Confidence, SourceSystem, Name = tostring(Data.name), "
                    "Description = tostring(Data.description)")
        return (f"let iocs = dynamic({literal});\n"
                "ThreatIntelligenceIndicator\n"
                f"| where TimeGenerated > ago({self.LOOKBACK})\n"
                "| where Active == true and ExpirationDateTime > now()\n"
                "| mv-expand Value = pack_array(NetworkIP, NetworkSourceIP, NetworkDestinationIP, DomainName, Url, "
                "FileHashValue) to typeof(string)\n"
                "| extend Value = tolower(Value)\n"
                "| where isnotempty(Value) and Value in (iocs)\n"
                "| summarize arg_max(TimeGenerated, ConfidenceScore, ThreatType, Description, SourceSystem) by IndicatorId, Value\n"
                "| project Value, Confidence = ConfidenceScore, SourceSystem, Name = ThreatType, Description")

    def lookup(self, ind: Indicator) -> ProviderResult:
        return self.lookup_many([ind])[ind]

    def lookup_many(self, inds: list[Indicator]) -> dict[Indicator, ProviderResult]:
        if not inds:
            return {}
        rows = self.api.query(self.workspace_id, self.query(i.value for i in inds))
        by_value: dict[str, list[dict]] = {}
        for row in rows:
            by_value.setdefault(str(row.get("Value", "")).lower(), []).append(row)
        out: dict[Indicator, ProviderResult] = {}
        for ind in inds:
            hits = by_value.get(ind.value.lower())
            if not hits:
                out[ind] = self.not_found("not in your Sentinel threat intelligence")
                continue
            confidence = max(int(h.get("Confidence") or 0) for h in hits)
            sources = sorted({str(h.get("SourceSystem") or "") for h in hits} - {""})
            names = sorted({str(h.get("Name") or "") for h in hits} - {""})
            summary = f"{len(hits)} active indicator(s) from {', '.join(sources) or 'Sentinel'}"
            if names:
                summary += f": {', '.join(names[:3])}"
            details = {"confidence": confidence, "sources": sources, "names": names}
            if confidence >= 50:
                out[ind] = self._result("hit", "malicious", max(70, confidence), summary, tags=names[:5], details=details)
            else:
                out[ind] = self._result("hit", "suspicious", 45, summary + f" (confidence {confidence})",
                                        tags=names[:5], details=details)
        return out


class DefenderIndicators(Provider):
    """Is this IOC already in your Defender custom indicators (blocked, alerted or allowed)?"""

    name = "defender_indicators"
    default_per_minute = 90
    BLOCK = {"block", "alertandblock", "blockandremediate"}
    WATCH = {"alert", "audit", "warn"}

    def __init__(self, http: HttpClient, api: DefenderApi) -> None:
        super().__init__(http)
        self.api = api

    def lookup(self, ind: Indicator) -> ProviderResult:
        self.limiter.acquire()
        escaped = ind.value.replace("'", "''")
        rows = self.api.get_all("/api/indicators", {"$filter": f"indicatorValue eq '{escaped}'"})
        if not rows:
            return self.not_found("not in your Defender indicators")
        actions = sorted({str(r.get("action") or "") for r in rows} - {""})
        lowered = {a.lower() for a in actions}
        expires = sorted(str(r.get("expirationTime") or "") for r in rows if r.get("expirationTime"))
        details = {"actions": actions, "titles": [r.get("title") for r in rows if r.get("title")][:3],
                   "expires": expires[-1] if expires else ""}
        summary = f"already in your Defender indicators: {', '.join(actions)}"
        if lowered & self.BLOCK:
            return self._result("hit", "malicious", 80, summary, details=details)
        if "allowed" in lowered:
            details["benign_service"] = True
            return self._result("clean", "harmless", 0, summary + " (your organization trusts it)", details=details)
        if lowered & self.WATCH:
            return self._result("hit", "suspicious", 50, summary, details=details)
        return self._result("hit", "unknown", None, summary, details=details)


# --------------------------------------------------------------------------------------------- demo

class DemoProvider(Provider):
    """Answers from a fixture so the tool can be demonstrated offline."""

    def __init__(self, name: str, types: Iterable[str], table: dict[str, dict]) -> None:
        super().__init__(HttpClient())
        self.name = name
        self.types = frozenset(types)
        self.table = {k.lower(): v for k, v in table.items()}

    def lookup(self, ind: Indicator) -> ProviderResult:
        entry = self.table.get(ind.value.lower())
        if entry is None:
            return self.not_found()
        result = ProviderResult.from_dict({"provider": self.name, **entry})
        result.provider = self.name
        return result


EXTERNAL_PROVIDERS: dict[str, type[Provider]] = {
    p.name: p for p in (VirusTotal, AbuseIPDB, OTX, GreyNoise, MalwareBazaar, URLhaus, ThreatFox)
}
