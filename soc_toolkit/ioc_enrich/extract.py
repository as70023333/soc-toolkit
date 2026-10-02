"""Find indicators in free text: refang, extract, classify, de-duplicate.

Handles defanged notes (hxxp, [.], [:]), Safe Links-free URLs, IPv4/IPv6, domains, and MD5,
SHA-1 and SHA-256 hashes. A line that is a single token is classified on its own, which is how
"one IOC per line" files work, including domains on file-extension-like TLDs (.zip, .mov).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

HASH_TYPES = ("md5", "sha1", "sha256")
IOC_TYPES = ("ipv4", "ipv6", "domain", "url", *HASH_TYPES)

# Top-level domains recognised in free text: generic, popular new gTLDs and every ccTLD.
_GENERIC = (
    "com net org edu gov mil int info biz name pro mobi asia tel travel jobs cat coop aero museum xxx "
    "io co ai app dev cloud online site top xyz club shop store tech live icu buzz vip work link click fun "
    "space website host press tv me cc pw su ws to ly gg im is sh la ms nu tk ml ga cf gq "
    "cfd sbs rest bond lol monster quest cyou today support help email page best fit world life network "
    "digital agency solutions services group company center systems security finance money loan win bid "
    "racing review stream download trade date party science men accountant faith cricket webcam ink ltd "
    "global news one team zone run gdn ninja guru rocks business email social media blog design studio "
    "agency capital ventures events photography photos pics pictures tips tools wiki world zip mov "
    "microsoft google amazon apple windows office azure example test invalid localhost onion"
)
_CC = (
    "ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by "
    "bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi "
    "fj fk fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in "
    "io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md "
    "me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe "
    "pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st "
    "su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu "
    "wf ws ye yt za zm zw"
)
KNOWN_TLDS = frozenset((_GENERIC + " " + _CC).split())
# TLDs that collide with common file extensions; in free text "script.py" is a file, not a domain.
FILE_LIKE_TLDS = frozenset({"py", "md", "sh", "pl", "rs", "cs", "ps", "zip", "mov", "so"})

_REFANG = (
    (re.compile(r"(?i)\bh(?:xx|\[xx\]|\*\*)p(s?)(?:\[:\]|:)//"), r"http\1://"),
    (re.compile(r"(?i)\bfxp://"), "ftp://"),
    (re.compile(r"(?i)\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"(?i)\[@\]|\[at\]"), "@"),
)

_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`{}|\\^\[\]]+")
_HASH = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_DOMAIN = re.compile(r"(?i)(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59}))\.?(?![\w-])")
_DOMAIN_FULL = re.compile(r"(?i)^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\.?$")
_TRAILING = ".,;:!?'\""

_NON_ROUTABLE = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
))


@dataclass(frozen=True, order=True)
class Indicator:
    type: str
    value: str

    @property
    def is_hash(self) -> bool:
        return self.type in HASH_TYPES

    @property
    def is_ip(self) -> bool:
        return self.type in ("ipv4", "ipv6")

    def host(self) -> str:
        """Domain or IP for host-based lookups; for URLs the URL's host."""
        if self.type == "url":
            from urllib.parse import urlsplit
            return (urlsplit(self.value).hostname or "").lower()
        return self.value


def refang(text: str) -> str:
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text


def defang(ind: Indicator) -> str:
    if ind.is_hash:
        return ind.value
    value = ind.value
    if ind.type == "url":
        value = re.sub(r"(?i)^http", "hxxp", value)
        value = re.sub(r"(?i)^ftp", "fxp", value)
    if ind.type == "ipv6":
        return value.replace(":", "[:]")
    return value.replace(".", "[.]")


def is_non_routable(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in _NON_ROUTABLE if net.version == ip.version)


def _clean_url(url: str) -> str:
    url = url.rstrip(_TRAILING)
    while url.endswith(")") and url.count("(") < url.count(")"):
        url = url[:-1].rstrip(_TRAILING)
    return url


def _ip(value: str) -> Indicator | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version == 4:
        return Indicator("ipv4", str(ip))
    if "::" not in value and value.count(":") != 7:
        return None
    if len(re.findall(r"[0-9A-Fa-f]{1,4}", value)) < 3:
        return None  # "::" or "a::b" in prose or code is not an address worth enriching
    return Indicator("ipv6", str(ip))


def _hash(value: str) -> Indicator:
    return Indicator({32: "md5", 40: "sha1", 64: "sha256"}[len(value)], value.lower())


def classify(token: str) -> Indicator | None:
    """Classify a single token, permissively (any alphabetic TLD counts)."""
    token = refang(token.strip()).strip(_TRAILING + "<>()[]")
    if not token:
        return None
    if re.fullmatch(r"(?i)(?:https?|ftp)://\S+", token):
        return Indicator("url", _clean_url(token))
    if re.fullmatch(r"[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}", token):
        return _hash(token)
    ip = _ip(token)
    if ip:
        return ip
    if _DOMAIN_FULL.match(token) and not re.fullmatch(r"[\d.]+", token):
        return Indicator("domain", token.lower().rstrip("."))
    return None


def extract(text: str, *, url_hosts: bool = False) -> list[Indicator]:
    """Extract unique indicators in order of first appearance."""
    found: dict[Indicator, None] = {}

    def add(ind: Indicator | None) -> None:
        if ind is not None:
            found.setdefault(ind, None)

    for raw_line in text.splitlines():
        line = refang(raw_line)
        stripped = line.strip()
        if stripped and not re.search(r"\s", stripped):
            single = classify(stripped)
            if single:
                add(single)
                if url_hosts and single.type == "url":
                    add(classify(single.host()))
                continue
        masked = line
        for m in _URL.finditer(line):
            url = _clean_url(m.group(0))
            ind = Indicator("url", url)
            add(ind)
            if url_hosts:
                add(classify(ind.host()))
            masked = masked.replace(m.group(0), " " * len(m.group(0)), 1)
        for m in _HASH.finditer(masked):
            add(_hash(m.group(1)))
        masked = _HASH.sub(lambda m: " " * len(m.group(0)), masked)
        for m in _IPV4.finditer(masked):
            add(_ip(m.group(0)))
        for m in _IPV6.finditer(masked):
            add(_ip(m.group(0)))
        masked = _IPV4.sub(lambda m: " " * len(m.group(0)), masked)
        for m in _DOMAIN.finditer(masked):
            domain = m.group(1).lower()
            tld = domain.rsplit(".", 1)[-1]
            if tld.startswith("xn--") or (tld in KNOWN_TLDS and tld not in FILE_LIKE_TLDS):
                add(Indicator("domain", domain))
    return list(found)
