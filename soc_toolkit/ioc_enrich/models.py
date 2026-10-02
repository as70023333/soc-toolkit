"""Result types and the verdict math that combines feeds."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from soc_toolkit.ioc_enrich.extract import Indicator

VERDICTS = ("malicious", "suspicious", "harmless", "unknown")
MALICIOUS_AT = 70
SUSPICIOUS_AT = 35


@dataclass
class ProviderResult:
    """One feed's answer about one indicator.

    status:  hit (the feed knows it), clean (looked up, nothing bad), not_found, error, skipped
    verdict: malicious, suspicious, harmless or unknown
    score:   0-100 maliciousness on a common scale, or None when the feed gives no opinion
    """

    provider: str
    status: str
    verdict: str = "unknown"
    score: int | None = None
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    link: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProviderResult":
        allowed = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**allowed)


@dataclass
class Enrichment:
    indicator: Indicator
    verdict: str
    score: int
    results: list[ProviderResult]
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.indicator.type, "value": self.indicator.value, "verdict": self.verdict,
                "score": self.score, "note": self.note, "results": [r.to_dict() for r in self.results]}

    def sources(self, verdict: str) -> list[str]:
        return [r.provider for r in self.results if r.verdict == verdict and r.status == "hit"]


def aggregate(results: list[ProviderResult]) -> tuple[str, int]:
    """Combine feed answers into one verdict and score.

    The strongest single opinion sets the score; two or more independent malicious verdicts add
    10. A "known benign service" answer (GreyNoise RIOT, your own Defender allow indicator) caps the
    score at 20 unless some feed calls the indicator malicious.
    """
    opinions = [r for r in results if r.status in ("hit", "clean") and r.score is not None]
    if not opinions:
        return "unknown", 0
    score = max(r.score or 0 for r in opinions)
    malicious = [r for r in opinions if r.verdict == "malicious"]
    harmless = [r for r in opinions if r.verdict == "harmless"]
    if len(malicious) >= 2:
        score = min(100, score + 10)
    if not malicious and any(r.details.get("benign_service") for r in harmless):
        score = min(score, 20)
    if score >= MALICIOUS_AT:
        return "malicious", score
    if score >= SUSPICIOUS_AT:
        return "suspicious", score
    if harmless:
        return "harmless", score
    return "unknown", score
