"""Fan out every indicator to every feed that supports it, in parallel, within each feed's rate limit."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterable

from soc_toolkit.ioc_enrich.cache import Cache
from soc_toolkit.ioc_enrich.extract import Indicator, is_non_routable
from soc_toolkit.ioc_enrich.models import Enrichment, ProviderResult, aggregate
from soc_toolkit.ioc_enrich.providers import Provider


@dataclass
class Policy:
    include_private: bool = False
    allow_domains: set[str] = field(default_factory=set)   # known-good: reported, never looked up
    internal_domains: set[str] = field(default_factory=set)  # yours: never sent to external feeds

    def __post_init__(self) -> None:
        self.allow_domains = {d.lower().strip(".") for d in self.allow_domains if d}
        self.internal_domains = {d.lower().strip(".") for d in self.internal_domains if d}


def _matches(host: str, domains: set[str]) -> bool:
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def _skip_reason(ind: Indicator, policy: Policy) -> str:
    if ind.is_ip and not policy.include_private and is_non_routable(ind.value):
        return "skipped: private or non-routable address"
    if ind.type in ("domain", "url"):
        host = ind.host()
        if host and _matches(host, policy.allow_domains):
            return "skipped: allowlisted domain"
        if host and is_non_routable(host) and not policy.include_private:
            return "skipped: private or non-routable address"
    return ""


def enrich(indicators: Iterable[Indicator], providers: list[Provider], *, policy: Policy | None = None,
           cache: Cache | None = None, workers: int = 8,
           progress: Callable[[int, int], None] | None = None) -> list[Enrichment]:
    policy = policy or Policy()
    inds = list(dict.fromkeys(indicators))
    notes = {ind: _skip_reason(ind, policy) for ind in inds}
    results: dict[Indicator, list[ProviderResult]] = {ind: [] for ind in inds}

    def internal(ind: Indicator) -> bool:
        return ind.type in ("domain", "url") and _matches(ind.host(), policy.internal_domains)

    work: list[tuple[Provider, Indicator]] = []
    batches: dict[Provider, list[Indicator]] = {}
    for ind in inds:
        if notes[ind]:
            continue
        for provider in providers:
            if not provider.supports(ind):
                continue
            if internal(ind) and provider.name not in ("sentinel_ti", "defender_indicators"):
                continue  # your own domains never leave your tenant
            cached = cache.get(provider.name, ind) if cache else None
            if cached:
                results[ind].append(cached)
            elif provider.batch:
                batches.setdefault(provider, []).append(ind)
            else:
                work.append((provider, ind))

    total = len(work) + len(batches)
    done = 0

    def run_one(provider: Provider, ind: Indicator) -> list[tuple[Indicator, ProviderResult]]:
        try:
            return [(ind, provider.lookup(ind))]
        except Exception as exc:  # one failing feed must never stop the run
            return [(ind, ProviderResult(provider.name, "error", summary=str(exc)[:200]))]

    def run_batch(provider: Provider, group: list[Indicator]) -> list[tuple[Indicator, ProviderResult]]:
        try:
            answers = provider.lookup_many(group)
            return [(ind, answers.get(ind) or provider.not_found()) for ind in group]
        except Exception as exc:
            return [(ind, ProviderResult(provider.name, "error", summary=str(exc)[:200])) for ind in group]

    if total:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = [pool.submit(run_one, p, i) for p, i in work]
            futures += [pool.submit(run_batch, p, g) for p, g in batches.items()]
            for future in as_completed(futures):
                for ind, result in future.result():
                    results[ind].append(result)
                    if cache:
                        cache.put(ind, result)
                done += 1
                if progress:
                    progress(done, total)

    order = {p.name: n for n, p in enumerate(providers)}
    out: list[Enrichment] = []
    for ind in inds:
        rows = sorted(results[ind], key=lambda r: order.get(r.provider, 99))
        verdict, score = aggregate(rows)
        note = notes[ind] or ("internal domain: checked only against your own Microsoft TI" if internal(ind) else "")
        if not notes[ind] and not rows:
            note = note or "no configured feed supports this indicator type"
        out.append(Enrichment(ind, verdict, score, rows, note))
    return out
