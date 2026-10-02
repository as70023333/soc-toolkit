"""SQLite cache so repeated runs do not burn feed quotas (e.g. VirusTotal's 500/day)."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from soc_toolkit.ioc_enrich.extract import Indicator
from soc_toolkit.ioc_enrich.models import ProviderResult

CACHEABLE = ("hit", "clean", "not_found")


def default_cache_path() -> Path:
    override = os.environ.get("IOC_CACHE_PATH")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "soc-toolkit" / "ioc-cache.sqlite3"


class Cache:
    """Results are kept for ``ttl_hours``; "not found" answers for a quarter of that, because a
    fresh indicator can appear in a feed within hours. Errors are never cached."""

    def __init__(self, path: Path, ttl_hours: float = 24.0, clock=time.time) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.ttl = ttl_hours * 3600
        self._clock = clock
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS results (provider TEXT, type TEXT, value TEXT, "
                         "stored REAL, payload TEXT, PRIMARY KEY (provider, type, value))")
        self._db.commit()
        try:
            os.chmod(path, 0o600)  # the cache lists the indicators you investigated
        except OSError:
            pass

    def get(self, provider: str, ind: Indicator) -> ProviderResult | None:
        with self._lock:
            row = self._db.execute("SELECT stored, payload FROM results WHERE provider=? AND type=? AND value=?",
                                   (provider, ind.type, ind.value)).fetchone()
        if not row:
            return None
        stored, payload = row
        result = ProviderResult.from_dict(json.loads(payload))
        ttl = self.ttl / 4 if result.status == "not_found" else self.ttl
        if self._clock() - stored > ttl:
            return None
        result.cached = True
        return result

    def put(self, ind: Indicator, result: ProviderResult) -> None:
        if result.status not in CACHEABLE:
            return
        payload = json.dumps({**result.to_dict(), "cached": False})
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?, ?)",
                             (result.provider, ind.type, ind.value, self._clock(), payload))
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()
