"""URL reputation from VirusTotal — a general signal, unlike a hand-written list.

Untrusted input, deterministic output: link domains go out, vendor counts come
back, and the counts become evidence in the rules layer. No email text, no full
URL, no sender and no address ever leaves.

Privacy cost, stated in the limitations: the domains that appear in your mail
are shared with a third party. Mitigated by sending domains only (never paths or
query strings, which can carry identifiers), caching for a week, skipping the
common hosts below, and capping lookups per sync.

Disabled entirely when VIRUSTOTAL_API_KEY is unset — then nothing is sent.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from telemail.triage.assess import Level

API = "https://www.virustotal.com/api/v3/domains/"
CACHE_TTL_DAYS = 7
MAX_LOOKUPS = 8             # per sync; the rest of a busy sync waits for the next one
MIN_INTERVAL = 15.0         # seconds between calls: the free tier allows 4/minute
DAILY_CAP = 400             # free tier gives 500/day; leave headroom for manual checks
# Calibrated on 12 domains from real mail (2026-09-18): legitimate senders score 0,
# substack.com 1 and google.com 2, so a single vendor is noise, not a signal.
THREAT_VENDORS = 4          # this many flagging it is a threat
CAUTION_VENDORS = 2         # two or three is worth a look

# Hosts where a lookup tells us nothing and only leaks that we saw them.
COMMON_HOSTS = {"google.com", "gmail.com", "youtube.com", "microsoft.com", "apple.com",
                "amazon.com", "amazon.in", "facebook.com", "instagram.com", "x.com",
                "twitter.com", "linkedin.com", "github.com", "telegram.org", "paypal.com"}


@dataclass
class DomainReport:
    domain: str
    malicious: int
    checked_at: datetime


def domains_from(read: dict | None) -> list[str]:
    """Link domains worth looking up, de-duplicated and in order of appearance."""
    out: dict[str, None] = {}
    for link in (read or {}).get("links", []):
        href = str(link.get("href") or "")
        if not href.lower().startswith(("http://", "https://")):
            continue
        try:
            host = (urlparse(href).hostname or "").lower().removeprefix("www.")
        except ValueError:
            continue
        registrable = ".".join(host.split(".")[-2:]) if host else ""
        if host and registrable not in COMMON_HOSTS:
            out[host] = None
    return list(out)


def vt_evidence(reports: list[DomainReport]) -> tuple[Level, list[str]]:
    level, evidence = Level.NONE, []
    for r in sorted(reports, key=lambda r: -r.malicious):
        if r.malicious >= THREAT_VENDORS:
            level = Level.THREAT
        elif r.malicious >= CAUTION_VENDORS:
            level = max(level, Level.CAUTION)
        else:
            continue
        evidence.append(f"VirusTotal: {r.malicious} vendors flag {r.domain}")
    return level, evidence


class VirusTotal:
    """Cached client. Every failure — no key, no network, unknown domain, rate
    limit — returns None, because reputation is evidence and never a gate."""

    def __init__(self, api_key: str, cache_path=Path("data/vt_cache.json"),
                 get=None, now=None, max_lookups: int = MAX_LOOKUPS,
                 min_interval: float = MIN_INTERVAL, daily_cap: int = DAILY_CAP,
                 sleep=None):
        self.api_key = api_key or ""
        self.cache_path = Path(cache_path)
        self.max_lookups = max_lookups
        self.min_interval = min_interval
        self.daily_cap = daily_cap
        self.now = now or (lambda: datetime.now().astimezone())
        self._get = get
        self._sleep = sleep
        self._last_call: datetime | None = None
        self._cache = self._load()

    # ------------------------------------------------------------- quota

    def _usage(self) -> int:
        """Calls made today, kept in the cache file so a restart does not reset it."""
        used = self._cache.get("__usage__", {})
        return int(used.get(self.now().date().isoformat(), 0))

    def _count_call(self) -> None:
        day = self.now().date().isoformat()
        used = self._cache.setdefault("__usage__", {})
        used[day] = int(used.get(day, 0)) + 1
        for old in [d for d in used if d != day]:
            del used[old]

    def _wait_turn(self) -> None:
        if self._last_call is None:
            return
        waited = (self.now() - self._last_call).total_seconds()
        if waited < self.min_interval:
            sleep = self._sleep
            if sleep is None:
                import time
                sleep = time.sleep
            sleep(self.min_interval - waited)

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _load(self) -> dict:
        try:
            return json.loads(self.cache_path.read_text())
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache))
        except OSError:
            pass

    def _fresh(self, domain: str) -> DomainReport | None:
        entry = self._cache.get(domain) if domain != "__usage__" else None
        if not entry:
            return None
        checked = datetime.fromisoformat(entry["checked_at"])
        if self.now() - checked > timedelta(days=CACHE_TTL_DAYS):
            return None
        return DomainReport(domain, int(entry["malicious"]), checked)

    def lookup(self, domain: str) -> DomainReport | None:
        if not self.enabled:
            return None
        cached = self._fresh(domain)
        if cached is not None:
            return cached
        if self._usage() >= self.daily_cap:
            return None
        self._wait_turn()
        get = self._get
        if get is None:
            import httpx
            get = httpx.get
        try:
            response = get(API + domain, headers={"x-apikey": self.api_key}, timeout=10)
            if response.status_code != 200:
                return None
            stats = (response.json().get("data", {}).get("attributes", {})
                     .get("last_analysis_stats", {}))
            malicious = int(stats.get("malicious", 0))
        except Exception:
            return None
        checked = self.now()
        self._last_call = checked
        self._count_call()
        self._cache[domain] = {"malicious": malicious, "checked_at": checked.isoformat()}
        self._save()
        return DomainReport(domain, malicious, checked)

    def reports(self, domains: list[str]) -> list[DomainReport]:
        if not self.enabled:
            return []
        out = []
        for domain in domains[:self.max_lookups]:
            report = self.lookup(domain)
            if report is not None:
                out.append(report)
        return out
