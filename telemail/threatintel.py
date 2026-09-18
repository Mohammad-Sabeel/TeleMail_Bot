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
MAX_LOOKUPS = 20            # free tier allows 4/minute; one sync stays well inside
THREAT_VENDORS = 2          # this many vendors flagging is a threat, one is caution

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
        elif r.malicious == 1:
            level = max(level, Level.CAUTION)
        else:
            continue
        verb = "vendor flags" if r.malicious == 1 else "vendors flag"
        evidence.append(f"VirusTotal: {r.malicious} {verb} {r.domain}")
    return level, evidence


class VirusTotal:
    """Cached client. Every failure — no key, no network, unknown domain, rate
    limit — returns None, because reputation is evidence and never a gate."""

    def __init__(self, api_key: str, cache_path=Path("data/vt_cache.json"),
                 get=None, now=None, max_lookups: int = MAX_LOOKUPS):
        self.api_key = api_key or ""
        self.cache_path = Path(cache_path)
        self.max_lookups = max_lookups
        self.now = now or (lambda: datetime.now().astimezone())
        self._get = get
        self._cache = self._load()

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
        entry = self._cache.get(domain)
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
