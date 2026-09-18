from datetime import datetime, timedelta, timezone

import pytest

from telemail.models import Email, SenderSignals
from telemail.threatintel import (CACHE_TTL_DAYS, DomainReport, VirusTotal,
                                  domains_from, vt_evidence)
from telemail.triage.assess import Level, assess_email

NOW = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)


def _email(**kw) -> Email:
    base = dict(message_id="m1", thread_id="t1", sender_email="a@b.c", sender_name="A",
                sender_domain="b.c", subject="Hi", snippet="text",
                received_at=NOW, signals=SenderSignals())
    return Email(**{**base, **kw})


def _read(*hrefs):
    return {"body": "", "attachments": [], "links": [{"href": h, "text": ""} for h in hrefs]}


# ------------------------------------------------------------------ domains

def test_collects_link_domains_without_duplicates_or_www():
    assert domains_from(_read("http://bit.ly/a", "https://www.bit.ly/b",
                              "https://evil.test/x")) == ["bit.ly", "evil.test"]


def test_ignores_unparseable_and_non_http_links():
    assert domains_from(_read("mailto:a@b.c", "javascript:void(0)", "", "http://")) == []


def test_never_sends_the_senders_own_domain_or_common_hosts():
    assert "google.com" not in domains_from(_read("https://google.com/x"))


# ------------------------------------------------------------------ evidence

def test_several_vendors_flagging_is_a_threat():
    level, evidence = vt_evidence([DomainReport("evil.test", malicious=5, checked_at=NOW)])
    assert level is Level.THREAT
    assert evidence == ["VirusTotal: 5 vendors flag evil.test"]


def test_two_or_three_vendors_is_only_caution():
    level, evidence = vt_evidence([DomainReport("odd.test", malicious=2, checked_at=NOW)])
    assert level is Level.CAUTION
    assert "2 vendors flag odd.test" in evidence[0]


def test_a_single_vendor_is_noise_and_adds_nothing():
    """Measured on real mail: substack.com scores 1, google.com 2."""
    assert vt_evidence([DomainReport("substack.com", 1, NOW)]) == (Level.NONE, [])


def test_clean_domains_add_nothing():
    assert vt_evidence([DomainReport("ok.test", malicious=0, checked_at=NOW)]) == (Level.NONE, [])


# ------------------------------------------------------------------ client

class _Response:
    def __init__(self, status, payload=None):
        self.status_code, self._payload = status, payload or {}

    def json(self):
        return self._payload


def _stats(malicious):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious,
                                                            "suspicious": 0}}}}


def test_lookup_caches_and_does_not_call_twice(tmp_path):
    calls = []

    def get(url, headers=None, timeout=None):
        calls.append(url)
        return _Response(200, _stats(2))

    vt = VirusTotal("key", cache_path=tmp_path / "vt.json", get=get, now=lambda: NOW)
    assert vt.lookup("evil.test").malicious == 2
    assert vt.lookup("evil.test").malicious == 2
    assert len(calls) == 1


def test_expired_cache_entries_are_refetched(tmp_path):
    calls = []

    def get(url, headers=None, timeout=None):
        calls.append(url)
        return _Response(200, _stats(0))

    old = NOW - timedelta(days=CACHE_TTL_DAYS + 1)
    vt = VirusTotal("key", cache_path=tmp_path / "vt.json", get=get, now=lambda: old,
                    min_interval=0)
    vt.lookup("ok.test")
    vt.now = lambda: NOW
    vt.lookup("ok.test")
    assert len(calls) == 2


def test_unknown_domain_is_not_an_error(tmp_path):
    vt = VirusTotal("key", cache_path=tmp_path / "vt.json",
                    get=lambda *a, **k: _Response(404), now=lambda: NOW)
    assert vt.lookup("new.test") is None


def test_network_failure_is_swallowed(tmp_path):
    def boom(*a, **k):
        raise OSError("no network")

    vt = VirusTotal("key", cache_path=tmp_path / "vt.json", get=boom, now=lambda: NOW)
    assert vt.lookup("evil.test") is None


def test_without_a_key_nothing_is_sent(tmp_path):
    def boom(*a, **k):
        raise AssertionError("must not call VirusTotal without a key")

    vt = VirusTotal("", cache_path=tmp_path / "vt.json", get=boom, now=lambda: NOW)
    assert vt.enabled is False
    assert vt.reports(["evil.test"]) == []


def test_lookups_are_capped_per_sync(tmp_path):
    calls = []

    def get(url, headers=None, timeout=None):
        calls.append(url)
        return _Response(200, _stats(0))

    vt = VirusTotal("key", cache_path=tmp_path / "vt.json", get=get, now=lambda: NOW,
                    max_lookups=2, min_interval=0)
    vt.reports([f"d{i}.test" for i in range(5)])
    assert len(calls) == 2


# ------------------------------------------------------------------ assess

def test_verdict_uses_virustotal_evidence():
    verdict = assess_email(_email(), None, _read("http://evil.test/x"), planner=None,
                           vt_reports=[DomainReport("evil.test", 6, NOW)])
    assert verdict.level is Level.THREAT
    assert any("VirusTotal" in e for e in verdict.evidence)


# ------------------------------------------------------------- quota guards

def _vt(tmp_path, calls, now=lambda: NOW, **kw):
    def get(url, headers=None, timeout=None):
        calls.append(url)
        return _Response(200, _stats(0))
    sleeps = kw.pop("sleeps", [])
    return VirusTotal("key", cache_path=tmp_path / "vt.json", get=get, now=now,
                      sleep=sleeps.append, **kw)


def test_waits_between_calls_to_respect_four_per_minute(tmp_path):
    calls, sleeps = [], []
    clock = [NOW]
    vt = _vt(tmp_path, calls, now=lambda: clock[0], sleeps=sleeps)
    vt.lookup("a.test")
    vt.lookup("b.test")
    assert sleeps and sleeps[0] == pytest.approx(vt.min_interval, abs=0.5)


def test_no_wait_when_enough_time_has_passed(tmp_path):
    calls, sleeps = [], []
    clock = [NOW]
    vt = _vt(tmp_path, calls, now=lambda: clock[0], sleeps=sleeps)
    vt.lookup("a.test")
    clock[0] = NOW + timedelta(seconds=60)
    vt.lookup("b.test")
    assert sleeps == []


def test_daily_quota_stops_further_lookups(tmp_path):
    calls = []
    vt = _vt(tmp_path, calls, daily_cap=3)
    for i in range(5):
        vt.lookup(f"d{i}.test")
    assert len(calls) == 3


def test_daily_quota_resets_the_next_day(tmp_path):
    calls = []
    clock = [NOW]
    vt = _vt(tmp_path, calls, now=lambda: clock[0], daily_cap=2)
    vt.lookup("a.test")
    vt.lookup("b.test")
    vt.lookup("c.test")
    clock[0] = NOW + timedelta(days=1)
    vt.lookup("d.test")
    assert len(calls) == 3


def test_cached_answers_do_not_count_against_the_quota(tmp_path):
    calls = []
    vt = _vt(tmp_path, calls, daily_cap=2)
    vt.lookup("a.test")
    vt.lookup("a.test")
    vt.lookup("b.test")
    vt.lookup("c.test")
    assert len(calls) == 2
