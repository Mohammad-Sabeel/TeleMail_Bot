"""Sync correctness: the properties that let the process be killed at any point.

These are the six break-it-on-purpose tests the plan gates Phase 2 behind.
"""
import pytest

from telemail.db import Database
from telemail.gmail.adapter import WatermarkExpired
from telemail.sync import WATERMARK_KEY, SyncEngine


def msg(mid, subject="Subject", sender="a@uni.edu", thread=None):
    return {"id": mid, "threadId": thread or f"t{mid}", "snippet": "snip",
            "labelIds": ["INBOX"],
            "payload": {"headers": [
                {"name": "From", "value": f"Someone <{sender}>"},
                {"name": "To", "value": "you@uni.edu"},
                {"name": "Subject", "value": subject},
                {"name": "Date", "value": "Tue, 01 Sep 2026 10:00:00 +0000"},
                {"name": "Authentication-Results",
                 "value": "mx.google.com; spf=pass; dkim=pass; dmarc=pass"}]}}


class FakeAdapter:
    """Scripted Gmail. Counts calls and can be told to fail."""

    def __init__(self, messages=None, history_pages=None, history_id="100"):
        self.messages = {m["id"]: m for m in (messages or [])}
        self.history_pages = history_pages or []
        self.history_id = history_id
        self.expire_history = False
        self.fail_on: set[str] = set()
        self.fetches: list[str] = []
        self._page = 0

    def profile(self): return {"historyId": self.history_id}

    def list_recent(self, max_results=100, query=""):
        return {"messages": [{"id": m} for m in list(self.messages)[:max_results]]}

    def history(self, start_history_id, max_results=500, page_token=None):
        if self.expire_history:
            raise WatermarkExpired(start_history_id)
        if self._page >= len(self.history_pages):
            return {"historyId": self.history_id}
        page = self.history_pages[self._page]
        self._page += 1
        return page

    def fetch_metadata(self, message_id):
        self.fetches.append(message_id)
        if message_id in self.fail_on:
            raise ConnectionError("network blip")
        return self.messages[message_id]


def engine(adapter, db=None):
    return SyncEngine(db or Database(":memory:"), adapter, own_address="you@uni.edu")


# ---------------------------------------------------------------- bootstrap

def test_bootstrap_ingests_and_sets_watermark():
    e = engine(FakeAdapter([msg("m1"), msg("m2")], history_id="500"))
    s = e.bootstrap()
    assert (s.inserted, s.duplicates) == (2, 0)
    assert e.db.get_state(WATERMARK_KEY) == "500"


def test_watermark_is_read_before_listing():
    """Read the historyId first, so mail arriving during the listing is
    replayed next poll rather than lost in the gap between two calls."""
    a = FakeAdapter([msg("m1")], history_id="500")
    order = []
    a.profile = lambda: (order.append("profile"), {"historyId": "500"})[1]
    orig = a.list_recent
    a.list_recent = lambda **kw: (order.append("list"), orig(**kw))[1]
    engine(a).bootstrap()
    assert order == ["profile", "list"]


# ------------------------------------------------------------- idempotency

def test_running_twice_inserts_nothing_the_second_time():
    a = FakeAdapter([msg(f"m{i}") for i in range(50)], history_id="500")
    e = engine(a)
    first = e.bootstrap()
    second = e.bootstrap()
    assert first.inserted == 50
    assert (second.inserted, second.duplicates) == (0, 50)
    assert e.db.count_emails() == 50


def test_poll_is_replay_safe():
    a = FakeAdapter([msg("m1")], history_id="101", history_pages=[
        {"history": [{"messagesAdded": [{"message": {"id": "m1"}}]}],
         "historyId": "101"}])
    e = engine(a)
    e.db.set_state(WATERMARK_KEY, "100")
    assert e.poll().inserted == 1
    a._page = 0                              # replay the same page
    assert e.poll().inserted == 0
    assert e.db.count_emails() == 1


def test_duplicate_ids_within_one_cycle_fetch_once():
    a = FakeAdapter([msg("m1")], history_id="101", history_pages=[
        {"history": [{"messagesAdded": [{"message": {"id": "m1"}},
                                        {"message": {"id": "m1"}}]}],
         "historyId": "101"}])
    e = engine(a)
    e.db.set_state(WATERMARK_KEY, "100")
    e.poll()
    assert a.fetches == ["m1"]


# ------------------------------------------------- replay, never skip

def test_watermark_holds_when_a_message_fails():
    """A partial failure must not advance the watermark, or the failed message
    is lost forever."""
    a = FakeAdapter([msg("m1"), msg("m2")], history_id="101", history_pages=[
        {"history": [{"messagesAdded": [{"message": {"id": "m1"}},
                                        {"message": {"id": "m2"}}]}],
         "historyId": "101"}])
    a.fail_on = {"m2"}
    e = engine(a)
    e.db.set_state(WATERMARK_KEY, "100")
    s = e.poll()
    assert s.errors and s.inserted == 1
    assert e.db.get_state(WATERMARK_KEY) == "100", "watermark advanced past a failure"


def test_recovery_after_a_failure_gets_the_missed_message():
    a = FakeAdapter([msg("m1"), msg("m2")], history_id="101", history_pages=[
        {"history": [{"messagesAdded": [{"message": {"id": "m1"}},
                                        {"message": {"id": "m2"}}]}],
         "historyId": "101"}])
    a.fail_on = {"m2"}
    e = engine(a)
    e.db.set_state(WATERMARK_KEY, "100")
    e.poll()
    a.fail_on.clear()
    a._page = 0
    s = e.poll()
    assert e.db.count_emails() == 2
    assert e.db.get_state(WATERMARK_KEY) == "101"


def test_clean_cycle_advances_the_watermark():
    a = FakeAdapter([msg("m1")], history_id="101", history_pages=[
        {"history": [{"messagesAdded": [{"message": {"id": "m1"}}]}],
         "historyId": "101"}])
    e = engine(a)
    e.db.set_state(WATERMARK_KEY, "100")
    assert e.poll().watermark == "101"


# -------------------------------------------------------------- self-healing

def test_expired_watermark_triggers_a_full_resync():
    a = FakeAdapter([msg("m1"), msg("m2")], history_id="900")
    a.expire_history = True
    e = engine(a)
    e.db.set_state(WATERMARK_KEY, "1")
    s = e.poll()
    assert s.resynced is True and s.inserted == 2
    assert e.db.get_state(WATERMARK_KEY) == "900"
    assert [x["event"] for x in e.db.audit_entries(event="resync")] == ["resync"]


def test_resync_does_not_duplicate_existing_mail():
    a = FakeAdapter([msg("m1"), msg("m2")], history_id="900")
    e = engine(a)
    e.bootstrap()
    a.expire_history = True
    e.db.set_state(WATERMARK_KEY, "1")
    s = e.poll()
    assert s.resynced and s.duplicates == 2 and e.db.count_emails() == 2


def test_no_watermark_falls_back_to_bootstrap():
    e = engine(FakeAdapter([msg("m1")], history_id="500"))
    assert e.poll().inserted == 1


# ---------------------------------------------------------------- paging

def test_history_pages_are_followed():
    a = FakeAdapter([msg("m1"), msg("m2")], history_id="102", history_pages=[
        {"history": [{"messagesAdded": [{"message": {"id": "m1"}}]}],
         "historyId": "101", "nextPageToken": "p2"},
        {"history": [{"messagesAdded": [{"message": {"id": "m2"}}]}],
         "historyId": "102"}])
    e = engine(a)
    e.db.set_state(WATERMARK_KEY, "100")
    s = e.poll()
    assert s.inserted == 2 and s.watermark == "102"


def test_empty_history_is_a_clean_no_op():
    a = FakeAdapter([], history_id="100")
    e = engine(a)
    e.db.set_state(WATERMARK_KEY, "100")
    s = e.poll()
    assert (s.inserted, s.fetched) == (0, 0) and s.ok


# ------------------------------------------------ signals survive the path

def test_signals_are_computed_during_sync():
    a = FakeAdapter([msg("m1")], history_id="500")
    e = engine(a)
    e.bootstrap()
    stored = e.db.get_email("m1")
    assert stored.signals.auth_source == "mx.google.com"
    assert stored.signals.spf == "pass"
    assert stored.is_direct is True


# ------------------------------------------------------------ inserted_ids

def test_inserted_ids_lists_only_new_messages():
    a = FakeAdapter([msg("m1"), msg("m2")], history_id="500")
    e = engine(a)
    first = e.bootstrap()
    assert first.inserted_ids == ["m1", "m2"]
    second = e.bootstrap()
    assert second.inserted_ids == [], "duplicates must not be reported as new"


def test_inserted_ids_from_a_poll():
    a = FakeAdapter([msg("m1"), msg("m2")], history_id="101", history_pages=[
        {"history": [{"messagesAdded": [{"message": {"id": "m2"}}]}],
         "historyId": "101"}])
    e = engine(a)
    e.db.set_state(WATERMARK_KEY, "100")
    assert e.poll().inserted_ids == ["m2"]


def test_failed_fetch_is_not_in_inserted_ids():
    a = FakeAdapter([msg("m1"), msg("m2")], history_id="500")
    a.fail_on = {"m2"}
    assert engine(a).bootstrap().inserted_ids == ["m1"]
