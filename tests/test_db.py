"""Database behaviour the rest of the system assumes."""
from datetime import datetime, timedelta

import pytest
import sqlite3

from telemail.db import Database
from telemail.models import Email, SenderSignals, TriageResult


@pytest.fixture
def db():
    d = Database(":memory:")
    yield d
    d.close()


def make_email(mid="m1", thread="t1", domain="uni.edu", **kw) -> Email:
    return Email(message_id=mid, thread_id=thread,
                 sender_email=f"someone@{domain}", sender_name="Someone",
                 sender_domain=domain, subject="Subject line",
                 snippet="A snippet.", received_at=datetime(2026, 9, 1, 10, 0),
                 **kw)


# --------------------------------------------------------------- idempotency

def test_insert_reports_new_then_duplicate(db):
    assert db.insert_email(make_email()) is True
    assert db.insert_email(make_email()) is False
    assert db.count_emails() == 1


def test_reingesting_500_messages_twice_yields_no_duplicates(db):
    """The workflow_1 gate, in miniature: sync must be replay-safe."""
    batch = [make_email(mid=f"m{i}", thread=f"t{i % 50}") for i in range(500)]
    for e in batch:
        db.insert_email(e)
    for e in batch:
        db.insert_email(e)
    assert db.count_emails() == 500


def test_round_trip_preserves_signals(db):
    e = make_email(signals=SenderSignals(spf="fail", dkim="fail", dmarc="fail",
                                         auth_source="mx.google.com",
                                         display_name_mismatch=True,
                                         first_contact=False,
                                         sender_message_count=12))
    db.insert_email(e)
    got = db.get_email("m1")
    assert got.signals.dmarc == "fail"
    assert got.signals.auth_source == "mx.google.com"
    assert got.signals.display_name_mismatch is True
    assert got.signals.sender_message_count == 12
    assert got.received_at == e.received_at


# ------------------------------------------------------------ sender history

def test_sender_history_excludes_the_current_message(db):
    """first_contact must be computed against PRIOR history. Counting the
    message being processed would make every sender look familiar."""
    db.insert_email(make_email(mid="m1"))
    assert db.sender_history("uni.edu", exclude="m1") == 0
    db.insert_email(make_email(mid="m2"))
    assert db.sender_history("uni.edu", exclude="m2") == 1


def test_sender_history_is_per_domain(db):
    db.insert_email(make_email(mid="m1", domain="uni.edu"))
    db.insert_email(make_email(mid="m2", domain="bank.com"))
    assert db.sender_history("uni.edu") == 1
    assert db.sender_history("nowhere.com") == 0


# ------------------------------------------------------------------- broker

def test_thread_exists_rejects_hallucinated_ids(db):
    db.insert_email(make_email(thread="real-thread"))
    assert db.thread_exists("real-thread") is True
    assert db.thread_exists("thread-the-model-invented") is False


# -------------------------------------------------------------------- audit

def test_audit_is_append_only_no_update(db):
    db.log(actor="broker", event="rejected", payload={"op": "send_email"},
           reason="not on allowlist")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.con.execute("UPDATE audit SET reason = 'nothing happened'")


def test_audit_is_append_only_no_delete(db):
    db.log(actor="planner", event="proposed", payload={"op": "delete"})
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.con.execute("DELETE FROM audit")


def test_audit_preserves_order_and_payload(db):
    db.log(actor="planner", event="proposed", payload={"op": "search", "q": "x"})
    db.log(actor="broker", event="rejected", payload={"op": "search"},
           reason="bad operator")
    rows = db.audit_entries()
    assert [r["event"] for r in rows] == ["proposed", "rejected"]
    assert rows[0]["payload"]["q"] == "x"
    assert rows[1]["reason"] == "bad operator"


def test_audit_filter_by_event(db):
    db.log(actor="broker", event="accepted", payload={})
    db.log(actor="broker", event="rejected", payload={})
    db.log(actor="broker", event="rejected", payload={})
    assert len(db.audit_entries(event="rejected")) == 2


# ------------------------------------------------------------------- triage

def test_triage_upsert_and_source_counts(db):
    db.insert_email(make_email(mid="m1"))
    db.insert_email(make_email(mid="m2"))
    db.upsert_triage(TriageResult(message_id="m1", category="promotional",
                                  urgency=1, requires_action=False,
                                  reason="bulk", confidence=0.9,
                                  source="prefilter"))
    db.upsert_triage(TriageResult(message_id="m2", category="academic",
                                  urgency=4, requires_action=True,
                                  reason="deadline", confidence=0.8,
                                  source="model"))
    assert db.source_counts() == {"prefilter": 1, "model": 1}

    # re-triage the same message: overwrite, do not duplicate
    db.upsert_triage(TriageResult(message_id="m1", category="suspicious",
                                  urgency=5, requires_action=True,
                                  reason="dmarc fail", confidence=0.95,
                                  source="model"))
    assert db.source_counts() == {"model": 2}
    assert db.get_triage("m1").category == "suspicious"


def test_triage_rejects_unknown_message(db):
    """Foreign key stops a verdict existing for a message we never stored."""
    with pytest.raises(sqlite3.IntegrityError):
        db.upsert_triage(TriageResult(message_id="ghost", category="other",
                                      urgency=1, requires_action=False,
                                      reason="", confidence=0.5,
                                      source="model"))


# -------------------------------------------------------------------- state

def test_watermark_round_trip(db):
    assert db.get_state("history_id", "0") == "0"
    db.set_state("history_id", "123456")
    db.set_state("history_id", "123457")
    assert db.get_state("history_id") == "123457"


# ------------------------------------------------ used from a worker thread

def test_database_is_usable_from_a_worker_thread():
    """/sync runs Gmail and triage via asyncio.to_thread, so the connection made
    on the main thread must work there too."""
    import asyncio
    d = Database(":memory:")
    d.insert_email(make_email(mid="m1"))
    assert asyncio.run(asyncio.to_thread(d.count_emails)) == 1
    d.close()
