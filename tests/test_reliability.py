"""Reliability collection and the results renderer."""
from datetime import datetime

import pytest

from eval.reliability import collect, render
from telemail.db import Database
from telemail.models import Email, SenderSignals, TriageResult


@pytest.fixture
def db():
    d = Database(":memory:")
    for i in range(3):
        d.insert_email(Email(message_id=f"m{i}", thread_id="t1",
                             sender_email="a@uni.edu", sender_domain="uni.edu",
                             subject="s", snippet="x",
                             received_at=datetime(2026, 9, 1),
                             signals=SenderSignals()))
    yield d
    d.close()


def verdict(mid, source):
    return TriageResult(message_id=mid, category="academic", urgency=3,
                        requires_action=False, reason="r", confidence=0.8,
                        source=source)


def test_schema_validity_is_one_minus_fallback_rate(db):
    db.upsert_triage(verdict("m0", "model"))
    db.upsert_triage(verdict("m1", "model"))
    db.upsert_triage(verdict("m2", "fallback"))
    r = collect(db)
    assert r["fallback_rate"] == pytest.approx(1 / 3, abs=1e-3)
    assert r["schema_validity"] == pytest.approx(2 / 3, abs=1e-3)


def test_prefilter_share_is_over_all_ingested_mail(db):
    """Deferred mail waiting for a model must not inflate the share."""
    db.upsert_triage(verdict("m0", "prefilter"))
    r = collect(db)
    assert r["prefilter_share"] == pytest.approx(1 / 3, abs=1e-3)
    assert r["awaiting_model"] == 2


def test_schema_validity_is_not_reported_over_zero_model_calls(db):
    db.upsert_triage(verdict("m0", "prefilter"))
    assert collect(db)["schema_validity"] is None


def test_rejections_are_grouped_by_reason(db):
    db.log(actor="broker", event="rejected", payload={}, reason="failed validation: 2")
    db.log(actor="broker", event="rejected", payload={}, reason="failed validation: 1")
    db.log(actor="broker", event="rejected", payload={}, reason="unknown thread_id")
    r = collect(db)
    assert r["broker"]["rejected"] == 3
    assert r["broker"]["by_reason"]["failed validation"] == 2


def test_unauthorised_updates_are_counted(db):
    db.log(actor="bot", event="unauthorised_update", payload={"chat_id": 999})
    assert collect(db)["unauthorised_updates"] == 1


def test_duplicates_are_zero_by_construction(db):
    """The primary key makes this structurally impossible; report it anyway."""
    assert collect(db)["duplicates"] == 0


def test_empty_database_does_not_divide_by_zero():
    d = Database(":memory:")
    r = collect(d)
    assert r["triaged"] == 0 and r["schema_validity"] is None
    d.close()


def test_render_includes_the_target_band(db):
    out = render(collect(db))
    assert "target 40-60%" in out and "must be 0" in out
