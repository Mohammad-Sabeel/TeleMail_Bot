"""Label store and the labelling view."""
from datetime import datetime

import pytest

from scripts.label import RUBRIC_VERSION, progress, render
from telemail.db import Database
from telemail.models import Email, SenderSignals, TriageResult


def mail(mid="m1", thread="t1", day=1, **sig) -> Email:
    return Email(message_id=mid, thread_id=thread, sender_email="a@uni.edu",
                 sender_name="Someone", sender_domain="uni.edu",
                 subject="Subject", snippet="Body snippet",
                 received_at=datetime(2026, 9, day), is_direct=True,
                 signals=SenderSignals(**sig))


@pytest.fixture
def db():
    d = Database(":memory:")
    yield d
    d.close()


def test_label_round_trip(db):
    db.insert_email(mail())
    db.add_label("m1", True)
    assert db.label_count() == 1
    assert db.label_balance() == {"important": 1}


def test_relabelling_overwrites(db):
    db.insert_email(mail())
    db.add_label("m1", True)
    db.add_label("m1", False)
    assert db.label_count() == 1 and db.label_balance() == {"not_important": 1}


def test_unlabelled_excludes_what_is_done(db):
    db.insert_email(mail("m1"))
    db.insert_email(mail("m2"))
    db.add_label("m1", True)
    assert [e.message_id for e in db.unlabelled()] == ["m2"]


def test_unlabelled_is_oldest_first(db):
    """Newest-first would bias the sample toward whatever arrived today."""
    db.insert_email(mail("new", day=9))
    db.insert_email(mail("old", day=1))
    assert [e.message_id for e in db.unlabelled()] == ["old", "new"]


def test_labels_require_a_known_message(db):
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        db.add_label("ghost", True)


def test_dataset_carries_thread_id_for_grouped_splits(db):
    """Held-out splits must be by thread, not by message."""
    db.insert_email(mail("m1", thread="t1"))
    db.insert_email(mail("m2", thread="t1"))
    db.add_label("m1", True)
    db.add_label("m2", False)
    ds = db.labelled_dataset()
    assert {d["thread_id"] for d in ds} == {"t1"}
    assert all(d["rubric_version"] == RUBRIC_VERSION for d in ds)


# --------------------------------------------------------- the view itself

def test_view_shows_the_facts_needed_to_judge(db):
    out = render(mail(spf="pass", dkim="pass", dmarc="pass",
                      auth_source="mx.google.com"), 1, 20)
    assert "Someone" in out and "Subject" in out and "Body snippet" in out
    assert "spf=pass" in out and "direct recipient" in out


def test_view_marks_unverified_authentication(db):
    assert "(unverified)" in render(mail(), 1, 20)


def test_view_never_leaks_a_system_verdict(db):
    """Seeing the model's guess would contaminate the ground truth."""
    out = render(mail(), 1, 20).lower()
    for leak in ("urgency", "category", "confidence", "suspicious",
                 "promotional", "prefilter", "model", "requires_action"):
        assert leak not in out, f"labelling view leaked '{leak}'"


def test_progress_reports_against_the_target(db):
    db.insert_email(mail())
    db.add_label("m1", True)
    out = progress(db)
    assert "1/150" in out and "important: 1" in out
