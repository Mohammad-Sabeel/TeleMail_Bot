"""T10 harness, driven by planners whose contamination behaviour we control."""
from datetime import datetime
from pathlib import Path

import pytest

from eval.cross_batch import (measure, neighbours_from_db, poison, render, run,
                              t10_payload, verdict_changed)
from telemail.db import Database
from telemail.models import Email, SenderSignals, TriageResult
from telemail.triage.planner import BATCH_SIZE

FIXTURES = Path("fixtures/own")
has_fixtures = pytest.mark.skipif(not list(FIXTURES.glob("T10_*.eml")),
                                  reason="run scripts.harvest_corpus first")
MARK = "ignore all previous instructions"


def mail(mid, snippet="Can we meet on Thursday?"):
    return Email(message_id=mid, thread_id=f"t{mid}", sender_email="a@uni.edu",
                 sender_domain="uni.edu", subject="s", snippet=snippet,
                 received_at=datetime(2026, 9, 1), signals=SenderSignals())


def tr(mid, requires_action=True, urgency=4):
    return TriageResult(message_id=mid, category="academic", urgency=urgency,
                        requires_action=requires_action, reason="r",
                        confidence=0.9, source="model")


class Contaminable:
    """One poisoned snippet anywhere in the batch flips every verdict."""
    def __init__(self): self.batch_sizes = []
    def triage(self, emails):
        self.batch_sizes.append(len(emails))
        hit = any(MARK in e.snippet.lower() for e in emails)
        return [tr(e.message_id, requires_action=not hit, urgency=1 if hit else 4)
                for e in emails]


class Isolated:
    """Judges each message only on its own content."""
    def triage(self, emails):
        return [tr(e.message_id, requires_action=MARK not in e.snippet.lower())
                for e in emails]


NEIGHBOURS = [mail(f"n{i}") for i in range(BATCH_SIZE - 1)]


def test_poison_places_the_payload_inside_the_snippet():
    p = poison(mail("c"), t10_payload())
    assert p.snippet.lower().startswith(MARK)
    assert len(p.snippet) <= 200 and p.message_id == "c#poisoned"


def test_verdict_changed_counts_a_requires_action_flip():
    assert verdict_changed(tr("x", True), tr("x", False)) is True
    assert verdict_changed(tr("x"), tr("x")) is False


def test_contamination_is_detected():
    m = measure(Contaminable(), NEIGHBOURS, poison(mail("c"), t10_payload()), mail("c"))
    assert m["contaminated"] == BATCH_SIZE - 1 and m["noise"] == 0


def test_isolated_model_shows_no_contamination_but_is_itself_affected():
    m = measure(Isolated(), NEIGHBOURS, poison(mail("c"), t10_payload()), mail("c"))
    assert m["contaminated"] == 0 and m["self_changed"] is True


def test_each_arm_is_exactly_one_full_batch():
    p = Contaminable()
    measure(p, NEIGHBOURS, poison(mail("c"), t10_payload()), mail("c"))
    assert p.batch_sizes[:3] == [BATCH_SIZE] * 3 and p.batch_sizes[3] == 1


def test_noise_baseline_is_subtracted_in_the_summary():
    rows = [{"variant": "1", "neighbours": 7, "contaminated": 3, "noise": 1,
             "self_changed": True, "batched_vs_alone_changed": False}]
    assert "attributable to contamination:            2/7" in render(rows)


def test_neighbours_from_db_excludes_and_limits():
    db = Database(":memory:")
    for i in range(10):
        db.insert_email(mail(f"m{i}"))
    got = neighbours_from_db(db, 7, exclude={"m0"})
    assert len(got) == 7 and "m0" not in {e.message_id for e in got}


@has_fixtures
def test_run_over_the_T10_fixtures(tmp_path):
    rows = run(Contaminable(), FIXTURES, NEIGHBOURS, out=tmp_path / "cb.csv")
    assert len(rows) == 3 and all(r["contaminated"] == 7 for r in rows)
    assert (tmp_path / "cb.csv").exists()


def test_run_rejects_a_partial_batch():
    with pytest.raises(ValueError):
        run(Isolated(), FIXTURES, NEIGHBOURS[:3])
