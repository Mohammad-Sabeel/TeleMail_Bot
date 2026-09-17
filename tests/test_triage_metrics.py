"""RQ1 harness. The split and the metrics are where results get inflated, so
both are pinned hard."""
from datetime import datetime

import pytest

from eval.metrics import Confusion, confusion, split_by_thread
from eval.triage_metrics import (evaluate, false_negatives, predicted_important,
                                 render)
from telemail.db import Database
from telemail.models import Email, SenderSignals, TriageResult
from telemail.triage.prefilter import PrefilterConfig


# ------------------------------------------------------------- the metrics

def test_confusion_counts():
    c = confusion([True, True, False, False], [True, False, True, False])
    assert (c.tp, c.fn, c.fp, c.tn) == (1, 1, 1, 1)
    assert c.precision == 0.5 and c.recall == 0.5 and c.f1 == 0.5
    assert c.n == 4 and c.accuracy == 0.5


def test_perfect_and_empty_cases():
    assert confusion([True, False], [True, False]).f1 == 1.0
    assert Confusion().f1 == 0.0 and Confusion().precision == 0.0


def test_length_mismatch_raises():
    with pytest.raises(ValueError):
        confusion([True], [True, False])


def test_recall_ignores_true_negatives():
    """Recall must not be inflated by a large not-important majority."""
    a = confusion([True] * 2 + [False] * 2, [True, False, False, False])
    b = confusion([True] * 2 + [False] * 98, [True, False] + [False] * 98)
    assert a.recall == b.recall == 0.5


# ---------------------------------------------------------------- the split

def rows(n_threads=8, per_thread=2):
    return [{"message_id": f"m{t}_{i}", "thread_id": f"t{t}", "important": i == 0}
            for t in range(n_threads) for i in range(per_thread)]


def test_split_never_divides_a_thread():
    """The leak that silently inflates email classification results."""
    train, test = split_by_thread(rows(20, 3), seed=1)
    assert {r["thread_id"] for r in train} & {r["thread_id"] for r in test} == set()


def test_split_is_deterministic_for_a_seed():
    a, _ = split_by_thread(rows(), seed=7)
    b, _ = split_by_thread(rows(), seed=7)
    assert [r["message_id"] for r in a] == [r["message_id"] for r in b]


def test_split_roughly_honours_the_fraction():
    train, test = split_by_thread(rows(40, 2), test_fraction=0.25, seed=3)
    assert 0.15 <= len(test) / (len(train) + len(test)) <= 0.40


def test_split_loses_nothing():
    all_rows = rows(12, 2)
    train, test = split_by_thread(all_rows, seed=5)
    assert len(train) + len(test) == len(all_rows)
    assert {r["message_id"] for r in train + test} == \
           {r["message_id"] for r in all_rows}


# ------------------------------------------------------------- predictions

def verdict(urgency, source="model"):
    return TriageResult(message_id="m", category="academic", urgency=urgency,
                        requires_action=True, reason="r", confidence=0.9,
                        source=source)


def test_missing_verdict_predicts_not_important():
    """A system that declined to decide has not said 'important'."""
    assert predicted_important(None, 4) is False


@pytest.mark.parametrize("urgency,thr,expected", [
    (5, 4, True), (4, 4, True), (3, 4, False), (3, 3, True)])
def test_threshold_applies(urgency, thr, expected):
    assert predicted_important(verdict(urgency), thr) is expected


# ------------------------------------------------------ the three conditions

def mail(mid, thread, subject="Lunch", unsub=False) -> Email:
    return Email(message_id=mid, thread_id=thread, sender_email="a@example.com",
                 sender_domain="example.com", subject=subject, snippet="x",
                 received_at=datetime(2026, 9, 1), is_direct=True,
                 has_list_unsubscribe=unsub, signals=SenderSignals())


@pytest.fixture
def env():
    db = Database(":memory:")
    db.insert_email(mail("bulk", "t1", subject="50% off", unsub=True))
    db.insert_email(mail("judge", "t2"))
    rows = [{"message_id": "bulk", "thread_id": "t1", "important": False},
            {"message_id": "judge", "thread_id": "t2", "important": True}]
    models = {"bulk": verdict(5), "judge": verdict(5)}
    yield db, rows, models
    db.close()


def test_prefilter_only_defaults_deferred_to_not_important(env):
    db, rows, models = env
    r = evaluate(db, rows, models, 4, PrefilterConfig())["prefilter only"]
    assert r.tn == 1                 # bulk correctly not-important
    assert r.fn == 1                 # judgement call missed, as rules must


def test_model_only_uses_the_model_everywhere(env):
    db, rows, models = env
    r = evaluate(db, rows, models, 4, PrefilterConfig())["model only"]
    assert r.tp == 1 and r.fp == 1   # gets the judgement call, over-calls bulk


def test_hybrid_takes_prefilter_first(env):
    db, rows, models = env
    r = evaluate(db, rows, models, 4, PrefilterConfig())["hybrid"]
    assert r.tp == 1 and r.tn == 1 and r.fp == 0 and r.fn == 0


def test_all_three_conditions_are_reported(env):
    db, rows, models = env
    out = evaluate(db, rows, models, 4, PrefilterConfig())
    assert set(out) == {"prefilter only", "model only", "hybrid"}


def test_false_negatives_are_enumerated(env):
    db, rows, models = env
    fns = false_negatives(db, rows, {"judge": verdict(1)}, 4, PrefilterConfig())
    assert [f["message_id"] for f in fns] == ["judge"]
    assert fns[0]["subject"] and "source" in fns[0]


# ----------------------------------------------------------------- render

def test_render_warns_about_small_samples(env):
    db, rows, models = env
    out = render(evaluate(db, rows, models, 4, PrefilterConfig()), 4, n=38)
    assert "single flipped case" in out
    assert "Confusion matrix" in out


def test_render_omits_the_warning_when_n_is_large(env):
    db, rows, models = env
    assert "single flipped case" not in render(
        evaluate(db, rows, models, 4, PrefilterConfig()), 4, n=500)
