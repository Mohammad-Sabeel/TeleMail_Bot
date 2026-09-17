from datetime import datetime, timedelta

from eval.performance import broker_overhead, cost, pipeline_latency
from telemail.db import Database
from telemail.models import Email, SenderSignals, TriageResult


def test_broker_overhead_measures_both_arms():
    r = broker_overhead(n=40)
    assert r["brokered"]["n"] == 40 and r["naive"]["n"] == 40
    assert r["brokered"]["p50"] > 0 and "overhead_p50" in r


def _email(mid, received):
    return Email(message_id=mid, thread_id="t", sender_email="a@b.c",
                 sender_domain="b.c", subject="s", snippet="x",
                 received_at=received, signals=SenderSignals())


def test_backfilled_mail_is_excluded_from_live_latency():
    db = Database(":memory:")
    now = datetime.now().astimezone()
    db.insert_email(_email("live", now - timedelta(seconds=30)))
    db.insert_email(_email("old", now - timedelta(days=5)))
    r = pipeline_latency(db)
    assert r["messages_total"] == 2 and r["live_messages"] == 1


def test_cost_is_not_reported_without_prices_or_usage():
    db = Database(":memory:")
    assert cost(db, 1.0, 3.0)["usd_per_1000"] is None
    db.log(actor="planner", event="model_usage",
           payload={"prompt_tokens": 1000, "completion_tokens": 100})
    assert cost(db, None, None)["usd_total"] is None


def test_cost_per_1000_verdicts():
    db = Database(":memory:")
    db.insert_email(_email("m1", datetime(2026, 9, 1)))
    db.upsert_triage(TriageResult(message_id="m1", category="academic", urgency=3,
                                  requires_action=False, reason="r",
                                  confidence=0.9, source="model"))
    db.log(actor="planner", event="model_usage",
           payload={"prompt_tokens": 1_000_000, "completion_tokens": 0})
    assert cost(db, 2.0, 0.0)["usd_per_1000"] == 2000.0


def test_usage_is_recorded_by_the_composition_root():
    import sys
    sys.path.insert(0, "tests")
    from test_main import app_with, mail
    from telemail.__main__ import triage_pending

    class Metered:
        def triage(self, emails):
            return [TriageResult(message_id=e.message_id, category="academic",
                                 urgency=3, requires_action=False, reason="r",
                                 confidence=0.9, source="model") for e in emails]
        def drain_usage(self):
            return [{"prompt_tokens": 500, "completion_tokens": 50}]

    app = app_with(Metered())
    app.db.insert_email(mail("m1"))
    triage_pending(app)
    assert app.db.audit_entries(event="model_usage")[0]["payload"]["prompt_tokens"] == 500
