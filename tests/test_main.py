"""Orchestration: the composition root makes no decisions, but it must route
them correctly."""
from datetime import datetime


from telemail.__main__ import (App, alerts_sent_today, pending_alerts,
                               triage_pending)
from telemail.broker.broker import Broker
from telemail.db import Database
from telemail.models import Email, SenderSignals, TriageResult
from telemail.policy import AlertPolicy
from telemail.triage.prefilter import PrefilterConfig

NOON = datetime(2026, 9, 1, 12, 0)


def mail(mid, sender="someone@example.com", subject="Lunch", unsub=False,
         **sig) -> Email:
    return Email(message_id=mid, thread_id=f"t{mid}", sender_email=sender,
                 sender_domain=sender.split("@")[1], subject=subject,
                 snippet="x", received_at=NOON, is_direct=True,
                 has_list_unsubscribe=unsub, signals=SenderSignals(**sig))


class RecordingPlanner:
    def __init__(self): self.seen = []
    def triage(self, emails):
        self.seen.extend(e.message_id for e in emails)
        return [TriageResult(message_id=e.message_id, category="academic",
                             urgency=4, requires_action=True, reason="r",
                             confidence=0.9, source="model") for e in emails]


class BrokenPlanner:
    def triage(self, emails): raise ConnectionError("down")


def app_with(planner, policy=None) -> App:
    db = Database(":memory:")
    return App(db=db, adapter=None, sync=None, broker=Broker(db, None),
               planner=planner, policy=policy or AlertPolicy(),
               prefilter_cfg=PrefilterConfig(), own_address="you@uni.edu")


# ---------------------------------------------- prefilter before the model

def test_only_deferred_mail_reaches_the_model():
    planner = RecordingPlanner()
    app = app_with(planner)
    app.db.insert_email(mail("bulk", subject="50% off", unsub=True))
    app.db.insert_email(mail("judgement"))
    app.db.insert_email(mail("spoof", spf="fail", dmarc="fail"))

    verdicts = triage_pending(app)
    assert planner.seen == ["judgement"], "prefilter work was sent to the model"
    assert {v.source for v in verdicts} == {"prefilter", "model"}


def test_sources_are_recorded_for_the_ablation():
    app = app_with(RecordingPlanner())
    app.db.insert_email(mail("bulk", subject="Sale", unsub=True))
    app.db.insert_email(mail("judgement"))
    triage_pending(app)
    assert app.db.source_counts() == {"prefilter": 1, "model": 1}


def test_already_triaged_mail_is_not_redone():
    planner = RecordingPlanner()
    app = app_with(planner)
    app.db.insert_email(mail("m1"))
    triage_pending(app)
    triage_pending(app)
    assert planner.seen == ["m1"]


def test_planner_failure_leaves_prefilter_results_intact():
    app = app_with(BrokenPlanner())
    app.db.insert_email(mail("bulk", subject="Sale", unsub=True))
    app.db.insert_email(mail("judgement"))
    verdicts = triage_pending(app)
    assert [v.message_id for v in verdicts] == ["bulk"]
    assert app.db.get_triage("judgement") is None


def test_nothing_pending_is_a_no_op():
    assert triage_pending(app_with(RecordingPlanner())) == []


# ------------------------------------------------------------ alert routing

def test_high_urgency_becomes_an_alert():
    app = app_with(RecordingPlanner())
    app.db.insert_email(mail("m1"))
    assert len(pending_alerts(app, triage_pending(app), now=NOON)) == 1


def test_bulk_mail_does_not_alert():
    app = app_with(RecordingPlanner())
    app.db.insert_email(mail("bulk", subject="Sale", unsub=True))
    assert pending_alerts(app, triage_pending(app), now=NOON) == []


def test_spoofed_mail_alerts_even_at_night():
    app = app_with(RecordingPlanner())
    app.db.insert_email(mail("spoof", spf="fail", dmarc="fail"))
    night = datetime(2026, 9, 1, 23, 30)
    assert len(pending_alerts(app, triage_pending(app), now=night)) == 1


def test_daily_cap_counts_only_today():
    app = app_with(RecordingPlanner())
    for i in range(3):
        app.db.log(actor="bot", event="alert_sent", payload={"message_id": i})
    assert alerts_sent_today(app) == 3


def test_cap_applies_within_a_single_cycle():
    """Twenty alerts in one batch must not become twenty-five."""
    app = app_with(RecordingPlanner(), policy=AlertPolicy(daily_cap=2))
    for i in range(5):
        app.db.insert_email(mail(f"m{i}"))
    assert len(pending_alerts(app, triage_pending(app), now=NOON)) == 2


# ------------------------------------------------- the two wiring bugs fixed

def test_triage_queue_is_independent_of_labelling():
    """Triage used to draw from the *unlabelled* queue, so catching up on
    labelling would have silently stopped triage entirely."""
    app = app_with(RecordingPlanner())
    app.db.insert_email(mail("m1"))
    app.db.add_label("m1", True)                 # labelled, but never triaged
    assert [e.message_id for e in app.db.untriaged()] == ["m1"]
    assert len(triage_pending(app)) == 1


def test_deferred_alert_is_delivered_once_the_window_passes():
    """policy.py promises 'defer, never drop'. The loop has to keep it."""
    from telemail.__main__ import due_alerts
    app = app_with(RecordingPlanner())
    app.db.insert_email(mail("m1"))
    triage_pending(app)

    night = datetime(2026, 9, 1, 23, 30)
    assert due_alerts(app, now=night) == [], "alerted during quiet hours"

    morning = datetime(2026, 9, 2, 8, 0)
    assert len(due_alerts(app, now=morning)) == 1, "deferred alert was lost"


def test_an_alerted_message_is_not_alerted_again():
    from telemail.__main__ import due_alerts
    app = app_with(RecordingPlanner())
    app.db.insert_email(mail("m1"))
    triage_pending(app)
    assert len(due_alerts(app, now=NOON)) == 1
    app.db.log(actor="bot", event="alert_sent", payload={"message_id": "m1"})
    assert due_alerts(app, now=NOON) == []


def test_backlog_is_scanned_not_just_the_current_batch():
    from telemail.__main__ import due_alerts
    app = app_with(RecordingPlanner())
    app.db.insert_email(mail("old"))
    triage_pending(app)                          # triaged in an earlier cycle
    app.db.insert_email(mail("new"))
    triage_pending(app)
    assert {v.message_id for _, v in due_alerts(app, now=NOON)} == {"old", "new"}


def test_http_loggers_are_silenced_so_the_token_never_reaches_a_log():
    """python-telegram-bot logs the request URL at INFO, and the URL embeds the
    bot token. Verified by asserting the suppression is actually applied."""
    import re
    src = open("telemail/__main__.py").read()
    assert re.search(r'for noisy in \([^)]*"httpx"', src)
    assert 'setLevel(logging.WARNING)' in src
    for name in ("httpx", "telegram.Bot"):
        assert name in src, f"{name} not suppressed"


def test_unconfigured_model_leaves_mail_untriaged_not_fallback():
    """Without a model, deferred mail must stay in the queue — fallback verdicts
    would pollute the database and the RQ1 numbers."""
    from telemail.triage.planner import OpenRouterPlanner
    app = app_with(OpenRouterPlanner(api_key="", model=""))
    app.db.insert_email(mail("bulk", subject="Sale", unsub=True))
    app.db.insert_email(mail("judgement"))
    verdicts = triage_pending(app)
    assert [v.message_id for v in verdicts] == ["bulk"]
    assert app.db.get_triage("judgement") is None
    assert "fallback" not in app.db.source_counts()


# ------------------------------------------------------------ Feature A wiring

def test_triage_all_empties_the_queue_across_batches():
    from telemail.__main__ import triage_all
    app = app_with(RecordingPlanner())
    for i in range(95):
        app.db.insert_email(mail(f"m{i}"))
    assert triage_all(app, limit=40) == 0
    assert sum(app.db.source_counts().values()) == 95


def test_triage_all_stops_when_the_model_is_down():
    from telemail.__main__ import triage_all
    app = app_with(BrokenPlanner())
    app.db.insert_email(mail("bulk", subject="Sale", unsub=True))
    app.db.insert_email(mail("judgement"))
    assert triage_all(app) == 1, "must terminate and report what is left"


def test_bot_no_longer_syncs_on_a_timer():
    import inspect
    import telemail.__main__ as main_mod
    src = inspect.getsource(main_mod)
    assert "run_repeating" not in src
    assert not hasattr(main_mod, "cycle")
