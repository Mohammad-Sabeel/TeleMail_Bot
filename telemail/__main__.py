"""Assembly and the run loop.

Everything here is wiring — no decisions are made in this file. That is
deliberate: the interesting behaviour lives in tested modules, and the
composition root is meant to be boring enough to read in one sitting.

    python -m telemail sync       # one poll, print what happened
    python -m telemail triage     # classify anything untriaged
    python -m telemail bot        # Telegram + the mail cycle, one process
    python -m telemail run        # headless loop, alerts logged only
    python -m telemail status     # counts, watermark, rejections
"""
from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from telemail.bot import TeleMailBot
from telemail.broker.broker import Broker
from telemail.budget import Budget
from telemail.config import get_settings
from telemail.db import Database
from telemail.gmail.adapter import GmailReadAdapter
from telemail.gmail.auth import build_service
from telemail.models import Email, TriageResult
from telemail.policy import AlertPolicy, should_alert
from telemail.sync import SyncEngine
from telemail.threatintel import VirusTotal
from telemail.triage.planner import OpenRouterPlanner
from telemail.triage.prefilter import PrefilterConfig, prefilter

log = logging.getLogger("telemail")


@dataclass
class App:
    db: Database
    adapter: GmailReadAdapter
    sync: SyncEngine
    broker: Broker
    planner: object
    policy: AlertPolicy
    prefilter_cfg: PrefilterConfig
    own_address: str
    bot: TeleMailBot | None = None


def build_app(db_path: str | None = None) -> App:
    s = get_settings()
    db = Database(db_path or s.db_path)
    adapter = GmailReadAdapter(
        build_service(s.gmail_credentials_path, s.gmail_token_path))

    own = s.own_address or adapter.profile().get("emailAddress", "")
    broker = Broker(db, adapter, write_service=None)
    planner = OpenRouterPlanner(s.openrouter_api_key, s.model_name)
    planner.budget = Budget(daily_tokens=s.daily_token_budget)

    app = App(db=db, adapter=adapter,
              sync=SyncEngine(db, adapter, own_address=own),
              broker=broker, planner=planner,
              policy=AlertPolicy(),
              prefilter_cfg=PrefilterConfig(),
              own_address=own,
              bot=TeleMailBot(s.telegram_bot_token, s.telegram_allowed_chat_id,
                              db=db, broker=broker, planner=planner,
                              adapter=adapter))
    app.bot.sync_fn = app.sync.poll
    app.bot.triage_fn = lambda: triage_all(app)
    app.bot.reports_dir = Path("data/reports")
    app.bot.max_reads_per_sync = s.max_reads_per_sync
    if s.virustotal_api_key:
        app.bot.threat_intel = VirusTotal(s.virustotal_api_key)
    return app


# ------------------------------------------------------------------ triage

def triage_pending(app: App, limit: int = 40) -> list[TriageResult]:
    """Prefilter first; only what it defers reaches the model.

    Splitting it this way is what makes `source` meaningful, and `source` is
    what makes the ablation possible without re-running anything.
    """
    pending = app.db.untriaged(limit)
    if not pending:
        return []

    decided, deferred = [], []
    for email in pending:
        verdict = prefilter(email, app.prefilter_cfg)
        (decided if verdict else deferred).append(verdict or email)

    if deferred:
        try:
            decided.extend(app.planner.triage(deferred))
        except Exception:
            log.exception("planner failed; leaving %d untriaged", len(deferred))
        for usage in getattr(app.planner, "drain_usage", lambda: [])():
            app.db.log(actor="planner", event="model_usage", payload=usage)

    for verdict in decided:
        app.db.upsert_triage(verdict)
    return decided


def triage_all(app: App, limit: int = 40, max_rounds: int = 50) -> int:
    """Triage until the queue is empty or a round decides nothing (model down).
    Returns how many emails are still untriaged."""
    # ponytail: stops at the first empty round; if >limit deferred emails fail
    # together, later emails wait for the next /sync. Page past failures if seen.
    for _ in range(max_rounds):
        if not triage_pending(app, limit):
            break
    return len(app.db.untriaged(10_000))


def alerts_sent_today(app: App) -> int:
    today = date.today().isoformat()
    return sum(1 for e in app.db.audit_entries(event="alert_sent")
               if e["ts"].startswith(today))


def due_alerts(app: App, now: datetime | None = None
               ) -> list[tuple[Email, TriageResult]]:
    """Everything triaged, never announced, and due now.

    Scanning the backlog rather than only the current batch is what actually
    delivers a message that quiet hours deferred at 23:30 — policy.py promises
    "defer, never drop", and this is the half that keeps the promise.
    """
    now = now or datetime.now()
    sent = alerts_sent_today(app)
    out = []
    for email, verdict in app.db.triaged_not_alerted():
        decision = should_alert(verdict, email, now=now,
                                sent_today=sent + len(out), policy=app.policy)
        if decision.alert:
            out.append((email, verdict))
        elif decision.deferred:
            log.debug("holding %s until %s (%s)", verdict.message_id,
                      decision.defer_until, decision.reason)
    return out


def pending_alerts(app: App, verdicts: list[TriageResult],
                   now: datetime | None = None) -> list[tuple[Email, TriageResult]]:
    """Alerts arising from one batch. `due_alerts` is the loop's entry point;
    this remains for callers that only care about what just happened."""
    fresh = {v.message_id for v in verdicts}
    return [(e, v) for e, v in due_alerts(app, now) if v.message_id in fresh]


# ------------------------------------------------------------- subcommands

def cmd_sync(app: App) -> None:
    s = app.sync.poll()
    print(f"fetched {s.fetched}  inserted {s.inserted}  duplicates {s.duplicates}")
    if s.resynced:
        print("watermark had expired; performed a full resync")
    if s.errors:
        print(f"{len(s.errors)} error(s); watermark held: {s.errors[:3]}")
    print(f"watermark: {app.db.get_state('history_id')}")


def cmd_triage(app: App) -> None:
    verdicts = triage_pending(app)
    if not verdicts:
        print("nothing to triage")
        return
    by_source: dict[str, int] = {}
    for v in verdicts:
        by_source[v.source] = by_source.get(v.source, 0) + 1
    print(f"triaged {len(verdicts)}: {by_source}")
    for email, v in pending_alerts(app, verdicts):
        print(f"  ALERT  [{v.urgency}] {v.category:<12} {email.subject[:50]}")


def cmd_status(app: App) -> None:
    db = app.db
    print(f"messages      {db.count_emails()}")
    print(f"labels        {db.label_count()}  {db.label_balance()}")
    print(f"triage source {db.source_counts() or 'none'}")
    print(f"watermark     {db.get_state('history_id')}")
    print(f"rejections    {len(db.audit_entries(event='rejected'))}")
    print(f"alerts today  {alerts_sent_today(app)}")


def cmd_bot(app: App) -> None:                     # pragma: no cover
    """Telegram long polling. Mail is fetched only when you send /sync."""
    log.info("bot running; mail syncs only on /sync; chat %s",
             app.bot.allowed_chat_id)
    app.bot.build_app().run_polling()


def cmd_run(app: App, interval: int) -> None:      # pragma: no cover
    """Headless: no Telegram, alerts logged only. Useful for a cold-start demo."""
    import time
    log.info("running headless; polling every %ss", interval)
    while True:
        try:
            app.sync.poll()
            triage_pending(app)
            for email, v in due_alerts(app):
                log.info("ALERT [%d] %s — %s", v.urgency, v.category,
                         email.subject)
        except KeyboardInterrupt:
            raise
        except Exception:
            log.exception("cycle failed; continuing")
        time.sleep(interval)


def main() -> None:
    ap = argparse.ArgumentParser(prog="telemail")
    ap.add_argument("command",
                    choices=["sync", "triage", "bot", "run", "status"])
    ap.add_argument("--interval", type=int, default=0)
    ap.add_argument("--db", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")

    # python-telegram-bot and httpx log full request URLs at INFO, and the URL
    # contains the bot token. A credential must never reach a log file.
    for noisy in ("httpx", "httpcore", "telegram.ext.Updater",
                  "telegram.Bot", "apscheduler"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    app = build_app(args.db)
    interval = args.interval or get_settings().poll_seconds
    {"sync": cmd_sync,
     "triage": cmd_triage,
     "status": cmd_status,
     "bot": cmd_bot,
     "run": lambda a: cmd_run(a, interval)}[args.command](app)


if __name__ == "__main__":
    main()
