from datetime import datetime, timedelta, timezone

from telemail.db import Database
from telemail.models import Email, SenderSignals
from telemail.report import purge_reports

NOW = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)


def _email(mid: str, when: datetime) -> Email:
    return Email(message_id=mid, thread_id="t" + mid, sender_email="a@b.c",
                 sender_name="A", sender_domain="b.c", subject="Subject " + mid,
                 snippet="preview text " + mid, received_at=when, labels=["INBOX"],
                 signals=SenderSignals())


def _db() -> Database:
    db = Database(":memory:")
    db.insert_email(_email("old", NOW - timedelta(days=4)))
    db.insert_email(_email("edge", NOW - timedelta(days=3, hours=1)))
    db.insert_email(_email("fresh", NOW - timedelta(days=1)))
    return db


def test_blanks_preview_text_older_than_the_window():
    db = _db()
    assert db.purge_content(NOW - timedelta(days=3)) == 2
    assert db.get_email("old").snippet == ""
    assert db.get_email("edge").snippet == ""
    assert db.get_email("fresh").snippet == "preview text fresh"


def test_keeps_metadata_and_is_idempotent():
    db = _db()
    db.purge_content(NOW - timedelta(days=3))
    old = db.get_email("old")
    assert old.subject == "Subject old" and old.sender_email == "a@b.c"
    assert old.received_at is not None
    assert db.purge_content(NOW - timedelta(days=3)) == 0


def test_sync_poll_purges_after_a_clean_cycle():
    from telemail.sync import SyncEngine

    class Adapter:
        def history(self, watermark, page_token=None):
            return {"history": [], "historyId": "99"}

    db = _db()
    db.set_state("history_id", "1")
    SyncEngine(db, Adapter(), retention_days=3, now=lambda: NOW).poll()
    assert db.get_email("old").snippet == ""
    assert db.get_email("fresh").snippet == "preview text fresh"


def test_old_reports_are_deleted_but_the_latest_is_kept(tmp_path):
    import os
    for name, age_days in (("a.pdf", 9), ("b.pdf", 5), ("c.pdf", 1)):
        path = tmp_path / name
        path.write_bytes(b"%PDF-1.4\n")
        stamp = (NOW - timedelta(days=age_days)).timestamp()
        os.utime(path, (stamp, stamp))
    assert purge_reports(tmp_path, NOW - timedelta(days=3)) == 2
    assert sorted(p.name for p in tmp_path.iterdir()) == ["c.pdf"]


def test_the_newest_report_is_kept_even_when_every_report_is_old(tmp_path):
    import os
    for name, age_days in (("a.pdf", 9), ("b.pdf", 5)):
        path = tmp_path / name
        path.write_bytes(b"%PDF-1.4\n")
        stamp = (NOW - timedelta(days=age_days)).timestamp()
        os.utime(path, (stamp, stamp))
    assert purge_reports(tmp_path, NOW - timedelta(days=3)) == 1
    assert [p.name for p in tmp_path.iterdir()] == ["b.pdf"]


def test_purge_reports_survives_a_missing_directory(tmp_path):
    assert purge_reports(tmp_path / "nope", NOW) == 0


# ------------------------------------------------------- /sync tells the user

def test_sync_reports_what_aged_out(tmp_path):
    import asyncio

    from telemail.bot import TeleMailBot
    from telemail.broker.broker import Broker
    from telemail.sync import SyncStats
    from tests.test_sync_command import _update

    db = Database(":memory:")
    old_pdf = tmp_path / "report-old.pdf"
    old_pdf.write_bytes(b"%PDF-1.4\n")
    keep_pdf = tmp_path / "report-new.pdf"
    keep_pdf.write_bytes(b"%PDF-1.4\n")
    import os
    for path, age in ((old_pdf, 9), (keep_pdf, 8)):
        stamp = (NOW - timedelta(days=age)).timestamp()
        os.utime(path, (stamp, stamp))

    bot = TeleMailBot("tok", 1, db=db, broker=Broker(db, None),
                      sync_fn=lambda: SyncStats(inserted=0, purged=4),
                      triage_fn=lambda: 0)
    bot.reports_dir = tmp_path
    bot.now = lambda: NOW
    update, msg = _update(chat=1)
    asyncio.run(bot.on_sync(update, None))

    note = msg.progress.edits[-1][0]
    assert "4 email preview" in note and "1 old report" in note
    assert not old_pdf.exists() and keep_pdf.exists()
