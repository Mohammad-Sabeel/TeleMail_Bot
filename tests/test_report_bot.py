"""Feature C in the bot: reading stage, stored verdicts, the document."""
import asyncio
from datetime import datetime

import pytest

from telemail.bot import TeleMailBot, format_email_details, warning_reason
from telemail.broker.broker import Broker
from telemail.db import Database
from telemail.gmail.adapter import MessageGone
from telemail.models import Email, SenderSignals, TriageResult
from telemail.sync import SyncStats

ALLOWED = 123456
BODY_MARKER = "BODY-MUST-NEVER-BE-STORED"
GIST_MARKER = "GIST-MUST-NEVER-BE-STORED"


def mail(mid, **sig) -> Email:
    return Email(message_id=mid, thread_id=f"t{mid}", sender_email=f"{mid}@uni.edu",
                 sender_name="Registrar", sender_domain="uni.edu", subject=f"Subject {mid}",
                 snippet="snippet", received_at=datetime(2026, 9, 16, 10),
                 signals=SenderSignals(first_contact=False, **sig))


def tr(mid, urgency=3, category="academic", source="model") -> TriageResult:
    return TriageResult(message_id=mid, category=category, urgency=urgency,
                        requires_action=False, reason="r", confidence=0.9, source=source)


class Adapter:
    def __init__(self): self.reads = []
    def read_message(self, message_id):
        self.reads.append(message_id)
        if message_id == "gone":
            raise MessageGone(message_id)
        links = ([{"text": "https://198.51.100.7/x", "href": "https://198.51.100.7/x"}]
                 if message_id == "ip" else [])
        return {"message_id": message_id, "body": f"hello {BODY_MARKER}",
                "attachments": [], "links": links, "untrusted": True}


class Planner:
    def ask_json(self, system, user):
        return {"gist": GIST_MARKER, "social_engineering": False,
                "injection_attempt": False, "suggested_action": "reply", "reason": "ok"}


class _Progress:
    def __init__(self): self.edits = []
    async def edit_text(self, text, **kw): self.edits.append((text, kw))


class _Msg:
    def __init__(self):
        self.sent, self.documents, self.progress = [], [], _Progress()
    async def reply_text(self, t, **kw):
        self.sent.append(t)
        return self.progress
    async def reply_document(self, document, filename=None, caption=None, **kw):
        self.documents.append({"filename": filename, "caption": caption,
                               "bytes": document.read()})


def _update(chat=ALLOWED):
    msg = _Msg()
    return type("U", (), {"effective_chat": type("C", (), {"id": chat})(),
                          "message": msg})(), msg


@pytest.fixture
def env(tmp_path):
    db = Database(":memory:")
    specs = [("ok", tr("ok", 4)), ("ip", tr("ip", 3)), ("gone", tr("gone", 2)),
             ("bulk", tr("bulk", 1, "promotional", "prefilter"))]
    for mid, verdict in specs:
        db.insert_email(mail(mid))
        db.upsert_triage(verdict)
    adapter = Adapter()
    bot = TeleMailBot("tok", ALLOWED, db=db, broker=Broker(db, adapter), planner=Planner(),
                      sync_fn=lambda: SyncStats(inserted=4,
                                                inserted_ids=["ok", "ip", "gone", "bulk"]),
                      triage_fn=lambda: 0)
    bot.reports_dir = tmp_path / "reports"
    bot.db.set_state("expect_asked_on", bot.today())
    return bot, adapter


def run_sync(bot):
    update, msg = _update()
    asyncio.run(bot.on_sync(update, None))
    return msg


def test_sync_sends_report_pdf_with_counts(env):
    bot, _ = env
    msg = run_sync(bot)
    doc = msg.documents[0]
    assert doc["filename"] == "report.pdf" and doc["bytes"].startswith(b"%PDF")
    assert doc["caption"] == "0 threats · 2 caution · 1 no threat indicators · 1 bulk not read"


def test_bulk_mail_is_not_read(env):
    bot, adapter = env
    run_sync(bot)
    assert "bulk" not in adapter.reads


def test_reads_go_through_the_broker_and_are_audited(env):
    bot, _ = env
    run_sync(bot)
    accepted = [e for e in bot.db.audit_entries(event="accepted")
                if e["payload"].get("op") == "read_message"]
    assert {e["payload"]["message_id"] for e in accepted} == {"ok", "ip", "gone"}


def test_verdicts_are_stored_with_level_and_evidence(env):
    bot, _ = env
    run_sync(bot)
    assert bot.db.get_assessment("ok")["level"] == "NONE"
    assert bot.db.get_assessment("ip")["level"] == "CAUTION"
    gone = bot.db.get_assessment("gone")
    assert gone["level"] == "CAUTION" and "body could not be read" in gone["evidence"]


def test_neither_body_nor_gist_reaches_the_database(env):
    bot, _ = env
    run_sync(bot)
    dump = "\n".join(bot.db.con.iterdump())
    assert BODY_MARKER not in dump and GIST_MARKER not in dump


def test_no_new_mail_means_no_report(env):
    bot, _ = env
    bot.sync_fn = lambda: SyncStats(inserted=0)
    msg = run_sync(bot)
    assert msg.documents == []


def test_reading_stage_is_shown(env):
    bot, _ = env
    msg = run_sync(bot)
    assert any("Reading 3" in text for text, _ in msg.progress.edits)


def test_bot_without_reports_dir_never_reads(env):
    bot, adapter = env
    bot.reports_dir = None
    msg = run_sync(bot)
    assert adapter.reads == [] and msg.documents == []


def test_stored_verdict_raises_a_warning():
    e = mail("a")
    assert warning_reason(e, tr("a"), "CAUTION") == "assessed as caution"
    assert warning_reason(e, tr("a"), "NONE") is None


def test_open_details_show_the_report_verdict():
    text = format_email_details(mail("a"), tr("a"),
                                {"level": "THREAT", "evidence": ["SPF, DMARC failed"]})
    assert "THREAT" in text and "SPF, DMARC failed" in text
