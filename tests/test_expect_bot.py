"""Feature B in the bot: warnings, summary section, ask/wait/skip, /expect."""
import asyncio
from datetime import datetime

import pytest

from telemail.bot import (ExpectedLine, SyncSummary, build_sync_summary,
                          format_expected_reply, format_sync_summary, open_buttons,
                          warning_reason)
from telemail.models import Email, SenderSignals, TriageResult


def mail(mid, subject=None, day=16, **sig) -> Email:
    return Email(message_id=mid, thread_id=f"t{mid}", sender_email=f"{mid}@uni.edu",
                 sender_name="Registrar", sender_domain="uni.edu",
                 subject=subject or f"Subject {mid}", snippet="snippet",
                 received_at=datetime(2026, 9, day, 10), signals=SenderSignals(**sig))


def tr(mid, urgency=3, category="academic") -> TriageResult:
    return TriageResult(message_id=mid, category=category, urgency=urgency,
                        requires_action=False, reason="r", confidence=0.9, source="model")


# ------------------------------------------------------------ warning_reason

def test_warning_for_suspicious_and_failed_checks_only():
    assert warning_reason(mail("a"), tr("a", 1, "suspicious")) == "flagged suspicious"
    assert warning_reason(mail("b", spf="fail"), tr("b")) == "failed sender checks"
    assert warning_reason(mail("c", spf="none"), tr("c")) is None


# ------------------------------------------------------------ summary section

def test_expected_section_sits_between_suspicious_and_top():
    items = [(mail("s"), tr("s", 5, "suspicious")), (mail("e"), tr("e", 2)),
             (mail("t"), tr("t", 5))]
    expected = [ExpectedLine("fee receipt", [(mail("e"), tr("e", 2), 0.84)])]
    text = format_sync_summary(build_sync_summary(items, expected=expected))
    assert text.index("Suspicious") < text.index("Expected today") < text.index("Top emails")


def test_expected_match_is_not_repeated_in_top():
    items = [(mail("e"), tr("e", 5)), (mail("t"), tr("t", 4))]
    expected = [ExpectedLine("fee", [(mail("e"), tr("e", 5), 0.9)])]
    s = build_sync_summary(items, expected=expected)
    assert [e.message_id for e, _ in s.top] == ["t"]
    assert [e.message_id for e, _ in s.listed] == ["e", "t"]


def test_suspicious_match_is_listed_once_and_keeps_its_warning():
    items = [(mail("s", spf="fail", dmarc="fail"), tr("s", 5, "suspicious"))]
    expected = [ExpectedLine("fee receipt",
                             [(mail("s", spf="fail", dmarc="fail"), tr("s", 5, "suspicious"), 0.95)])]
    s = build_sync_summary(items, expected=expected)
    assert [e.message_id for e, _ in s.listed] == ["s"]
    text = format_sync_summary(s)
    assert "matches “fee receipt” but flagged suspicious" in text


def test_unmatched_keyword_says_nothing_yet():
    text = format_expected_reply([ExpectedLine("visa letter", [])])
    assert "visa letter — nothing yet" in text


def test_expected_reply_escapes_keyword_and_subject():
    line = ExpectedLine("*bold* kw", [(mail("a", subject="_x_"), tr("a"), 0.7)])
    text = format_expected_reply([line])
    assert "*bold*" not in text and "\\_x\\_" in text


def test_open_buttons_include_expected_matches():
    s = SyncSummary(new=0, important=0, suspicious=[], top=[],
                    expected=[ExpectedLine("k", [(mail("a"), None, 0.8)])])
    assert open_buttons(s) == [("Open 1", "open:a")]


# ------------------------------------------------------------ bot flow

from telemail.bot import HELP, TeleMailBot
from telemail.broker.broker import Broker
from telemail.db import Database
from telemail.sync import SyncStats

ALLOWED = 123456
TODAY = "2026-09-17"


class _Progress:
    def __init__(self): self.edits = []
    async def edit_text(self, text, **kw): self.edits.append((text, kw))


class _Msg:
    def __init__(self, text=""):
        self.text, self.sent, self.progress = text, [], _Progress()
    async def reply_text(self, t, **kw):
        self.sent.append((t, kw))
        return self.progress


def _update(chat=ALLOWED, text=""):
    msg = _Msg(text)
    return type("U", (), {"effective_chat": type("C", (), {"id": chat})(),
                          "message": msg, "callback_query": None})(), msg


def _ctx(*args):
    return type("Ctx", (), {"args": list(args)})()


@pytest.fixture
def bot():
    db = Database(":memory:")
    db.insert_email(mail("draft", subject="Thesis draft chapter three"))
    db.upsert_triage(tr("draft", 4))
    b = TeleMailBot("tok", ALLOWED, db=db, broker=Broker(db, None),
                    sync_fn=lambda: SyncStats(inserted=1, inserted_ids=["draft"]),
                    triage_fn=lambda: 0)
    b.today = lambda: TODAY
    b.now = lambda: datetime(2026, 9, 17, 12)
    return b


def texts(msg):
    return [t for t, _ in msg.sent]


def test_first_sync_of_the_day_asks_once(bot):
    u, msg = _update()
    asyncio.run(bot.on_sync(u, None))
    assert any("expecting today" in t for t in texts(msg))
    ask_kw = [kw for t, kw in msg.sent if "expecting today" in t][0]
    assert ask_kw["reply_markup"] is not None, "has a [Skip] button"

    u2, msg2 = _update()
    asyncio.run(bot.on_sync(u2, None))
    assert not any("expecting today" in t for t in texts(msg2))


def test_next_text_is_taken_as_keywords_exactly_once(bot):
    asyncio.run(bot.on_sync(*_update()[:1], None))
    u, msg = _update(text="thesis draft, visa letter")
    asyncio.run(bot.on_text(u, None))
    assert bot.db.expectations_for(TODAY) == ["thesis draft", "visa letter"]
    reply = texts(msg)[0]
    assert "Thesis draft chapter three" in reply and "visa letter — nothing yet" in reply

    u2, msg2 = _update(text="what is urgent")
    asyncio.run(bot.on_text(u2, None))
    assert bot.db.expectations_for(TODAY) == ["thesis draft", "visa letter"]
    assert "needs a model" in texts(msg2)[0], "second text routes to /ask"


def test_skip_ends_the_wait(bot):
    asyncio.run(bot.on_sync(*_update()[:1], None))
    edited = []

    class Q:
        data = "expect:skip"
        async def answer(self, *a, **kw): pass
        async def edit_message_text(self, t, **kw): edited.append(t)

    update = type("U", (), {"effective_chat": type("C", (), {"id": ALLOWED})(),
                            "callback_query": Q()})()
    asyncio.run(bot.on_callback(update, None))
    assert "Skipped" in edited[0]
    u, msg = _update(text="fee receipt")
    asyncio.run(bot.on_text(u, None))
    assert bot.db.expectations_for(TODAY) == []


def test_sync_summary_includes_todays_matches(bot):
    bot.db.set_state("expect_asked_on", TODAY)
    bot.db.add_expectations(TODAY, ["thesis draft"])
    u, msg = _update()
    asyncio.run(bot.on_sync(u, None))
    final = msg.progress.edits[-1][0]
    assert "Expected today" in final and "thesis draft" in final


def test_expect_command_add_list_clear(bot):
    u, msg = _update()
    asyncio.run(bot.on_expect(u, _ctx("thesis", "draft,", "visa")))
    assert bot.db.expectations_for(TODAY) == ["thesis draft", "visa"]

    u, msg = _update()
    asyncio.run(bot.on_expect(u, _ctx()))
    assert "Thesis draft chapter three" in texts(msg)[0]

    u, msg = _update()
    asyncio.run(bot.on_expect(u, _ctx("clear")))
    assert "Cleared 2" in texts(msg)[0] and bot.db.expectations_for(TODAY) == []


def test_yesterdays_keywords_do_not_apply(bot):
    bot.db.add_expectations("2026-09-16", ["thesis draft"])
    u, msg = _update()
    asyncio.run(bot.on_expect(u, _ctx()))
    assert "Nothing expected today" in texts(msg)[0]


def test_expect_ignores_strangers(bot):
    u, msg = _update(chat=999)
    asyncio.run(bot.on_expect(u, _ctx("secret")))
    assert msg.sent == [] and bot.db.expectations_for(TODAY) == []


def test_help_lists_expect():
    assert "/expect" in HELP
