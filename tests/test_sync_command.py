"""Feature A: /sync summary, [Open], and the /sync handler."""
import asyncio
from datetime import datetime

import pytest

from telemail.bot import (SyncSummary, build_sync_summary, format_sync_summary,
                          open_buttons)
from telemail.models import Email, SenderSignals, TriageResult


def mail(mid, day=1, hour=10, subject=None, **sig) -> Email:
    return Email(message_id=mid, thread_id=f"t{mid}", sender_email="a@uni.edu",
                 sender_name="Someone", sender_domain="uni.edu",
                 subject=subject or f"Subject {mid}", snippet="snippet text",
                 received_at=datetime(2026, 9, day, hour),
                 signals=SenderSignals(**sig))


def tr(mid, urgency=3, category="academic") -> TriageResult:
    return TriageResult(message_id=mid, category=category, urgency=urgency,
                        requires_action=urgency >= 4, reason="reason text",
                        confidence=0.9, source="model")


def ids(pairs):
    return [e.message_id for e, _ in pairs]


# ------------------------------------------------------------ build_sync_summary

def test_counts_new_important_and_suspicious():
    items = [(mail("a"), tr("a", 5)), (mail("b"), tr("b", 4)),
             (mail("c"), tr("c", 2)), (mail("d"), tr("d", 5, "suspicious"))]
    s = build_sync_summary(items)
    assert (s.new, s.important, len(s.suspicious)) == (4, 3, 1)


def test_suspicious_listed_first_and_all_of_them():
    items = [(mail(f"s{i}", hour=i), tr(f"s{i}", 1, "suspicious")) for i in range(7)]
    items.append((mail("x"), tr("x", 5)))
    s = build_sync_summary(items)
    assert len(s.suspicious) == 7, "every suspicious email is shown, uncapped"
    assert ids(s.suspicious) == [f"s{i}" for i in range(6, -1, -1)], "newest first"
    assert ids(s.listed)[:7] == ids(s.suspicious)


def test_top_is_capped_at_five_by_urgency():
    items = [(mail(f"m{u}"), tr(f"m{u}", u)) for u in (1, 2, 3, 4, 5)]
    items += [(mail("n5"), tr("n5", 5)), (mail("n4"), tr("n4", 4))]
    s = build_sync_summary(items)
    assert len(s.top) == 5
    assert [t.urgency for _, t in s.top] == [5, 5, 4, 4, 3]


def test_ties_break_newest_first():
    items = [(mail("old", day=1), tr("old", 4)), (mail("new", day=3), tr("new", 4))]
    assert ids(build_sync_summary(items).top) == ["new", "old"]


def test_no_email_appears_twice():
    items = [(mail("s"), tr("s", 5, "suspicious")), (mail("a"), tr("a", 5))]
    s = build_sync_summary(items)
    assert ids(s.listed) == ["s", "a"]


def test_untriaged_emails_rank_last():
    items = [(mail("none"), None), (mail("low"), tr("low", 1))]
    assert ids(build_sync_summary(items).top) == ["low", "none"]


def test_missing_emails_are_skipped():
    s = build_sync_summary([(None, None), (mail("a"), tr("a", 3))])
    assert s.new == 1


def test_empty_sync():
    s = build_sync_summary([])
    assert (s.new, s.important, s.suspicious, s.top) == (0, 0, [], [])


# ------------------------------------------------------------ formatting

def test_empty_summary_says_no_new_mail():
    assert "No new mail" in format_sync_summary(build_sync_summary([]))


def test_summary_text_has_counts_sections_and_numbering():
    items = [(mail("s"), tr("s", 5, "suspicious")), (mail("a"), tr("a", 5))]
    text = format_sync_summary(build_sync_summary(items))
    assert "2 new · 2 important · 1 suspicious" in text
    assert text.index("Suspicious") < text.index("Top emails")
    assert "*1\\.*" in text and "*2\\.*" in text


def test_attacker_subject_cannot_forge_layout():
    items = [(mail("a", subject="*VERIFIED* _trusted_"), tr("a", 5))]
    text = format_sync_summary(build_sync_summary(items))
    assert "*VERIFIED*" not in text


def test_notes_are_appended_and_escaped():
    text = format_sync_summary(build_sync_summary([]), ["Model unavailable — 2 left."])
    assert "Model unavailable — 2 left\\." in text


def test_open_buttons_follow_listed_order():
    items = [(mail("s"), tr("s", 5, "suspicious")), (mail("a"), tr("a", 5))]
    assert open_buttons(build_sync_summary(items)) == [
        ("Open 1", "open:s"), ("Open 2", "open:a")]


def test_open_buttons_skip_ids_too_long_for_telegram():
    long_id = "x" * 70
    items = [(mail(long_id), tr(long_id, 5))]
    assert open_buttons(build_sync_summary(items)) == []


# ------------------------------------------------------------ [Open]

from telemail.bot import TeleMailBot, format_email_details
from telemail.broker.broker import Broker
from telemail.db import Database

ALLOWED = 123456
MARKER = "SNIPPET-MUST-NOT-APPEAR"


def test_details_show_metadata_and_verdict():
    e = mail("a", spf="pass", dkim="pass", dmarc="pass", auth_source="mx.google.com")
    text = format_email_details(e, tr("a", 5))
    assert "Someone" in text and "Subject a" in text
    assert "SPF pass" in text and "urgency 5" in text and "reason text" in text


def test_details_warn_on_failed_checks_and_missing_assertion():
    text = format_email_details(mail("a", spf="fail", dmarc="fail"), None)
    assert "Failed" in text and "spf" in text
    assert "no trusted assertion" in text
    assert "Not triaged yet" in text


def test_details_never_include_snippet_or_body():
    e = mail("a").model_copy(update={"snippet": MARKER})
    assert MARKER not in format_email_details(e, tr("a", 5))


class _Reply:
    def __init__(self): self.sent = []
    async def reply_text(self, t, **kw): self.sent.append((t, kw))


def _callback_update(data, chat=ALLOWED):
    reply = _Reply()

    class Q:
        message = reply
        async def answer(self, *a, **kw): pass
        async def edit_message_text(self, *a, **kw):
            raise AssertionError("[Open] must not overwrite the summary")

    q = Q(); q.data = data
    update = type("U", (), {"effective_chat": type("C", (), {"id": chat})(),
                            "callback_query": q})()
    return update, reply


@pytest.fixture
def open_env():
    db = Database(":memory:")
    db.insert_email(mail("m1").model_copy(update={"snippet": MARKER}))
    db.upsert_triage(tr("m1", 5))
    return db, TeleMailBot("tok", ALLOWED, db=db, broker=Broker(db, None))


def test_open_replies_with_details_without_body(open_env):
    _, bot = open_env
    update, reply = _callback_update("open:m1")
    asyncio.run(bot.on_callback(update, None))
    text, kw = reply.sent[0]
    assert "Subject m1" in text and kw.get("parse_mode") == "MarkdownV2"
    assert MARKER not in text


def test_open_unknown_id_is_rejected(open_env):
    _, bot = open_env
    update, reply = _callback_update("open:does-not-exist")
    asyncio.run(bot.on_callback(update, None))
    assert "no longer" in reply.sent[0][0]


def test_open_ignores_strangers(open_env):
    _, bot = open_env
    update, reply = _callback_update("open:m1", chat=999)
    asyncio.run(bot.on_callback(update, None))
    assert reply.sent == []
