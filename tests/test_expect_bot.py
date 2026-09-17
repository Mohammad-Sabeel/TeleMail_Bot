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
