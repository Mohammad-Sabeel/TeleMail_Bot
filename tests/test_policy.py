"""Alert policy — a pure function, so every branch is trivially pinned."""
from datetime import datetime

import pytest

from telemail.models import Email, SenderSignals, TriageResult
from telemail.policy import (AlertPolicy, in_quiet_hours, next_quiet_end,
                             should_alert)

NOON = datetime(2026, 9, 1, 12, 0)
MIDNIGHT = datetime(2026, 9, 1, 23, 30)
VIP = AlertPolicy(vip_senders=frozenset({"supervisor@uni.edu"}))


def mail(sender="someone@example.com") -> Email:
    return Email(message_id="m1", thread_id="t1", sender_email=sender,
                 sender_domain=sender.split("@")[1], subject="s", snippet="x",
                 received_at=NOON, signals=SenderSignals())


def verdict(urgency=5, category="academic", source="model") -> TriageResult:
    return TriageResult(message_id="m1", category=category, urgency=urgency,
                        requires_action=True, reason="r", confidence=0.9,
                        source=source)


# ------------------------------------------------------------- thresholds

def test_high_urgency_alerts():
    assert should_alert(verdict(5), mail(), now=NOON).alert is True


def test_low_urgency_does_not():
    d = should_alert(verdict(2), mail(), now=NOON)
    assert d.alert is False and "below" in d.reason


# ---------------------------------------------------- security overrides

def test_suspicious_overrides_quiet_hours():
    d = should_alert(verdict(5, "suspicious"), mail(), now=MIDNIGHT)
    assert d.alert is True and "overrides" in d.reason


def test_suspicious_overrides_the_daily_cap():
    d = should_alert(verdict(5, "suspicious"), mail(), now=NOON, sent_today=999)
    assert d.alert is True


def test_suspicious_overrides_a_low_urgency_score():
    """A manipulated urgency must not be able to silence a spoofing verdict."""
    assert should_alert(verdict(1, "suspicious"), mail(), now=NOON).alert is True


# ------------------------------------------------------------ quiet hours

@pytest.mark.parametrize("hour,quiet", [(23, True), (0, True), (6, True),
                                        (7, False), (12, False), (22, False)])
def test_quiet_window_wraps_midnight(hour, quiet):
    assert in_quiet_hours(datetime(2026, 9, 1, hour), AlertPolicy()) is quiet


def test_quiet_hours_defer_rather_than_drop():
    """Dropping loses a message; deferring delays it."""
    d = should_alert(verdict(5), mail(), now=MIDNIGHT)
    assert d.alert is False and d.deferred is True
    assert d.defer_until == datetime(2026, 9, 2, 7, 0)


def test_defer_target_is_the_same_morning_when_before_midnight():
    d = should_alert(verdict(5), mail(), now=datetime(2026, 9, 1, 2, 0))
    assert d.defer_until == datetime(2026, 9, 1, 7, 0)


def test_vip_bypasses_quiet_hours():
    d = should_alert(verdict(5), mail("supervisor@uni.edu"), now=MIDNIGHT,
                     policy=VIP)
    assert d.alert is True and d.reason == "priority sender"


# --------------------------------------------------------------- the cap

def test_daily_cap_suppresses_and_defers():
    d = should_alert(verdict(5), mail(), now=NOON, sent_today=20)
    assert d.alert is False and d.deferred is True and "cap" in d.reason


def test_vip_bypasses_the_cap():
    assert should_alert(verdict(5), mail("supervisor@uni.edu"), now=NOON,
                        sent_today=99, policy=VIP).alert is True


def test_under_the_cap_alerts():
    assert should_alert(verdict(5), mail(), now=NOON, sent_today=19).alert is True


# ------------------------------------------------------------- fallback

def test_fallback_verdicts_are_surfaced_not_swallowed():
    """source=fallback means the model could not be trusted to have answered.
    Recall over precision: surface it."""
    d = should_alert(verdict(3, source="fallback"), mail(), now=NOON)
    assert d.alert is True


def test_fallback_can_be_turned_off():
    p = AlertPolicy(alert_on_fallback=False)
    assert should_alert(verdict(3, source="fallback"), mail(), now=NOON,
                        policy=p).alert is False


# --------------------------------------------------------------- purity

def test_policy_is_deterministic_and_side_effect_free():
    args = (verdict(5), mail())
    a = should_alert(*args, now=NOON, sent_today=3)
    b = should_alert(*args, now=NOON, sent_today=3)
    assert a == b


def test_vip_newsletter_is_still_a_newsletter():
    d = should_alert(verdict(1, "promotional"), mail("supervisor@uni.edu"),
                     now=NOON, policy=VIP)
    assert d.alert is True and d.reason == "priority sender"
