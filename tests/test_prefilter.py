"""Prefilter rules — especially the two orderings the report depends on."""
from datetime import datetime
from pathlib import Path

import pytest

from telemail.models import Email, SenderSignals
from telemail.triage.prefilter import (PrefilterConfig, decision_share,
                                       matches_security_terms, prefilter)

FIXTURES = Path("fixtures/own")
VIP = PrefilterConfig(vip_senders={"supervisor@uni.edu"}, vip_domains={"uni.edu"})


def mail(sender="someone@example.com", subject="Lunch on Friday",
         unsub=False, **sig) -> Email:
    return Email(message_id="m1", thread_id="t1", sender_email=sender,
                 sender_name="Someone", sender_domain=sender.split("@")[1],
                 subject=subject, snippet="...",
                 received_at=datetime(2026, 9, 1), is_direct=True,
                 has_list_unsubscribe=unsub,
                 signals=SenderSignals(**sig))


# ------------------------------------------------ ordering 1: auth beats VIP

def test_spoofed_vip_is_suspicious_not_important():
    """The ordering that matters most. A message forging a priority sender is
    the attack; if the VIP rule ran first it would award urgency 5 and a
    trusted framing to the forgery."""
    e = mail(sender="supervisor@uni.edu", spf="fail", dkim="fail", dmarc="fail")
    r = prefilter(e, VIP)
    assert r.category == "suspicious"
    assert r.source == "prefilter"
    assert "authentication failed" in r.reason.lower()


def test_genuine_vip_is_important():
    r = prefilter(mail(sender="supervisor@uni.edu", spf="pass", dkim="pass",
                       dmarc="pass"), VIP)
    assert r.category == "personal" and r.urgency == 5 and r.confidence == 1.0


def test_vip_by_domain():
    assert prefilter(mail(sender="registry@uni.edu"), VIP).urgency == 5


# --------------------------------------- absence of evidence is not evidence

def test_spf_none_does_not_trigger_suspicion():
    """Many legitimate small senders publish no SPF record. Flagging them is
    the false positive the recall argument says costs most."""
    assert prefilter(mail(spf="none", dkim="none", dmarc="none")) is None


def test_single_failure_is_not_enough():
    """A lone dkim=fail happens to legitimate mail modified in transit."""
    assert prefilter(mail(dkim="fail")) is None


def test_two_failures_are_enough():
    r = prefilter(mail(spf="fail", dmarc="fail"))
    assert r.category == "suspicious" and r.urgency == 5


def test_reason_names_the_corroborating_signals():
    r = prefilter(mail(spf="fail", dmarc="fail", display_name_mismatch=True,
                       reply_to_differs=True))
    assert "display_name_mismatch" in r.reason and "reply_to_differs" in r.reason


# ------------------------------- ordering 2: security terms beat unsubscribe

def test_breach_notice_with_unsubscribe_is_deferred_not_filed_as_bulk():
    """A genuine breach notice usually carries List-Unsubscribe, because it
    left through the same bulk mailer as the newsletters."""
    e = mail(subject="Security alert: unusual sign-in to your account", unsub=True)
    assert prefilter(e) is None, "suppressed a security notice as bulk mail"


def test_ordinary_bulk_mail_is_promotional():
    r = prefilter(mail(subject="50% off everything this weekend", unsub=True))
    assert r.category == "promotional" and r.urgency == 1


@pytest.mark.parametrize("subject", [
    "Your password was changed", "Verify your identity",
    "Invoice 1042 overdue", "Account suspended", "Wire transfer confirmation",
    "Unauthorized login attempt", "Your OTP code",
])
def test_security_vocabulary_defers_to_the_model(subject):
    assert prefilter(mail(subject=subject, unsub=True)) is None


@pytest.mark.parametrize("subject", [
    "Lunch on Friday", "Reading group notes", "Photos from the trip",
])
def test_ordinary_subjects_do_not_match(subject):
    assert matches_security_terms(subject, PrefilterConfig()) is False


# ------------------------------------------------------------ machine senders

def test_no_reply_is_a_notification():
    r = prefilter(mail(sender="no-reply@service.example"))
    assert r.category == "notification" and r.requires_action is False


def test_spoofed_no_reply_is_still_suspicious():
    r = prefilter(mail(sender="no-reply@service.example", spf="fail", dmarc="fail"))
    assert r.category == "suspicious"


# ------------------------------------------------------------------- deferral

def test_ordinary_mail_is_deferred():
    assert prefilter(mail()) is None


def test_every_verdict_is_sourced_prefilter():
    cases = [mail(spf="fail", dmarc="fail"),
             mail(sender="supervisor@uni.edu"),
             mail(subject="Sale", unsub=True),
             mail(sender="noreply@x.example")]
    for e in cases:
        r = prefilter(e, VIP)
        assert r is not None and r.source == "prefilter"


# --------------------------------------------------------------- calibration

@pytest.mark.skipif(not list(FIXTURES.glob("*.eml")),
                    reason="run scripts.harvest_corpus first")
def test_decision_share_on_fixtures_is_reported():
    from telemail.gmail.normalise import from_eml_path
    emails = [from_eml_path(f, own_address="you@example.invalid")
              for f in sorted(FIXTURES.glob("*.eml"))]
    stats = decision_share(emails)
    assert stats["total"] == len(emails)
    assert 0.0 <= stats["share"] <= 1.0
