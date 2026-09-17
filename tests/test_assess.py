"""Feature C verdict layers."""
from datetime import datetime

import pytest

from telemail.models import Email, SenderSignals
from telemail.triage.assess import Level, deterministic_evidence, link_evidence


def mail(**sig) -> Email:
    return Email(message_id="m1", thread_id="t1", sender_email="a@uni.edu",
                 sender_name="Registrar", sender_domain="uni.edu", subject="Fees",
                 snippet="x", received_at=datetime(2026, 9, 16),
                 signals=SenderSignals(**sig))


def read(links=(), attachments=(), body="Hello"):
    return {"body": body, "links": list(links), "attachments": list(attachments)}


# ------------------------------------------------------------ layer 1

def test_clean_email_has_no_evidence():
    assert deterministic_evidence(mail(first_contact=False), read()) == (Level.NONE, [])


def test_two_auth_failures_are_a_threat_one_is_not():
    level, ev = deterministic_evidence(mail(spf="fail", dmarc="fail"), read())
    assert level is Level.THREAT and "SPF, DMARC failed" in ev
    assert deterministic_evidence(mail(dkim="fail", first_contact=False), read())[0] is Level.NONE


def test_display_name_mismatch_is_caution():
    assert deterministic_evidence(mail(display_name_mismatch=True), read())[0] is Level.CAUTION


def test_reply_to_differs_only_counts_on_first_contact():
    """Measured: 20% of real read mail has a different Reply-To (mailing lists)."""
    assert deterministic_evidence(mail(reply_to_differs=True, first_contact=False),
                                  read())[0] is Level.NONE
    assert deterministic_evidence(mail(reply_to_differs=True, first_contact=True),
                                  read())[0] is Level.CAUTION


@pytest.mark.parametrize("link,expected", [
    ({"text": "https://198.51.100.7/x", "href": "https://198.51.100.7/x"}, "raw IP address"),
    ({"text": "here", "href": "https://xn--pypal-4ve.com"}, "punycode"),
    ({"text": "www.uni.edu", "href": "https://evil.example/login"},
     "link text shows uni.edu but goes to evil.example"),
])
def test_suspicious_links(link, expected):
    assert any(expected in e for e in link_evidence([link]))


@pytest.mark.parametrize("link", [
    {"text": "Click here", "href": "https://uni.edu/portal"},
    {"text": "portal.uni.edu", "href": "https://portal.uni.edu/x"},
    {"text": "uni.edu", "href": "https://mail.uni.edu/x"},
    {"text": "https://uni.edu/a", "href": "https://uni.edu/a"},
    {"text": "support@uni.edu", "href": "mailto:support@uni.edu"},
])
def test_ordinary_links_raise_nothing(link):
    assert link_evidence([link]) == []


def test_risky_attachment_is_caution_ordinary_is_not():
    assert deterministic_evidence(mail(first_contact=False),
                                  read(attachments=["Invoice.HTML"]))[0] is Level.CAUTION
    assert deterministic_evidence(mail(first_contact=False),
                                  read(attachments=["notes.pdf"]))[0] is Level.NONE


def test_unreadable_email_still_gets_header_checks():
    assert deterministic_evidence(mail(spf="fail", dkim="fail"), None)[0] is Level.THREAT

