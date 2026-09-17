"""Normalisation, tested against the real adversarial fixtures on disk."""
from datetime import datetime
from pathlib import Path

import pytest

from telemail.db import Database
from telemail.gmail.normalise import (_display_name_mismatch, from_eml_bytes,
                                      from_eml_path, from_gmail_payload)

FIXTURES = Path("data/fixtures")
has_fixtures = pytest.mark.skipif(not list(FIXTURES.glob("*.eml")),
                                  reason="run scripts.harvest_corpus first")

GENUINE = b"""Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
From: Dr Supervisor <supervisor@uni.edu>
To: student@uni.edu
Reply-To: supervisor@uni.edu
Subject: Thesis draft
Date: Tue, 01 Sep 2026 10:00:00 +0000
Message-ID: <abc123@uni.edu>

Can you send the draft by Friday?
"""

SPOOFED = b"""Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
From: "helpdesk@uni.edu" <attacker@evil.example>
To: student@uni.edu
Reply-To: collect@elsewhere.example
Subject: Account suspended
Date: Tue, 01 Sep 2026 11:00:00 +0000
Message-ID: <spoof@evil.example>

Verify immediately.
"""


# ------------------------------------------------------------------- basics

def test_headers_become_fields():
    e = from_eml_bytes(GENUINE, own_address="student@uni.edu")
    assert e.message_id == "abc123@uni.edu"
    assert e.sender_email == "supervisor@uni.edu"
    assert e.sender_name == "Dr Supervisor"
    assert e.sender_domain == "uni.edu"
    assert e.subject == "Thesis draft"
    assert e.is_direct is True
    assert e.received_at == datetime.fromisoformat("2026-09-01T10:00:00+00:00")
    assert "draft by Friday" in e.snippet


def test_genuine_auth_is_read():
    s = from_eml_bytes(GENUINE).signals
    assert (s.spf, s.dkim, s.dmarc) == ("pass", "pass", "pass")
    assert s.auth_source == "mx.google.com"
    assert s.failed_checks() == []


def test_spoof_is_caught_on_three_independent_signals():
    s = from_eml_bytes(SPOOFED).signals
    assert (s.spf, s.dkim, s.dmarc) == ("fail", "fail", "fail")
    assert s.display_name_mismatch is True     # claims uni.edu, sent from evil.example
    assert s.reply_to_differs is True
    assert set(s.failed_checks()) >= {"spf", "dkim", "dmarc",
                                      "display_name_mismatch", "reply_to_differs"}


def test_is_direct_false_when_only_cc():
    raw = GENUINE.replace(b"To: student@uni.edu", b"To: someone@else.example")
    assert from_eml_bytes(raw, own_address="student@uni.edu").is_direct is False


def test_missing_message_id_falls_back_to_content_hash():
    raw = GENUINE.replace(b"Message-ID: <abc123@uni.edu>\n", b"")
    a = from_eml_bytes(raw)
    b = from_eml_bytes(raw)
    assert a.message_id == b.message_id and len(a.message_id) == 40


def test_thread_id_follows_the_references_root():
    raw = GENUINE.replace(b"Subject:", b"References: <root@uni.edu> <mid@uni.edu>\nSubject:")
    assert from_eml_bytes(raw).thread_id == "root@uni.edu"


# ------------------------------------------------- display-name mismatch rule

@pytest.mark.parametrize("display,domain,expected", [
    ("helpdesk@uni.edu", "evil.example", True),      # address in the name, wrong domain
    ("uni.edu Support", "evil.example", True),       # domain in the name, wrong domain
    ("Dr Supervisor", "uni.edu", False),             # ordinary name
    ("IT Helpdesk", "gmail.com", False),             # generic name is not evidence
    ("support@uni.edu", "uni.edu", False),           # consistent
    ("", "uni.edu", False),
])
def test_display_name_rule(display, domain, expected):
    assert _display_name_mismatch(display, domain) is expected


# ----------------------------------------------------- first contact via db

def test_first_contact_is_true_then_false():
    db = Database(":memory:")
    first = from_eml_bytes(GENUINE, db=db)
    assert first.signals.first_contact is True
    assert first.signals.sender_message_count == 0
    db.insert_email(first)

    second = from_eml_bytes(GENUINE.replace(b"<abc123@uni.edu>", b"<def456@uni.edu>"),
                            db=db)
    assert second.signals.first_contact is False
    assert second.signals.sender_message_count == 1
    db.close()


# --------------------------------------------------------- the real fixtures

@has_fixtures
def test_every_fixture_normalises():
    for f in sorted(FIXTURES.glob("*.eml")):
        e = from_eml_path(f, own_address="you@example.invalid")
        assert e.message_id and e.sender_domain and e.subject
        assert e.is_direct is True


@has_fixtures
def test_T11_forged_header_yields_no_trusted_assertion():
    """End to end: the attacker's own Authentication-Results must not survive
    normalisation as a passed check."""
    e = from_eml_path(FIXTURES / "T11_v1.eml")
    assert e.signals.auth_source == ""          # nothing we trust asserted anything
    assert e.signals.spf == "none"              # NOT "pass" — the forgery is discarded
    assert "spf" not in e.signals.failed_checks()   # unknown is not failed


@has_fixtures
def test_T8_snippet_truncates_but_body_is_long():
    e = from_eml_path(FIXTURES / "T8_v1.eml")
    assert len(e.snippet) <= 200
    assert e.has_list_unsubscribe is False


# -------------------------------------------------------- gmail payload path

def test_gmail_payload_normalises_identically():
    payload = {"id": "17a2b", "threadId": "t99", "snippet": "Can you send the draft",
               "labelIds": ["INBOX", "UNREAD"],
               "payload": {"headers": [
                   {"name": "From", "value": "Dr Supervisor <supervisor@uni.edu>"},
                   {"name": "To", "value": "student@uni.edu"},
                   {"name": "Subject", "value": "Thesis draft"},
                   {"name": "Date", "value": "Tue, 01 Sep 2026 10:00:00 +0000"},
                   {"name": "Authentication-Results",
                    "value": "mx.google.com; spf=pass; dkim=pass; dmarc=pass"}]}}
    e = from_gmail_payload(payload, own_address="student@uni.edu")
    ref = from_eml_bytes(GENUINE, own_address="student@uni.edu")

    assert e.message_id == "17a2b" and e.thread_id == "t99"
    assert e.labels == ["INBOX", "UNREAD"]
    # the fields that must agree across both sources
    for field in ("sender_email", "sender_domain", "sender_name", "subject",
                  "is_direct", "received_at"):
        assert getattr(e, field) == getattr(ref, field), field
    assert e.signals == ref.signals
