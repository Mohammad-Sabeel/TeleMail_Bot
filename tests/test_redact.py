from datetime import datetime, timezone

from telemail.bot import escape_md, format_answer
from telemail.redact import HIDDEN, redact
from telemail.report import ReportEntry, SyncReport, render_pdf
from telemail.triage.assess import Level

SECRETS = [
    ("Dear Student, Your new password is Xqv@7305 -- Network Admin", "Xqv@7305"),
    ("password: hunter2", "hunter2"),
    ("Password - S3cure!pass", "S3cure!pass"),
    ("Your Recovery Code - 909410", "909410"),
    ("Your code is: 482913. Use it to sign in", "482913"),
    ("Verification code 771204 (expires in 10 minutes)", "771204"),
    ("OTP for txn is 5521", "5521"),
    ("one-time passcode=889900", "889900"),
    ("Your PIN: 7788", "7788"),
]

KEEP = [
    "Request for Student Email Password Reset",
    "kindly reset the password for my student email account",
    "we have attached the password-protected PDF document",
    "Please read our code of conduct",
    "A friend sent you money: Rs 1,250",
    "Example Nagar New Delhi - 110001",
    "Passkey added to your account",
]


def test_hides_each_secret():
    for text, secret in SECRETS:
        out = redact(text)
        assert secret not in out, text
        assert HIDDEN in out, text


def test_keeps_ordinary_mentions():
    for text in KEEP:
        assert redact(text) == text


def test_every_markdown_message_is_redacted():
    assert "7305" not in escape_md("new password is Xqv@7305")


def test_answer_with_a_password_is_redacted():
    msg = format_answer("The admin set your new password is Xqv@7305.", [])
    assert "Xqv@7305" not in msg and "hidden" in msg


def test_report_pdf_text_is_redacted(tmp_path):
    from telemail import report
    assert "909410" not in report._clean("Recovery Code - 909410", True)
    entry = ReportEntry("m1", "a@b.c", "Recovery Code - 909410",
                        datetime(2026, 9, 17, tzinfo=timezone.utc), 1, Level.NONE,
                        [], "No reply needed", "Gives code 909410")
    path = render_pdf(SyncReport(datetime(2026, 9, 17), [], [], [entry], []),
                      tmp_path / "r.pdf", font_path="")
    assert path.exists()
