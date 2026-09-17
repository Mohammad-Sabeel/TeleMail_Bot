"""Hide passwords and one-time codes before any text leaves for Telegram or the PDF.

Deterministic, applied at the output edge (bot.escape_md, report._clean), so no
answer, subject or gist can repeat a secret that sits in an email. It does not stop
the model from seeing the secret; it stops the secret reaching the chat.

ponytail: keyword-anchored regex. Misses secrets with no nearby keyword and may hide
an ordinary word after "password is"; hiding too much is the safe failure.
"""
from __future__ import annotations

import re

HIDDEN = "[hidden, open the email in Gmail]"

_KEY = (r"\b(?:(?:verification|recovery|security|login|confirmation|access|one[- ]time)\s+)?"
        r"(?:password|passcode|passwd|pwd|pin|otp|code)\b")
_TOKEN = r"(\S+)"
_PATTERNS = [
    # keyword, separator, any token: "password is X", "code: X", "Code - X"
    re.compile(_KEY + r"(?:\s+\w+){0,3}?(?:\s*[:=]\s*|\s+[-–]\s+|\s+is:?\s+)" + _TOKEN, re.I),
    # keyword directly followed by a token containing a digit: "code 771204"
    re.compile(_KEY + r"\s+(\S*\d\S*)", re.I),
]


def _hide(m: re.Match) -> str:
    token = m.group(1)
    core = token.rstrip(".,;:)")
    if not core:
        return m.group(0)
    start = m.start(1) - m.start(0)
    return m.group(0)[:start] + HIDDEN + token[len(core):]


def redact(text: str) -> str:
    for pattern in _PATTERNS:
        text = pattern.sub(_hide, text)
    return text
