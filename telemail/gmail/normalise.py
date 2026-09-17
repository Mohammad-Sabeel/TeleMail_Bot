"""Raw message -> Email + SenderSignals.

Two entry points, one core. `from_eml_bytes` reads RFC 5322 off disk (the
adversarial fixtures, and anything you export from a mailbox);
`from_gmail_payload` reads the Gmail API's metadata response. Both produce the
identical `Email`, which is why the pipeline can be built and tested against
fixtures before OAuth exists.

Everything here is deterministic. No model is involved, and nothing in this
module can reach a mailbox.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from telemail.gmail.headers import parse_auth_results
from telemail.models import Email, SenderSignals

SNIPPET_CHARS = 200
_DOMAINISH = re.compile(r"[\w.-]+\.(?:com|org|net|edu|gov|io|co|uk|edu\.\w+)\b", re.I)


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower() if "@" in address else ""


def _header_pairs(msg: EmailMessage) -> list[tuple[str, str]]:
    return [(k, str(v)) for k, v in msg.items()]


def _display_name_mismatch(display: str, sender_domain: str) -> bool:
    """True when the display name asserts an identity the address contradicts.

    `"IT Helpdesk" <random@gmail.com>` alone is not enough — plenty of
    legitimate mail looks like that. We flag only when the display name itself
    contains an address or a domain that disagrees with the real one, which is
    the spoofing pattern rather than a naming style.
    """
    if not display:
        return False
    low = display.lower()
    if "@" in low:
        claimed = _domain(low)
        return bool(claimed) and claimed != sender_domain
    m = _DOMAINISH.search(low)
    if m:
        claimed = m.group(0).lower()
        return claimed != sender_domain and not sender_domain.endswith("." + claimed)
    return False


def _body_text(msg: EmailMessage) -> str:
    if not msg.is_multipart():
        try:
            return msg.get_content()
        except Exception:
            return ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain" and \
                "attachment" not in str(part.get("Content-Disposition", "")):
            try:
                return part.get_content()
            except Exception:
                continue
    return ""


def _snippet(text: str, limit: int = SNIPPET_CHARS) -> str:
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _has_attachment(msg: EmailMessage) -> bool:
    return any("attachment" in str(p.get("Content-Disposition", "")).lower()
               for p in msg.walk()) if msg.is_multipart() else False


def _thread_id(msg: EmailMessage, fallback: str) -> str:
    """.eml has no Gmail thread id. The root of the References chain is the
    closest equivalent and keeps replies grouped, which matters because the
    held-out split must be by thread, not by message."""
    refs = str(msg.get("References", "")).split()
    if refs:
        return refs[0].strip("<>")
    irt = str(msg.get("In-Reply-To", "")).strip().strip("<>")
    return irt or fallback


def build_signals(headers: list[tuple[str, str]], sender_email: str,
                  sender_name: str | None, *, db=None,
                  message_id: str | None = None) -> SenderSignals:
    auth = parse_auth_results(headers)
    sender_domain = _domain(sender_email)

    reply_to = dict((k.lower(), v) for k, v in headers).get("reply-to", "")
    reply_addrs = [a for _, a in getaddresses([reply_to])] if reply_to else []
    reply_differs = bool(reply_addrs) and _domain(reply_addrs[0]) != sender_domain

    count = 0
    if db is not None and sender_domain:
        count = db.sender_history(sender_domain, exclude=message_id)

    return SenderSignals(
        spf=auth["spf"], dkim=auth["dkim"], dmarc=auth["dmarc"],
        auth_source=auth["auth_source"],
        display_name_mismatch=_display_name_mismatch(sender_name or "", sender_domain),
        reply_to_differs=reply_differs,
        first_contact=(count == 0),
        sender_message_count=count)


def from_message(msg: EmailMessage, *, own_address: str = "",
                 message_id: str | None = None, thread_id: str | None = None,
                 snippet: str | None = None, labels: list[str] | None = None,
                 db=None) -> Email:
    headers = _header_pairs(msg)

    mid = (message_id or str(msg.get("Message-ID", "")).strip().strip("<>")
           or hashlib.sha1(bytes(msg)).hexdigest())

    froms = getaddresses([str(msg.get("From", ""))])
    sender_name, sender_email = (froms[0] if froms else ("", ""))
    sender_email = sender_email.lower()

    recipients = {a.lower() for _, a in getaddresses([str(msg.get("To", ""))])}

    try:
        received = parsedate_to_datetime(str(msg.get("Date", "")))
    except (TypeError, ValueError):
        received = None
    if received is None:
        received = datetime.now(timezone.utc)

    signals = build_signals(headers, sender_email, sender_name,
                            db=db, message_id=mid)

    return Email(
        message_id=mid,
        thread_id=thread_id or _thread_id(msg, mid),
        sender_email=sender_email,
        sender_name=sender_name or None,
        sender_domain=_domain(sender_email),
        subject=re.sub(r"\s+", " ", str(msg.get("Subject", ""))).strip() or "(no subject)",
        snippet=snippet if snippet is not None else _snippet(_body_text(msg)),
        received_at=received,
        labels=labels or [],
        is_direct=bool(own_address) and own_address.lower() in recipients,
        has_list_unsubscribe="list-unsubscribe" in {k.lower() for k, _ in headers},
        has_attachment=_has_attachment(msg),
        signals=signals)


def from_eml_bytes(raw: bytes, **kw) -> Email:
    return from_message(BytesParser(policy=policy.default).parsebytes(raw), **kw)


def from_eml_path(path, **kw) -> Email:
    from pathlib import Path
    return from_eml_bytes(Path(path).read_bytes(), **kw)


def from_gmail_payload(message: dict, *, own_address: str = "", db=None) -> Email:
    """Normalise the Gmail API `users.messages.get(format="metadata")` shape.

    The API gives headers as [{"name": ..., "value": ...}] plus its own snippet,
    ids and labels — so we synthesise a header-only message and reuse the same
    core, guaranteeing fixtures and live mail normalise identically.
    """
    msg = EmailMessage()
    for h in message.get("payload", {}).get("headers", []):
        try:
            msg[h["name"]] = h["value"]
        except ValueError:
            continue                       # malformed header, skip it
    return from_message(msg, own_address=own_address,
                        message_id=message["id"],
                        thread_id=message.get("threadId", message["id"]),
                        snippet=_snippet(message.get("snippet", "")),
                        labels=message.get("labelIds", []), db=db)
