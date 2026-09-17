"""Read-only Gmail client. The only module that talks to the mailbox.

There are no write methods here. Not disabled, not guarded by a flag — absent.
Combined with the read-only scope, that is two independent controls: even if
this file were compromised, the credential cannot send.

`summarise` is the highest-exposure operation in the system, because it is the
only one that reads full message bodies — which is where injected instructions
actually live. Triage sees a 200-character snippet and most payloads sit beyond
it. Bodies are fetched here, returned, and never persisted (D4).
"""
from __future__ import annotations

import base64
import re
from html.parser import HTMLParser
from typing import Any

class WatermarkExpired(Exception):
    """Gmail returns 404 when a historyId is older than its retention window.

    Translated here so sync.py never has to import the Google SDK — the
    boundary test asserts only this module and auth.py may.
    """


class MessageGone(Exception):
    """404 on a message id: it was deleted after appearing in history (one-time
    codes, purged spam). Permanent, so sync skips it instead of retrying."""


def _http_status(e: Exception) -> int | None:
    return getattr(getattr(e, "resp", None), "status", None)


MAX_BODY_CHARS = 8000        # cost bound and exposure bound, in that order
MAX_THREAD_MESSAGES = 20

METADATA_HEADERS = ["From", "To", "Cc", "Subject", "Date", "Reply-To",
                    "List-Unsubscribe", "Authentication-Results",
                    "References", "In-Reply-To", "Message-ID"]


def _decode(data: str | None) -> str:
    if not data:
        return ""
    try:
        return base64.urlsafe_b64decode(data.encode()).decode("utf-8", "replace")
    except Exception:
        return ""


def extract_body(payload: dict) -> str:
    """Depth-first walk for the first text/plain part, falling back to text/html.

    Attachments are skipped entirely — the project does not process them, and
    saying so is cleaner than half-supporting them.
    """
    plain, html = [], []

    def walk(part: dict) -> None:
        if len(plain) or len(html) > 4:
            return
        mime = part.get("mimeType", "")
        disposition = part.get("filename") or ""
        if disposition:
            return                                  # an attachment; skip
        if mime == "text/plain":
            plain.append(_decode(part.get("body", {}).get("data")))
            return
        if mime == "text/html":
            html.append(_decode(part.get("body", {}).get("data")))
        for child in part.get("parts", []) or []:
            walk(child)

    walk(payload)
    text = (plain[0] if plain else (html[0] if html else ""))
    return text[:MAX_BODY_CHARS]


MAX_LINKS = 50
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


def _parts(payload: dict):
    yield payload
    for child in payload.get("parts", []) or []:
        yield from _parts(child)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[dict] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append({"text": " ".join("".join(self._text).split()),
                               "href": self._href})
            self._href = None


def extract_links(payload: dict) -> list[dict]:
    """Anchors from HTML parts, bare URLs from plain parts. Attachments skipped."""
    links: list[dict] = []
    for part in _parts(payload):
        if part.get("filename"):
            continue
        data = _decode(part.get("body", {}).get("data"))
        if part.get("mimeType") == "text/html":
            parser = _LinkParser()
            try:
                parser.feed(data)
            except Exception:
                pass
            links += [link for link in parser.links if link["href"]]
        elif part.get("mimeType") == "text/plain":
            links += [{"text": url, "href": url} for url in _URL_RE.findall(data)]
    seen, out = set(), []
    for link in links:
        key = (link["text"], link["href"])
        if key not in seen:
            seen.add(key)
            out.append(link)
    return out[:MAX_LINKS]


def attachment_names(payload: dict) -> list[str]:
    return [part["filename"] for part in _parts(payload) if part.get("filename")]


class GmailReadAdapter:
    """Injected with a built service so it can be tested without a network."""

    def __init__(self, service, user_id: str = "me"):
        self._service = service
        self._user = user_id

    # ----------------------------------------------------------- read ops

    def search(self, query: str, max_results: int = 10) -> list[dict]:
        """Metadata only. No bodies, so no injection surface on this path."""
        listing = self._service.users().messages().list(
            userId=self._user, q=query, maxResults=max_results).execute()

        out = []
        for ref in listing.get("messages", [])[:max_results]:
            msg = self._service.users().messages().get(
                userId=self._user, id=ref["id"], format="metadata",
                metadataHeaders=METADATA_HEADERS).execute()
            headers = {h["name"]: h["value"]
                       for h in msg.get("payload", {}).get("headers", [])}
            out.append({"message_id": msg["id"],
                        "thread_id": msg.get("threadId", msg["id"]),
                        "subject": headers.get("Subject", ""),
                        "sender": headers.get("From", ""),
                        "date": headers.get("Date", ""),
                        "snippet": msg.get("snippet", "")})
        return out

    def get_thread(self, thread_id: str) -> dict:
        """Thread metadata. Still no bodies."""
        thread = self._service.users().threads().get(
            userId=self._user, id=thread_id, format="metadata",
            metadataHeaders=METADATA_HEADERS).execute()

        messages = []
        for msg in thread.get("messages", [])[:MAX_THREAD_MESSAGES]:
            headers = {h["name"]: h["value"]
                       for h in msg.get("payload", {}).get("headers", [])}
            messages.append({"message_id": msg["id"],
                             "subject": headers.get("Subject", ""),
                             "sender": headers.get("From", ""),
                             "date": headers.get("Date", ""),
                             "snippet": msg.get("snippet", "")})
        return {"thread_id": thread_id, "messages": messages}

    def summarise(self, thread_id: str) -> dict:
        """Full bodies. The highest-exposure read in the system.

        Everything returned here is attacker-authored and must be treated as
        data by whatever consumes it. It is not stored (D4).
        """
        thread = self._service.users().threads().get(
            userId=self._user, id=thread_id, format="full").execute()

        messages = []
        for msg in thread.get("messages", [])[:MAX_THREAD_MESSAGES]:
            headers = {h["name"]: h["value"]
                       for h in msg.get("payload", {}).get("headers", [])}
            messages.append({"message_id": msg["id"],
                             "subject": headers.get("Subject", ""),
                             "sender": headers.get("From", ""),
                             "body": extract_body(msg.get("payload", {}))})
        return {"thread_id": thread_id, "messages": messages,
                "untrusted": True}          # consumers must delimit this content

    def read_message(self, message_id: str) -> dict:
        """One message in full: body, attachment names, links. Attacker-authored,
        returned for the report and never stored (D4)."""
        try:
            msg = self._service.users().messages().get(
                userId=self._user, id=message_id, format="full").execute()
        except Exception as e:
            if _http_status(e) == 404:
                raise MessageGone(message_id) from e
            raise
        payload = msg.get("payload", {})
        return {"message_id": message_id, "body": extract_body(payload),
                "attachments": attachment_names(payload),
                "links": extract_links(payload), "untrusted": True}

    def fetch_metadata(self, message_id: str) -> dict:
        """Raw API shape for the sync path; normalise.from_gmail_payload consumes it."""
        try:
            return self._service.users().messages().get(
                userId=self._user, id=message_id, format="metadata",
                metadataHeaders=METADATA_HEADERS).execute()
        except Exception as e:
            if _http_status(e) == 404:
                raise MessageGone(message_id) from e
            raise

    def history(self, start_history_id: str, max_results: int = 500,
                page_token: str | None = None) -> dict:
        """Incremental change feed (D5: polling, not Pub/Sub push)."""
        try:
            return self._service.users().history().list(
                userId=self._user, startHistoryId=start_history_id,
                historyTypes=["messageAdded"], maxResults=max_results,
                pageToken=page_token).execute()
        except Exception as e:
            if _http_status(e) == 404:
                raise WatermarkExpired(start_history_id) from e
            raise

    def list_recent(self, max_results: int = 100, query: str = "") -> dict:
        """Full-resync fallback for an expired history watermark."""
        return self._service.users().messages().list(
            userId=self._user, q=query, maxResults=max_results).execute()

    def profile(self) -> dict[str, Any]:
        return self._service.users().getProfile(userId=self._user).execute()
