"""Adapter behaviour, and the read-only property asserted structurally."""
import ast
import base64
import pathlib

import pytest

from telemail.gmail.adapter import (MAX_BODY_CHARS, GmailReadAdapter,
                                    extract_body)
from telemail.gmail.auth import FORBIDDEN_SCOPES, SCOPES


def b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode()


class FakeService:
    """Mimics the googleapiclient builder chain and records every call."""

    def __init__(self, responses: dict):
        self.responses, self.calls = responses, []

    def users(self): return self
    def messages(self): return _Endpoint(self, "messages")
    def threads(self): return _Endpoint(self, "threads")
    def history(self): return _Endpoint(self, "history")
    def getProfile(self, **kw): return _Exec(self, ("getProfile", kw))

    # Write endpoints exist on the real API. If the adapter ever reaches for
    # one, these record it and the tests below fail.
    def send(self, **kw): return _Exec(self, ("send", kw))
    def trash(self, **kw): return _Exec(self, ("trash", kw))
    def modify(self, **kw): return _Exec(self, ("modify", kw))
    def delete(self, **kw): return _Exec(self, ("delete", kw))


class _Endpoint:
    def __init__(self, svc, name): self.svc, self.name = svc, name
    def __getattr__(self, op):
        def call(**kw): return _Exec(self.svc, (f"{self.name}.{op}", kw))
        return call


class _Exec:
    def __init__(self, svc, record): self.svc, self.record = svc, record
    def execute(self):
        self.svc.calls.append(self.record)
        return self.svc.responses.get(self.record[0], {})


MSG = {"id": "m1", "threadId": "t1", "snippet": "a snippet",
       "payload": {"headers": [{"name": "Subject", "value": "Hello"},
                               {"name": "From", "value": "a@uni.edu"},
                               {"name": "Date", "value": "Tue, 1 Sep 2026 10:00:00 +0000"}]}}


@pytest.fixture
def adapter():
    return GmailReadAdapter(FakeService({
        "messages.list": {"messages": [{"id": "m1"}]},
        "messages.get": MSG,
        "threads.get": {"messages": [MSG]},
    }))


# --------------------------------------------------------- read-only proof

def test_adapter_class_exposes_no_write_methods():
    """Not disabled — absent. `dir()` is the whole allowlist."""
    forbidden = {"send", "send_email", "trash", "delete", "modify",
                 "insert", "batchModify", "batchDelete", "reply", "forward",
                 "mark_read", "label"}
    assert forbidden & set(dir(GmailReadAdapter)) == set()


def test_no_write_endpoint_is_ever_called(adapter):
    adapter.search("from:uni.edu")
    adapter.get_thread("t1")
    adapter.summarise("t1")
    called = {c[0] for c in adapter._service.calls}
    assert not any(w in name for name in called
                   for w in ("send", "trash", "delete", "modify", "insert"))


def test_scope_is_readonly_only():
    assert SCOPES == ["https://www.googleapis.com/auth/gmail.readonly"]
    assert not set(SCOPES) & FORBIDDEN_SCOPES


def test_source_contains_no_forbidden_scope_string():
    """A widened scope must not creep in anywhere in the package."""
    for path in pathlib.Path("telemail").rglob("*.py"):
        text = path.read_text()
        for scope in FORBIDDEN_SCOPES:
            assert scope not in text or path.name == "auth.py", \
                f"{path} references {scope}"


def test_only_auth_and_adapter_import_the_google_sdk():
    holders = set()
    for path in pathlib.Path("telemail").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            if any(m.startswith(("googleapiclient", "google.oauth2",
                                 "google_auth_oauthlib", "google.auth"))
                   for m in mods):
                holders.add(path.name)
    assert holders <= {"auth.py", "adapter.py"}, holders


# ------------------------------------------------------------- read paths

def test_search_returns_metadata_without_bodies(adapter):
    rows = adapter.search("from:uni.edu", max_results=5)
    assert rows[0]["subject"] == "Hello" and rows[0]["message_id"] == "m1"
    assert "body" not in rows[0], "search must not expose bodies"


def test_search_requests_metadata_format_only(adapter):
    adapter.search("x")
    gets = [kw for name, kw in adapter._service.calls if name == "messages.get"]
    assert all(kw["format"] == "metadata" for kw in gets)


def test_search_honours_max_results(adapter):
    adapter.search("x", max_results=3)
    listing = [kw for n, kw in adapter._service.calls if n == "messages.list"][0]
    assert listing["maxResults"] == 3


def test_get_thread_has_no_bodies(adapter):
    out = adapter.get_thread("t1")
    assert out["thread_id"] == "t1"
    assert "body" not in out["messages"][0]


def test_summarise_is_the_only_path_that_reads_bodies():
    svc = FakeService({"threads.get": {"messages": [
        {"id": "m1", "payload": {"mimeType": "text/plain",
                                 "headers": [{"name": "Subject", "value": "S"}],
                                 "body": {"data": b64("the full body text")}}}]}})
    out = GmailReadAdapter(svc).summarise("t1")
    assert out["messages"][0]["body"] == "the full body text"
    assert out["untrusted"] is True, "consumers must know this is attacker-authored"
    assert [kw["format"] for n, kw in svc.calls if n == "threads.get"] == ["full"]


# ---------------------------------------------------------- body decoding

def test_prefers_text_plain_over_html():
    payload = {"mimeType": "multipart/alternative", "parts": [
        {"mimeType": "text/html", "body": {"data": b64("<b>html</b>")}},
        {"mimeType": "text/plain", "body": {"data": b64("plain wins")}}]}
    assert extract_body(payload) == "plain wins"


def test_falls_back_to_html_when_no_plain_part():
    payload = {"mimeType": "multipart/alternative", "parts": [
        {"mimeType": "text/html", "body": {"data": b64("<b>only html</b>")}}]}
    assert "only html" in extract_body(payload)


def test_attachments_are_skipped():
    payload = {"mimeType": "multipart/mixed", "parts": [
        {"mimeType": "text/plain", "filename": "payload.txt",
         "body": {"data": b64("INSTRUCTIONS INSIDE ATTACHMENT")}},
        {"mimeType": "text/plain", "body": {"data": b64("real body")}}]}
    assert extract_body(payload) == "real body"


def test_body_is_truncated():
    payload = {"mimeType": "text/plain", "body": {"data": b64("x" * 50_000)}}
    assert len(extract_body(payload)) == MAX_BODY_CHARS


def test_undecodable_body_returns_empty_not_crash():
    payload = {"mimeType": "text/plain", "body": {"data": "!!!not base64!!!"}}
    assert extract_body(payload) == ""


def test_missing_payload_is_safe():
    assert extract_body({}) == ""


# ---------------------------------------------------- 404 on a message fetch

class _HttpErr(Exception):
    def __init__(self, status):
        self.resp = type("R", (), {"status": status})()


class _RaisingService(FakeService):
    def __init__(self, status):
        super().__init__({})
        self.status = status

    def messages(self):
        svc = self

        class _E:
            def get(self, **kw):
                class _X:
                    def execute(self_inner):
                        raise _HttpErr(svc.status)
                return _X()
        return _E()


def test_fetch_of_deleted_message_raises_message_gone():
    from telemail.gmail.adapter import MessageGone
    with pytest.raises(MessageGone):
        GmailReadAdapter(_RaisingService(404)).fetch_metadata("gone-id")


def test_other_http_errors_are_not_mistaken_for_deletion():
    from telemail.gmail.adapter import MessageGone
    with pytest.raises(_HttpErr):
        GmailReadAdapter(_RaisingService(500)).fetch_metadata("x")


# ------------------------------------------------------------ read_message

FULL = {"id": "m1", "payload": {"mimeType": "multipart/mixed", "parts": [
    {"mimeType": "multipart/alternative", "parts": [
        {"mimeType": "text/plain",
         "body": {"data": b64("Pay now at https://198.51.100.7/login please")}},
        {"mimeType": "text/html",
         "body": {"data": b64('<p>Visit <a href="https://evil.example/x">www.uni.edu</a> '
                              'or <a href="https://xn--pypal-4ve.com">here</a></p>')}}]},
    {"mimeType": "application/octet-stream", "filename": "invoice.html",
     "body": {"attachmentId": "a1"}}]}}


def test_read_message_returns_body_attachments_and_links():
    out = GmailReadAdapter(FakeService({"messages.get": FULL})).read_message("m1")
    assert out["body"].startswith("Pay now") and out["untrusted"] is True
    assert out["attachments"] == ["invoice.html"]
    hrefs = {l["href"] for l in out["links"]}
    assert {"https://198.51.100.7/login", "https://evil.example/x",
            "https://xn--pypal-4ve.com"} <= hrefs
    shown = [l for l in out["links"] if l["href"] == "https://evil.example/x"][0]
    assert shown["text"] == "www.uni.edu"


def test_read_message_uses_full_format():
    svc = FakeService({"messages.get": FULL})
    GmailReadAdapter(svc).read_message("m1")
    assert [kw["format"] for n, kw in svc.calls if n == "messages.get"] == ["full"]


def test_read_message_of_deleted_message_raises_message_gone():
    from telemail.gmail.adapter import MessageGone
    with pytest.raises(MessageGone):
        GmailReadAdapter(_RaisingService(404)).read_message("gone")


def test_links_from_malformed_html_do_not_raise():
    from telemail.gmail.adapter import extract_links
    payload = {"mimeType": "text/html", "body": {"data": b64("<a href='x'>unclosed <b")}}
    assert isinstance(extract_links(payload), list)
