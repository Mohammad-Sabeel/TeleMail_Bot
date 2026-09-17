"""The enforcement boundary. Every rejection must be logged and no exception
may escape into the pipeline."""
from datetime import datetime

import pytest

from telemail.broker.broker import Broker, BrokerResult
from telemail.broker.intents import BrokerRejection, validate_query
from telemail.db import Database
from telemail.models import Email, SenderSignals


class FakeAdapter:
    """Read-only. Records what was asked for."""
    def __init__(self): self.calls = []
    def search(self, query, max_results):
        self.calls.append(("search", query, max_results)); return [{"id": "m1"}]
    def get_thread(self, thread_id):
        self.calls.append(("get_thread", thread_id)); return {"id": thread_id}
    def summarise(self, thread_id):
        self.calls.append(("summarise", thread_id)); return {"summary": "..."}


class FakeWriter:
    def __init__(self): self.calls = []
    def mark_read(self, message_id):
        self.calls.append(("mark_read", message_id)); return {"ok": True}
    def label_urgent(self, message_id):
        self.calls.append(("label_urgent", message_id)); return {"ok": True}


@pytest.fixture
def env():
    db = Database(":memory:")
    db.insert_email(Email(message_id="m1", thread_id="t1",
                          sender_email="a@uni.edu", sender_domain="uni.edu",
                          subject="s", snippet="x",
                          received_at=datetime(2026, 9, 1),
                          signals=SenderSignals()))
    adapter, writer = FakeAdapter(), FakeWriter()
    yield db, Broker(db, adapter, writer), adapter, writer
    db.close()


# ------------------------------------------------------------- happy path

def test_valid_search_executes_and_audits(env):
    db, broker, adapter, _ = env
    r = broker.execute({"op": "search", "query": "from:uni.edu", "max_results": 5},
                       actor="planner")
    assert r.ok and adapter.calls == [("search", "from:uni.edu", 5)]
    assert [e["event"] for e in db.audit_entries()] == \
           ["proposed", "accepted", "executed"]


def test_valid_get_thread_executes(env):
    _, broker, adapter, _ = env
    assert broker.execute({"op": "get_thread", "thread_id": "t1"},
                          actor="planner").ok
    assert adapter.calls == [("get_thread", "t1")]


# ------------------------------------ the twenty malformed proposals, audited

MALFORMED = [
    ({"op": "send_email", "to": "x@evil.example"},           "write op not on allowlist"),
    ({"op": "forward", "thread_id": "t1"},                   "forward not on allowlist"),
    ({"op": "delete", "message_id": "m1"},                   "delete not on allowlist"),
    ({"op": "trash", "message_id": "m1"},                    "trash not on allowlist"),
    ({"op": "mark_read", "message_id": "m1"},                "write op via model path"),
    ({"op": "__class__"},                                    "dunder as an op"),
    ({"op": "search"},                                       "missing required query"),
    ({"op": "get_thread"},                                   "missing thread_id"),
    ({"op": "search", "query": "x", "recipient": "e@x.com"}, "invented extra field"),
    ({"op": "search", "query": "x", "max_results": 500},     "max_results above bound"),
    ({"op": "search", "query": "x", "max_results": 0},       "max_results below bound"),
    ({"op": "search", "query": "x" * 500},                   "query over length limit"),
    ({"op": "search", "query": "rfc822msgid:x"},             "operator not permitted"),
    ({"op": "search", "query": "deleteall:true"},            "operator not permitted"),
    ({"op": "get_thread", "thread_id": "../../etc/passwd"},  "path traversal in id"),
    ({"op": "get_thread", "thread_id": "t1; DROP TABLE"},    "injection in id"),
    ({"op": "get_thread", "thread_id": "nonexistent"},       "hallucinated thread"),
    ({"op": "summarise", "thread_id": "also-not-real"},      "hallucinated thread"),
    ({"op": None},                                           "null op"),
    ({},                                                     "empty proposal"),
    ({"action": "search", "query": "x"},                     "wrong discriminator key"),
]


@pytest.mark.parametrize("raw,why", MALFORMED, ids=[w for _, w in MALFORMED])
def test_malformed_proposal_is_rejected_and_audited(env, raw, why):
    db, broker, adapter, writer = env
    r = broker.execute(raw, actor="planner")
    assert r.ok is False, why
    assert adapter.calls == [] and writer.calls == []
    events = [e["event"] for e in db.audit_entries()]
    assert events == ["proposed", "rejected"], why
    assert db.audit_entries(event="rejected")[0]["reason"]


def test_no_exception_escapes_for_any_malformed_input(env):
    _, broker, _, _ = env
    for raw, _why in MALFORMED:
        assert isinstance(broker.execute(raw, actor="planner"), BrokerResult)


def test_non_dict_proposal_is_rejected(env):
    _, broker, adapter, _ = env
    for raw in ["search", 42, None, ["op", "search"]]:
        assert broker.execute(raw, actor="planner").ok is False
    assert adapter.calls == []


# --------------------------------------------------------- query validation

@pytest.mark.parametrize("q", ["from:a@b.com", "subject:invoice newer_than:7d",
                               "is:unread has:attachment", "plain words"])
def test_allowed_queries(q):
    assert validate_query(q) == q


@pytest.mark.parametrize("q", ["rfc822msgid:x", "filename:secret", "drive:x"])
def test_forbidden_operators(q):
    with pytest.raises(BrokerRejection):
        validate_query(q)


# ------------------------------------------------- immutable action binding

def test_approved_action_runs_once(env):
    db, broker, _, writer = env
    tid = broker.register_transaction(message_id="m1", action="mark_read")
    assert broker.approve(tid, actor="user").ok
    assert writer.calls == [("mark_read", "m1")]


def test_transaction_cannot_be_replayed(env):
    _, broker, _, writer = env
    tid = broker.register_transaction(message_id="m1", action="mark_read")
    broker.approve(tid, actor="user")
    r = broker.approve(tid, actor="user")
    assert r.ok is False and "already used" in r.reason
    assert len(writer.calls) == 1


def test_unknown_transaction_is_rejected(env):
    _, broker, _, writer = env
    assert broker.approve("forged-token", actor="user").ok is False
    assert writer.calls == []


def test_model_cannot_mint_a_transaction(env):
    """register_transaction is the only route to a write, and it refuses
    anything outside the approvable union."""
    _, broker, _, writer = env
    for action in ("send_email", "delete", "search", "../mark_read"):
        with pytest.raises(BrokerRejection):
            broker.register_transaction(message_id="m1", action=action)
    assert writer.calls == []


def test_write_is_refused_when_no_service_configured(env):
    db, _, adapter, _ = env
    broker = Broker(db, adapter, write_service=None)     # the default deployment
    tid = broker.register_transaction(message_id="m1", action="mark_read")
    r = broker.approve(tid, actor="user")
    assert r.ok is False and "no write service" in r.reason


def test_approval_targets_the_bound_message_not_a_later_claim(env):
    """The target is fixed at registration. Nothing the model emits afterwards
    can redirect it."""
    db, broker, _, writer = env
    db.insert_email(Email(message_id="m2", thread_id="t2",
                          sender_email="b@uni.edu", sender_domain="uni.edu",
                          subject="s", snippet="x",
                          received_at=datetime(2026, 9, 1),
                          signals=SenderSignals()))
    tid = broker.register_transaction(message_id="m1", action="mark_read")
    broker.approve(tid, actor="user")
    assert writer.calls == [("mark_read", "m1")]         # never m2


# ------------------------------------------------------------ read_message

class ReadingAdapter(FakeAdapter):
    def read_message(self, message_id):
        self.calls.append(("read_message", message_id))
        return {"message_id": message_id, "body": "text", "attachments": [],
                "links": [], "untrusted": True}


def test_read_message_executes_and_is_audited():
    db = Database(":memory:")
    db.insert_email(Email(message_id="m1", thread_id="t1", sender_email="a@uni.edu",
                          sender_domain="uni.edu", subject="s", snippet="x",
                          received_at=datetime(2026, 9, 1), signals=SenderSignals()))
    adapter = ReadingAdapter()
    r = Broker(db, adapter).execute({"op": "read_message", "message_id": "m1"},
                                    actor="report")
    assert r.ok and r.data["body"] == "text"
    assert adapter.calls == [("read_message", "m1")]
    assert [e["event"] for e in db.audit_entries()] == ["proposed", "accepted", "executed"]


@pytest.mark.parametrize("raw,why", [
    ({"op": "read_message", "message_id": "unknown"}, "unknown message"),
    ({"op": "read_message", "message_id": "../../x"}, "path in id"),
    ({"op": "read_message"}, "missing id"),
    ({"op": "read_message", "message_id": "m1", "extra": 1}, "extra field"),
])
def test_read_message_rejections(env, raw, why):
    db, broker, adapter, _ = env
    assert broker.execute(raw, actor="planner").ok is False, why
    assert adapter.calls == []
