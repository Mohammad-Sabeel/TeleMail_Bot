"""Bot logic. The pure functions carry the security properties, so they are
tested directly; the handlers are exercised with stub updates."""
import asyncio
from datetime import datetime

import pytest

from telemail.bot import (TeleMailBot, build_buttons, escape_md, format_alert,
                          format_search_results, is_authorised)
from telemail.broker.broker import Broker
from telemail.db import Database
from telemail.models import Email, SenderSignals, TriageResult

ALLOWED = 123456


def mail(subject="Thesis draft", sender="a@uni.edu", **sig) -> Email:
    return Email(message_id="m1", thread_id="t1", sender_email=sender,
                 sender_name="Dr Supervisor", sender_domain=sender.split("@")[1],
                 subject=subject, snippet="x", received_at=datetime(2026, 9, 1),
                 signals=SenderSignals(**sig))


def verdict(urgency=5, category="academic", source="model") -> TriageResult:
    return TriageResult(message_id="m1", category=category, urgency=urgency,
                        requires_action=True, reason="Deadline this week",
                        confidence=0.9, source=source)


class FakeAdapter:
    def search(self, query, max_results): return [{"subject": "S", "sender": "a@b.c"}]
    def get_thread(self, thread_id): return {}
    def summarise(self, thread_id): return {}


@pytest.fixture
def env():
    db = Database(":memory:")
    db.insert_email(mail())
    yield db, Broker(db, FakeAdapter())


# ---------------------------------------------------------- authorisation

@pytest.mark.parametrize("chat,ok", [(ALLOWED, True), (str(ALLOWED), True),
                                     (999, False), (None, False), (0, False)])
def test_allowlist(chat, ok):
    assert is_authorised(chat, ALLOWED) is ok


def test_unauthorised_update_is_dropped_and_audited(env):
    db, broker = env
    bot = TeleMailBot("tok", ALLOWED, db=db, broker=broker)

    class U:
        effective_chat = type("C", (), {"id": 999})()
    assert bot._guard(U()) is False
    assert len(db.audit_entries(event="unauthorised_update")) == 1


def test_every_handler_guards_first(env):
    """A stranger must not reach any command, including /status."""
    db, broker = env
    bot = TeleMailBot("tok", ALLOWED, db=db, broker=broker)
    calls = []

    class Msg:
        async def reply_text(self, *a, **kw): calls.append(a)

    class U:
        effective_chat = type("C", (), {"id": 999})()
        message = Msg()
        callback_query = None

    class Ctx:
        args = ["anything"]

    asyncio.run(bot.on_status(U(), Ctx()))
    asyncio.run(bot.on_ask(U(), Ctx()))
    assert calls == [], "an unauthorised chat received a reply"


# --------------------------------------------------------------- escaping

@pytest.mark.parametrize("raw", ["a_b", "a*b", "a[b]", "a`b", "a.b", "a!b",
                                 "a-b", "a(b)", "a|b", "a>b"])
def test_markdown_specials_are_escaped(raw):
    out = escape_md(raw)
    assert all(out[i - 1] == "\\" for i, c in enumerate(out)
               if c in r"_*[]()~`>#+-=|{}.!" and i > 0)


def test_crafted_subject_cannot_forge_the_alert_layout():
    """The subject is attacker-authored. Unescaped, it could fake our own
    labels — spoofing the interface rather than the mail."""
    evil = "*VERIFIED* _trusted sender_\n*From:* ceo@bank.com"
    out = format_alert(mail(subject=evil), verdict())
    assert "*VERIFIED*" not in out
    assert out.count("*From:*") == 1, "attacker injected a second From line"


def test_escaping_survives_none_and_empty():
    assert escape_md(None) == "" and escape_md("") == ""


# ----------------------------------------------------------- alert content

def test_alert_shows_failed_checks():
    out = format_alert(mail(spf="fail", dkim="fail", auth_source="mx.google.com"),
                       verdict(5, "suspicious"))
    assert "Failed checks" in out and "spf" in out


def test_alert_warns_when_no_trusted_assertion():
    assert "No trusted authentication assertion" in format_alert(mail(), verdict())


def test_alert_marks_fallback_verdicts():
    out = format_alert(mail(), verdict(source="fallback"))
    assert "surfaced by default" in out


def test_search_results_render_and_cap():
    rows = [{"subject": f"S{i}", "sender": "a@b.c"} for i in range(30)]
    assert format_search_results(rows).count("•") == 10
    assert format_search_results([]) == "_No matching messages_"


# ------------------------------------------------------ callback binding

def test_buttons_carry_a_token_not_a_message_id(env):
    db, broker = env
    buttons = build_buttons(broker, mail(), verdict(5))
    assert buttons, "no actions registered"
    for b in buttons:
        assert "m1" not in b.token, "callback data leaks the target id"
        assert db.get_transaction(b.token)["message_id"] == "m1"


def test_low_urgency_gets_fewer_actions(env):
    _, broker = env
    assert len(build_buttons(broker, mail(), verdict(5))) == 2
    assert len(build_buttons(broker, mail(), verdict(2))) == 1


def test_callback_approves_through_the_broker(env):
    db, broker = env
    token = build_buttons(broker, mail(), verdict(5))[0].token
    bot = TeleMailBot("tok", ALLOWED, db=db, broker=broker)
    replies = []

    class Q:
        data = f"tx:{token}"
        async def answer(self): pass
        async def edit_message_text(self, t): replies.append(t)

    class U:
        effective_chat = type("C", (), {"id": ALLOWED})()
        callback_query = Q()

    asyncio.run(bot.on_callback(U(), None))
    # no write service configured, so the broker refuses — and says so
    assert replies and "Rejected" in replies[0]


def test_forged_callback_token_is_rejected(env):
    db, broker = env
    bot = TeleMailBot("tok", ALLOWED, db=db, broker=broker)
    replies = []

    class Q:
        data = "tx:forged-token"
        async def answer(self): pass
        async def edit_message_text(self, t): replies.append(t)

    class U:
        effective_chat = type("C", (), {"id": ALLOWED})()
        callback_query = Q()

    asyncio.run(bot.on_callback(U(), None))
    assert "Rejected" in replies[0] and "unknown transaction" in replies[0]


def test_malformed_callback_data_is_rejected(env):
    db, broker = env
    bot = TeleMailBot("tok", ALLOWED, db=db, broker=broker)
    replies = []

    class Q:
        data = "mark_read:m1"          # what a naive design would have sent
        async def answer(self): pass
        async def edit_message_text(self, t): replies.append(t)

    class U:
        effective_chat = type("C", (), {"id": ALLOWED})()
        callback_query = Q()

    asyncio.run(bot.on_callback(U(), None))
    assert "Unrecognised" in replies[0]


# ----------------------------------------------------------------- /ask

# ------------------------------------------------- interactive commands

class _Msg:
    def __init__(self, text=""): self.text, self.sent = text, []
    async def reply_text(self, t, **kw): self.sent.append(t)


def _update(chat=ALLOWED, text=""):
    msg = _Msg(text)
    return type("U", (), {"effective_chat": type("C", (), {"id": chat})(),
                          "message": msg, "callback_query": None})(), msg


def _ctx(*args):
    return type("Ctx", (), {"args": list(args)})()


@pytest.fixture
def bot_env(env):
    db, broker = env
    from telemail.models import TriageResult
    db.upsert_triage(TriageResult(message_id="m1", category="academic",
                                  urgency=5, requires_action=True,
                                  reason="deadline", confidence=0.9,
                                  source="model"))
    return db, TeleMailBot("tok", ALLOWED, db=db, broker=broker,
                           adapter=FakeAdapter())


def test_start_lists_what_works_without_a_model(bot_env):
    _, bot = bot_env
    u, msg = _update()
    asyncio.run(bot.on_start(u, None))
    for cmd in ("/recent", "/urgent", "/suspicious", "/search", "/status"):
        assert cmd in msg.sent[0]


def test_recent_lists_messages(bot_env):
    _, bot = bot_env
    u, msg = _update()
    asyncio.run(bot.on_recent(u, _ctx()))
    assert "Thesis draft" in msg.sent[0]


def test_recent_honours_a_count(bot_env):
    db, bot = bot_env
    u, msg = _update()
    asyncio.run(bot.on_recent(u, _ctx("1")))
    assert msg.sent[0].count("·") >= 1


def test_urgent_shows_high_urgency_only(bot_env):
    db, bot = bot_env
    u, msg = _update()
    asyncio.run(bot.on_urgent(u, None))
    assert "Thesis draft" in msg.sent[0]


def test_suspicious_is_empty_on_a_clean_inbox(bot_env):
    _, bot = bot_env
    u, msg = _update()
    asyncio.run(bot.on_suspicious(u, None))
    assert "No authentication failures" in msg.sent[0]


def test_user_search_still_crosses_the_broker(bot_env):
    """Complete mediation means complete — a human's search is validated and
    audited exactly like a model's."""
    db, bot = bot_env
    u, msg = _update()
    asyncio.run(bot.on_search(u, _ctx("from:uni.edu")))
    assert [e["event"] for e in db.audit_entries()][-3:] == \
           ["proposed", "accepted", "executed"]


def test_user_search_with_a_forbidden_operator_is_rejected(bot_env):
    db, bot = bot_env
    u, msg = _update()
    asyncio.run(bot.on_search(u, _ctx("rfc822msgid:x")))
    assert "Rejected" in msg.sent[0]
    assert db.audit_entries(event="rejected")


def test_plain_text_is_routed_to_ask(bot_env):
    _, bot = bot_env
    u, msg = _update(text="what is urgent today")
    asyncio.run(bot.on_text(u, None))
    assert "OPENROUTER_API_KEY" in msg.sent[0]      # no planner configured


def test_ask_without_a_key_explains_what_does_work(bot_env):
    db, bot = bot_env

    class NoKeyPlanner:
        api_key = ""
    bot.planner = NoKeyPlanner()
    u, msg = _update()
    asyncio.run(bot.on_ask(u, _ctx("anything")))
    assert "/recent" in msg.sent[0] and "OPENROUTER_API_KEY" in msg.sent[0]


def test_interactive_commands_all_guard(bot_env):
    _, bot = bot_env
    for handler, ctx in ((bot.on_start, None), (bot.on_recent, _ctx()),
                         (bot.on_urgent, None), (bot.on_suspicious, None),
                         (bot.on_search, _ctx("x"))):
        u, msg = _update(chat=999)
        asyncio.run(handler(u, ctx))
        assert msg.sent == [], f"{handler.__name__} replied to a stranger"
