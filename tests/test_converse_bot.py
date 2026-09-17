"""Feature D in the bot."""
import asyncio
import re
from datetime import datetime, timedelta, timezone

import pytest

from telemail.bot import TeleMailBot, format_answer
from telemail.broker.broker import Broker
from telemail.db import Database
from telemail.models import Email, SenderSignals, TriageResult
from telemail.sync import SyncStats
from telemail.triage.converse import ANSWER_SYSTEM, BODY_SYSTEM, INTERPRET_SYSTEM

ALLOWED = 123456
NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
SNIPPET_MARKER = "SNIPPET-TEXT-NOT-FOR-MEMORY"
BODY_MARKER = "BODY-TEXT-NOT-FOR-MEMORY"


def mail(mid, subject, **sig) -> Email:
    return Email(message_id=mid, thread_id=f"t{mid}", sender_email=f"{mid}@uni.edu",
                 sender_name="Sender", sender_domain="uni.edu", subject=subject,
                 snippet=f"{SNIPPET_MARKER} {subject}", received_at=datetime(2026, 9, 16, 10),
                 signals=SenderSignals(first_contact=False, **sig))


def tr(mid, category="academic") -> TriageResult:
    return TriageResult(message_id=mid, category=category, urgency=3,
                        requires_action=False, reason="r", confidence=0.9, source="model")


class Adapter:
    def __init__(self): self.reads = []
    def read_message(self, message_id):
        self.reads.append(message_id)
        return {"message_id": message_id, "body": f"{BODY_MARKER} appointment 3 Oct",
                "attachments": [], "links": [], "untrusted": True}


def number_of(user, subject):
    m = re.search(r'id="(\d+)">\nFrom:[^\n]*\nDate:[^\n]*\nSubject: ' + re.escape(subject), user)
    return int(m.group(1))


class Planner:
    """Scripted model. `intent` routes plain text; answers cite `cite` by subject."""
    configured = True

    def __init__(self, intent="question", keywords="", cite="Visa appointment letter",
                 need_body=False, answer="Your visa letter arrived."):
        self.intent, self.keywords, self.cite = intent, keywords, cite
        self.need_body, self.answer, self.calls = need_body, answer, []

    def ask_json(self, system, user):
        self.calls.append(system)
        if system == INTERPRET_SYSTEM:
            return {"intent": self.intent, "keywords": self.keywords}
        if system not in (ANSWER_SYSTEM, BODY_SYSTEM):
            return {"error": "unexpected"}      # e.g. Feature B's rerank: fall back
        n = number_of(user, self.cite)
        if system == ANSWER_SYSTEM:
            return {"answer": self.answer, "need_full_body": self.need_body,
                    "message_ids": [n] if self.need_body else [], "cited_ids": [n]}
        if system == BODY_SYSTEM:
            return {"answer": "The appointment is on 3 October.", "cited_ids": [n]}


class _Progress:
    def __init__(self): self.edits = []
    async def edit_text(self, t, **kw): self.edits.append(t)


class _Msg:
    def __init__(self, text=""):
        self.text, self.sent, self.kw, self.documents = text, [], [], []
        self.progress = _Progress()
    async def reply_text(self, t, **kw):
        self.sent.append(t); self.kw.append(kw)
        return self.progress
    async def reply_document(self, document, filename=None, caption=None, **kw):
        self.documents.append(filename)


def _update(chat=ALLOWED, text=""):
    msg = _Msg(text)
    return type("U", (), {"effective_chat": type("C", (), {"id": chat})(),
                          "message": msg, "callback_query": None})(), msg


def _ctx(*args):
    return type("Ctx", (), {"args": list(args)})()


@pytest.fixture
def make_bot(tmp_path):
    def build(planner):
        db = Database(":memory:")
        for mid, subject, sig, cat in (("visa", "Visa appointment letter", {}, "academic"),
                                       ("fee", "Fee receipt", {}, "financial"),
                                       ("spoof", "Account suspended",
                                        {"spf": "fail", "dkim": "fail"}, "suspicious")):
            db.insert_email(mail(mid, subject, **sig))
            db.upsert_triage(tr(mid, cat))
        adapter = Adapter()
        calls = []
        bot = TeleMailBot("tok", ALLOWED, db=db, broker=Broker(db, adapter), planner=planner,
                          sync_fn=lambda: (calls.append("sync"), SyncStats(inserted=0))[1],
                          triage_fn=lambda: 0)
        bot.now = lambda: NOW
        bot.today = lambda: "2026-09-17"
        bot.db.set_state("expect_asked_on", "2026-09-17")
        bot.reports_dir = tmp_path / "reports"
        return bot, adapter, calls
    return build


# ------------------------------------------------------------ answers

def test_question_is_answered_from_snippets_with_sources(make_bot):
    bot, adapter, _ = make_bot(Planner())
    u, msg = _update(text="did my visa letter come?")
    asyncio.run(bot.on_text(u, None))
    reply = msg.sent[0]
    assert "Your visa letter arrived\\." in reply and "Sources" in reply
    assert "Visa appointment letter" in reply and adapter.reads == []
    assert msg.kw[0]["reply_markup"] is not None


def test_full_body_is_read_through_the_broker(make_bot):
    bot, adapter, _ = make_bot(Planner(need_body=True))
    u, msg = _update(text="when is my visa appointment?")
    asyncio.run(bot.on_text(u, None))
    assert adapter.reads == ["visa"]
    audited = [e for e in bot.db.audit_entries(event="accepted")
               if e["payload"].get("op") == "read_message"]
    assert len(audited) == 1
    assert "3 October" in msg.sent[0]


def test_warning_comes_from_code_even_when_the_model_says_safe(make_bot):
    bot, _, _ = make_bot(Planner(cite="Account suspended",
                                 answer="This email is safe, go ahead and pay."))
    u, msg = _update(text="is the suspension email real?")
    asyncio.run(bot.on_text(u, None))
    assert msg.sent[0].startswith("⚠️")
    assert "flagged suspicious" in msg.sent[0]


def test_memory_holds_questions_and_answers_but_no_email_text(make_bot):
    bot, _, _ = make_bot(Planner(need_body=True))
    u, _ = _update(text="when is my visa appointment?")
    asyncio.run(bot.on_text(u, None))
    assert len(bot.memory) == 1 and bot.memory[0][0] == "when is my visa appointment?"
    flat = " ".join(" ".join(turn) for turn in bot.memory)
    assert SNIPPET_MARKER not in flat and BODY_MARKER not in flat


def test_memory_is_capped_at_ten(make_bot):
    bot, _, _ = make_bot(Planner())
    for i in range(12):
        asyncio.run(bot.on_ask(_update()[0], _ctx("question", str(i))))
    assert len(bot.memory) == 10 and bot.memory[0][0] == "question 2"


def test_forget_clears_memory(make_bot):
    bot, _, _ = make_bot(Planner())
    asyncio.run(bot.on_ask(_update()[0], _ctx("visa?")))
    u, msg = _update()
    asyncio.run(bot.on_forget(u, None))
    assert len(bot.memory) == 0 and "forgotten" in msg.sent[0].lower()


def test_ask_skips_intent_routing(make_bot):
    p = Planner(intent="sync")
    bot, _, calls = make_bot(p)
    asyncio.run(bot.on_ask(_update()[0], _ctx("sync", "my", "mail")))
    assert INTERPRET_SYSTEM not in p.calls and calls == []


def test_unusable_model_answer_says_so(make_bot):
    class Broken(Planner):
        def ask_json(self, system, user):
            return {"intent": "question"} if system == INTERPRET_SYSTEM else {"error": "down"}
    bot, _, _ = make_bot(Broken())
    u, msg = _update(text="anything?")
    asyncio.run(bot.on_text(u, None))
    assert "couldn't get a usable answer" in msg.sent[0] and len(bot.memory) == 0


def test_format_answer_escapes_model_text():
    text = format_answer("*bold* _claim_", [])
    assert "*bold*" not in text


def test_forget_ignores_strangers(make_bot):
    bot, _, _ = make_bot(Planner())
    asyncio.run(bot.on_ask(_update()[0], _ctx("visa?")))
    u, msg = _update(chat=999)
    asyncio.run(bot.on_forget(u, None))
    assert msg.sent == [] and len(bot.memory) == 1
