from datetime import datetime, timezone

from telemail.indicators import add_indicator, load_indicators, match_indicators
from telemail.models import Email, SenderSignals
from telemail.triage.assess import Level, assess_email

LIST = """
# domains and phrases I have seen in attacks
bit.ly
verify-your-account.example
Ignore previous instructions
attacker@evil.test
"""


def _write(tmp_path, text=LIST):
    path = tmp_path / "indicators.txt"
    path.write_text(text)
    return path


def _email(**kw) -> Email:
    base = dict(message_id="m1", thread_id="t1", sender_email="a@b.c", sender_name="A",
                sender_domain="b.c", subject="Hello", snippet="nothing special",
                received_at=datetime(2026, 9, 18, tzinfo=timezone.utc),
                signals=SenderSignals())
    return Email(**{**base, **kw})


def test_loads_entries_ignoring_comments_and_blanks(tmp_path):
    assert load_indicators(_write(tmp_path)) == [
        "bit.ly", "verify-your-account.example", "ignore previous instructions",
        "attacker@evil.test"]


def test_missing_file_is_not_an_error(tmp_path):
    assert load_indicators(tmp_path / "nope.txt") == []


def test_matches_are_case_insensitive_and_listed_once():
    found = match_indicators("Please IGNORE PREVIOUS INSTRUCTIONS and ignore previous "
                             "instructions again", ["ignore previous instructions"])
    assert found == ["ignore previous instructions"]


def test_special_characters_are_matched_literally():
    assert match_indicators("see http://bit.ly/x", ["bit.ly"]) == ["bit.ly"]
    assert match_indicators("see bitXly", ["bit.ly"]) == []


def test_indicator_in_the_body_makes_it_a_threat():
    verdict = assess_email(_email(), None,
                           {"body": "click http://bit.ly/abc now", "links": [],
                            "attachments": []},
                           planner=None, indicators=["bit.ly"])
    assert verdict.level is Level.THREAT
    assert any("bit.ly" in e for e in verdict.evidence)


def test_indicator_in_sender_or_subject_counts():
    verdict = assess_email(_email(sender_email="attacker@evil.test"), None,
                           {"body": "hi", "links": [], "attachments": []},
                           planner=None, indicators=["attacker@evil.test"])
    assert verdict.level is Level.THREAT


def test_no_indicator_leaves_the_verdict_alone():
    verdict = assess_email(_email(), None,
                           {"body": "an ordinary email", "links": [], "attachments": []},
                           planner=None, indicators=["bit.ly"])
    assert verdict.level is Level.NONE


def test_add_indicator_appends_and_refuses_duplicates(tmp_path):
    path = _write(tmp_path)
    assert add_indicator(path, "  New-Phrase  ") is True
    assert "new-phrase" in load_indicators(path)
    assert add_indicator(path, "new-phrase") is False
    assert load_indicators(path).count("new-phrase") == 1


def test_add_indicator_creates_the_file(tmp_path):
    path = tmp_path / "sub" / "indicators.txt"
    assert add_indicator(path, "evil.test") is True
    assert load_indicators(path) == ["evil.test"]


def test_add_indicator_refuses_blank_and_very_short(tmp_path):
    path = _write(tmp_path)
    assert add_indicator(path, "   ") is False
    assert add_indicator(path, "a") is False


# --------------------------------------------------------------- /flag command

def _bot(tmp_path):
    import asyncio  # noqa: F401  (used by the callers below)

    from telemail.bot import TeleMailBot
    from telemail.broker.broker import Broker
    from telemail.db import Database

    db = Database(":memory:")
    bot = TeleMailBot("tok", 1, db=db, broker=Broker(db, None))
    bot.indicators_path = tmp_path / "indicators.txt"
    return bot


def _update(text, chat=1):
    class Msg:
        def __init__(self): self.sent = []
        async def reply_text(self, t, **kw): self.sent.append(t)
    msg = Msg()
    return type("U", (), {"effective_chat": type("C", (), {"id": chat})(),
                          "message": msg})(), msg


def test_flag_adds_an_indicator(tmp_path):
    import asyncio
    bot = _bot(tmp_path)
    update, msg = _update("/flag")
    ctx = type("C", (), {"args": ["ignore", "previous", "instructions"]})()
    asyncio.run(bot.on_flag(update, ctx))
    assert load_indicators(bot.indicators_path) == ["ignore previous instructions"]
    assert "ignore previous instructions" in msg.sent[0]


def test_flag_without_text_explains_itself(tmp_path):
    import asyncio
    bot = _bot(tmp_path)
    update, msg = _update("/flag")
    asyncio.run(bot.on_flag(update, type("C", (), {"args": []})()))
    assert "flagged" not in msg.sent[0].lower()
    assert load_indicators(bot.indicators_path) == []


def test_flag_reports_a_duplicate(tmp_path):
    import asyncio
    bot = _bot(tmp_path)
    ctx = type("C", (), {"args": ["evil.test"]})()
    asyncio.run(bot.on_flag(*[_update("/flag")[0], ctx]))
    update, msg = _update("/flag")
    asyncio.run(bot.on_flag(update, ctx))
    assert "already" in msg.sent[0].lower()


def test_flag_ignores_strangers(tmp_path):
    import asyncio
    bot = _bot(tmp_path)
    update, msg = _update("/flag", chat=999)
    asyncio.run(bot.on_flag(update, type("C", (), {"args": ["evil.test"]})()))
    assert msg.sent == [] and load_indicators(bot.indicators_path) == []
