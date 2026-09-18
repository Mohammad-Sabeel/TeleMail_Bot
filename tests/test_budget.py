from datetime import datetime, timedelta, timezone

import pytest

from telemail.budget import Budget, BudgetExceeded

NOW = datetime(2026, 9, 18, 10, 0, tzinfo=timezone.utc)


def test_spending_accumulates(tmp_path):
    b = Budget(tmp_path / "b.json", daily_tokens=100, now=lambda: NOW)
    b.spend(30, 20)
    assert b.used_today() == 50
    assert b.exhausted is False


def test_passing_the_ceiling_raises(tmp_path):
    b = Budget(tmp_path / "b.json", daily_tokens=100, now=lambda: NOW)
    b.spend(60, 30)
    with pytest.raises(BudgetExceeded):
        b.spend(20, 0)


def test_the_ceiling_resets_the_next_day(tmp_path):
    clock = [NOW]
    b = Budget(tmp_path / "b.json", daily_tokens=100, now=lambda: clock[0])
    b.spend(90, 0)
    clock[0] = NOW + timedelta(days=1)
    assert b.used_today() == 0
    b.spend(90, 0)


def test_usage_survives_a_restart(tmp_path):
    path = tmp_path / "b.json"
    Budget(path, daily_tokens=100, now=lambda: NOW).spend(40, 0)
    assert Budget(path, daily_tokens=100, now=lambda: NOW).used_today() == 40


def test_a_corrupt_file_does_not_crash_the_bot(tmp_path):
    path = tmp_path / "b.json"
    path.write_text("{not json")
    assert Budget(path, now=lambda: NOW).used_today() == 0


def test_planner_charges_the_budget_after_a_call(tmp_path, monkeypatch):
    from telemail.triage.planner import OpenRouterPlanner

    b = Budget(tmp_path / "b.json", daily_tokens=1000, now=lambda: NOW)
    planner = OpenRouterPlanner("key", "some-model")
    planner.budget = b
    monkeypatch.setattr(planner, "_post", lambda *a, **k: (
        {"answer": "ok"}, {"prompt_tokens": 100, "completion_tokens": 50}))
    planner.ask_json("system", "prompt")
    assert b.used_today() == 150


def test_planner_refuses_once_the_budget_is_gone(tmp_path, monkeypatch):
    from telemail.triage.planner import OpenRouterPlanner

    b = Budget(tmp_path / "b.json", daily_tokens=10, now=lambda: NOW)
    b.spend(10, 0)
    planner = OpenRouterPlanner("key", "some-model")
    planner.budget = b
    monkeypatch.setattr(planner, "_post", lambda *a, **k: (
        {"answer": "ok"}, {"prompt_tokens": 1, "completion_tokens": 1}))
    assert planner.ask_json("system", "prompt") == {"error": "budget exhausted"}


def test_sync_caps_how_many_emails_are_read():
    from telemail.bot import TeleMailBot
    from telemail.broker.broker import Broker
    from telemail.db import Database

    db = Database(":memory:")
    bot = TeleMailBot("tok", 1, db=db, broker=Broker(db, None))
    bot.max_reads_per_sync = 3
    assert bot._reads_allowed([f"m{i}" for i in range(10)]) == [f"m{i}" for i in range(3)]
