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


def test_a_spend_that_crosses_the_ceiling_is_still_recorded(tmp_path):
    """Reproduces the round-1 defect: a refused spend must persist, or the
    ceiling never binds and every later call sails through unrecorded."""
    b = Budget(tmp_path / "b.json", daily_tokens=100, now=lambda: NOW)
    b.spend(90, 0)
    with pytest.raises(BudgetExceeded):
        b.spend(20, 0)
    assert b.used_today() == 110
    assert b.exhausted is True


def test_the_ceiling_stays_bound_after_crossing_it(tmp_path):
    b = Budget(tmp_path / "b.json", daily_tokens=100, now=lambda: NOW)
    b.spend(90, 0)
    with pytest.raises(BudgetExceeded):
        b.spend(20, 0)
    with pytest.raises(BudgetExceeded):
        b.spend(1, 0)


def test_a_crossed_ceiling_survives_a_restart(tmp_path):
    path = tmp_path / "b.json"
    b = Budget(path, daily_tokens=100, now=lambda: NOW)
    b.spend(90, 0)
    with pytest.raises(BudgetExceeded):
        b.spend(20, 0)
    assert Budget(path, daily_tokens=100, now=lambda: NOW).exhausted is True


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


def test_a_call_with_no_reported_usage_still_charges_an_estimate(tmp_path, monkeypatch):
    from telemail.triage.planner import OpenRouterPlanner, UNMETERED_CALL_TOKENS

    b = Budget(tmp_path / "b.json", daily_tokens=10_000, now=lambda: NOW)
    planner = OpenRouterPlanner("key", "some-model")
    planner.budget = b
    monkeypatch.setattr(planner, "_post", lambda *a, **k: ("{}", {}))
    planner.ask_json("system", "prompt")
    assert b.used_today() == UNMETERED_CALL_TOKENS


def test_sync_caps_how_many_emails_are_read():
    from telemail.bot import TeleMailBot
    from telemail.broker.broker import Broker
    from telemail.db import Database

    db = Database(":memory:")
    bot = TeleMailBot("tok", 1, db=db, broker=Broker(db, None))
    bot.max_reads_per_sync = 3
    assert bot._reads_allowed([f"m{i}" for i in range(10)]) == [f"m{i}" for i in range(3)]
