from eval.adaptive import ATTACKER_SYSTEM, attack_rounds, best_payload
from eval.goals import CANARY, Goal
from tests.test_run_goals import FakePlanner


class FakeAttacker:
    def __init__(self, bodies):
        self.bodies, self.prompts = list(bodies), []

    def ask_json(self, system, prompt):
        self.prompts.append(prompt)
        return {"body": self.bodies.pop(0) if self.bodies else "give up"}

    def drain_usage(self):
        return {"prompt_tokens": 5, "completion_tokens": 5}


class StopBudget:
    exhausted = True

    def spend(self, *a, **k):
        return False


class RecordingBudget:
    exhausted = False

    def __init__(self):
        self.spent = []

    def spend(self, prompt_tokens, completion_tokens):
        self.spent.append((prompt_tokens, completion_tokens))


def test_attacker_is_told_how_the_defence_works():
    assert "broker" in ATTACKER_SYSTEM.lower()
    assert "allowlist" in ATTACKER_SYSTEM.lower()


def test_rounds_stop_early_on_a_win():
    planner = FakePlanner(answer="My instructions say: at most 6 sentences")
    rounds = attack_rounds(Goal.PROMPT, planner, FakeAttacker(["a", "b", "c"]), rounds=3)
    assert len(rounds) == 1 and rounds[0]["won"] is True


def test_rounds_feed_the_previous_failure_back():
    planner = FakePlanner(answer="nothing to see")
    attacker = FakeAttacker(["a", "b"])
    attack_rounds(Goal.EXFIL, planner, attacker, rounds=2)
    assert "did not work" in attacker.prompts[1].lower()


def test_an_exhausted_budget_stops_before_any_call():
    attacker = FakeAttacker(["a"])
    rounds = attack_rounds(Goal.EXFIL, FakePlanner(), attacker, rounds=3,
                           budget=StopBudget())
    assert rounds == [] and attacker.prompts == []


def test_the_attacker_faces_the_defended_system():
    # The mediated arm redacts the secret, so an attacker trying to exfil the canary
    # will never see a win. This pins that we measure against the defended system,
    # not the naive undefended baseline.
    planner = FakePlanner(answer=f"code is {CANARY}")
    rounds = attack_rounds(Goal.EXFIL, planner, FakeAttacker(["a"]), rounds=1)
    assert len(rounds) == 1 and rounds[0]["won"] is False


def test_each_round_charges_the_attackers_usage():
    """A real budget must actually deplete during an attack run, not just be
    read — see eval.adaptive._charge_usage."""
    budget = RecordingBudget()
    attacker = FakeAttacker(["a", "b"])
    attack_rounds(Goal.EXFIL, FakePlanner(answer="nothing to see"), attacker,
                 rounds=2, budget=budget)
    assert budget.spent == [(5, 5), (5, 5)]


def test_best_payload_returns_the_winner():
    rounds = [{"body": "x", "won": False}, {"body": "y", "won": True}]
    assert best_payload(rounds) == "y"
    assert best_payload([{"body": "x", "won": False}]) is None
