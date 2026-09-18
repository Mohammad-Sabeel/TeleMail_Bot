import csv

from eval.goals import Goal
from eval.render import goals_section
from eval.run_goals import load_cases, parse_args


def test_defaults_are_the_safe_ones():
    args = parse_args([])
    assert args.split == "dev", "the test split is touched once, on purpose"
    assert args.ablation == "full"
    assert args.limit == 0, "no cap by default; --limit opts into a cheap run"


def test_split_choice_is_validated():
    import pytest
    with pytest.raises(SystemExit):
        parse_args(["--split", "everything"])


def test_goals_section_renders_a_table(tmp_path, monkeypatch):
    path = tmp_path / "goal_results.csv"
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["goal", "arm", "won", "source", "split",
                                           "ablation", "answer", "invoked"])
        w.writeheader()
        w.writerow({"goal": "G3", "arm": "naive", "won": "True", "source": "llmail",
                    "split": "dev", "ablation": "full", "answer": "", "invoked": ""})
        w.writerow({"goal": "G3", "arm": "mediated", "won": "False", "source": "llmail",
                    "split": "dev", "ablation": "full", "answer": "", "invoked": ""})
    monkeypatch.setattr("eval.render.GOAL_RESULTS", path)
    section = goals_section()
    assert "G3" in section and "naive" in section and "mediated" in section


def test_goals_section_is_none_without_a_run(tmp_path, monkeypatch):
    monkeypatch.setattr("eval.render.GOAL_RESULTS", tmp_path / "missing.csv")
    assert goals_section() is None


def test_load_cases_reads_the_frozen_llmail_fixtures():
    """The manifest is frozen (BUILD_PLAN Stage 1 freeze); these counts are the
    split's real attack/control tally and should not drift."""
    attack, control = load_cases("llmail", "dev")
    assert len(attack) == 70
    assert len(control) == 17
    assert all(isinstance(goal, Goal) for goal, _email, _body in attack)


def test_load_cases_assigns_goals_round_robin():
    attack, _control = load_cases("llmail", "dev")
    seen = {goal for goal, _email, _body in attack}
    assert seen == set(Goal), "every goal should get coverage, not just the first"
