import csv

from eval.goals import Goal
from eval.render import goals_section
from eval.run_goals import _cap_total, _select_cases, load_cases, parse_args


def test_defaults_are_the_safe_ones():
    args = parse_args([])
    assert args.split == "dev", "the test split is touched once, on purpose"
    assert args.ablation == "full"
    assert args.limit == 0, "no cap by default; --limit opts into a cheap run"
    assert args.cases == "both", "today's behaviour unchanged by default"


def test_split_choice_is_validated():
    import pytest
    with pytest.raises(SystemExit):
        parse_args(["--split", "everything"])


def test_cases_choice_is_validated():
    import pytest
    with pytest.raises(SystemExit):
        parse_args(["--cases", "everything"])


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


def test_load_cases_fixtures_source_is_the_projects_own_pool_not_llmail():
    """--source fixtures must read fixtures/own/, the in-distribution
    baseline, never the held-out fixtures/llmail/ pool."""
    attack, control = load_cases("fixtures", "dev")
    assert len(attack) == 33
    assert len(control) == 33
    assert all(isinstance(goal, Goal) for goal, _email, _body in attack)


def test_load_cases_fixtures_source_ignores_split():
    """fixtures/own/ carries no split header; every fixture is available
    regardless of --split."""
    dev_attack, dev_control = load_cases("fixtures", "dev")
    test_attack, test_control = load_cases("fixtures", "test")
    assert len(dev_attack) == len(test_attack)
    assert len(dev_control) == len(test_control)


def test_cap_total_caps_the_combined_count_not_each_list():
    attack = list(range(10))
    control = list(range(10))
    a, c = _cap_total(attack, control, 6)
    assert len(a) + len(c) == 6


def test_cap_total_zero_means_no_cap():
    attack = list(range(3))
    control = list(range(4))
    a, c = _cap_total(attack, control, 0)
    assert (a, c) == (attack, control)


def test_select_cases_attack_drops_every_control():
    attack, control = load_cases("llmail", "dev")
    a, c = _select_cases(attack, control, "attack")
    assert len(a) == 70, "the real frozen dev-split attack count"
    assert c == []


def test_select_cases_control_drops_every_attack():
    attack, control = load_cases("llmail", "dev")
    a, c = _select_cases(attack, control, "control")
    assert a == []
    assert len(c) == 17, "the real frozen dev-split control count"


def test_select_cases_both_is_unchanged():
    attack, control = load_cases("llmail", "dev")
    a, c = _select_cases(attack, control, "both")
    assert (a, c) == (attack, control)


def test_cases_control_with_limit_yields_exactly_that_many_control_cases():
    """--cases control --limit 12 must spend the whole limit on controls —
    not zero, the way a plain --limit does once attacks eat the quota."""
    attack, control = load_cases("llmail", "dev")
    a, c = _select_cases(attack, control, "control")
    a, c = _cap_total(a, c, 12)
    assert len(a) + len(c) == 12
    assert len(c) == 12
    assert a == []
