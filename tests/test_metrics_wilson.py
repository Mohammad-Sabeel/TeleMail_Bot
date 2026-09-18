import pytest

from eval.metrics import rate_line, wilson


def test_zero_successes_has_a_lower_bound_of_zero():
    low, high = wilson(0, 20)
    assert low == 0.0
    assert 0.15 < high < 0.17          # 20 clean trials still allow ~16%


def test_all_successes_has_an_upper_bound_of_one():
    low, high = wilson(20, 20)
    assert high == 1.0
    assert 0.83 < low < 0.85


def test_known_interval():
    low, high = wilson(5, 20)          # 25%
    assert low == pytest.approx(0.1103, abs=0.001)
    assert high == pytest.approx(0.4693, abs=0.001)


def test_empty_sample_is_the_whole_range():
    assert wilson(0, 0) == (0.0, 1.0)


def test_more_successes_than_trials_is_an_error():
    with pytest.raises(ValueError):
        wilson(3, 2)


def test_rate_line_reports_count_percentage_and_interval():
    line = rate_line("G1 action hijack", 5, 20)
    assert "5/20" in line and "25.0%" in line
    assert "[11.0, 46.9]" in line
