from pathlib import Path

import pytest

from eval.t11_headers import run

FIXTURES = Path("data/fixtures")


@pytest.mark.skipif(not list(FIXTURES.glob("T11_*.eml")), reason="no fixtures")
def test_t11_delivered_naive_loses_trusted_holds():
    s = run(FIXTURES)["summary"]
    assert s["delivered"]["n"] == 3
    assert s["delivered"]["naive"] == 3, "dict-collapse should trust the forgery"
    assert s["delivered"]["trusted"] == 0
    assert s["undelivered"]["trusted"] == 0   # topmost header is not Google's
