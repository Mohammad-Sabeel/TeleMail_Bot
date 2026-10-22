"""results/README.md is published; the inbox it is measured on is not."""
from eval import render


def test_false_negatives_are_counted_never_named(monkeypatch):
    fake = {"n_test": 1, "threshold": 2,
            "conditions": {"hybrid": {"tp": 0, "fp": 0, "fn": 1, "tn": 0}},
            "false_negatives": [{"source": "prefilter", "urgency": 1,
                                 "sender": "someone@bank.example",
                                 "subject": "Your OTP is 4821"}]}
    monkeypatch.setattr(render, "load", lambda name, base=None: fake)
    out = render.triage_section()
    assert "missed by `prefilter`: 1" in out
    assert "bank.example" not in out and "someone" not in out and "OTP" not in out
