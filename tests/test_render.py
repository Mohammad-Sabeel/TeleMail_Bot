"""results.md is published; the inbox it is measured on is not."""
from eval import render


def test_false_negatives_show_the_sender_domain_only(monkeypatch):
    fake = {"n_test": 1, "threshold": 2,
            "conditions": {"hybrid": {"tp": 0, "fp": 0, "fn": 1, "tn": 0}},
            "false_negatives": [{"source": "prefilter", "urgency": 1,
                                 "sender": "someone@bank.example",
                                 "subject": "Your OTP is 4821"}]}
    monkeypatch.setattr(render, "load", lambda name: fake)
    out = render.triage_section()
    assert "bank.example" in out
    assert "someone@" not in out and "OTP" not in out
