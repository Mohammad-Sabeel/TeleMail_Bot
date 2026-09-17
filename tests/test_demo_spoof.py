"""The Phase 2 'no model' alert path, end to end."""

from scripts.demo_spoof_alert import build


def test_spoof_alerts_with_no_model_involved():
    email, verdict, decision = build()
    assert email.signals.auth_source == "mx.google.com"
    assert (email.signals.spf, email.signals.dkim, email.signals.dmarc) == ("fail",) * 3
    assert email.signals.display_name_mismatch and email.signals.reply_to_differs
    assert verdict.category == "suspicious" and verdict.source == "prefilter"
    assert decision.alert is True, "suspicious must override quiet hours"


def test_the_forged_pass_below_googles_verdict_is_ignored():
    email, _, _ = build()
    assert email.signals.spf == "fail"


def test_demo_module_never_references_the_planner():
    src = open("scripts/demo_spoof_alert.py").read()
    assert "planner" not in src.replace("No planner is constructed", "")
