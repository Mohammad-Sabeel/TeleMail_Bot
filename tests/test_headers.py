"""T11 — forged Authentication-Results.

Header order matters and is modelled as delivered: Gmail's own verdict first,
sender-written headers below it."""
from telemail.gmail.headers import parse_auth_results, parse_auth_results_naive

GENUINE = ("Authentication-Results",
           "mx.google.com; dkim=pass header.i=@uni.edu; "
           "spf=pass (google.com: domain of x designates 1.2.3.4) smtp.mailfrom=x@uni.edu; "
           "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=uni.edu")

SPOOFED = ("Authentication-Results",
           "mx.google.com; dkim=fail header.i=@uni.edu; "
           "spf=fail (google.com: domain of x does not designate 5.6.7.8) smtp.mailfrom=x@uni.edu; "
           "dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=uni.edu")

# What an attacker writes into the message they send you.
FORGED = ("Authentication-Results",
          "attacker.example.com; spf=pass; dkim=pass; dmarc=pass")
FORGED_AS_GOOGLE = ("Authentication-Results",
                    "mx.google.com; spf=pass; dkim=pass; dmarc=pass")

# As delivered: Gmail prepends its verdict above the sender's headers.
DELIVERED_ATTACK = [SPOOFED, ("From", "ceo@uni.edu"), FORGED]


def test_genuine_header_is_read():
    r = parse_auth_results([GENUINE])
    assert (r["spf"], r["dkim"], r["dmarc"]) == ("pass", "pass", "pass")
    assert r["auth_source"] == "mx.google.com"


def test_spoofed_sender_is_detected():
    r = parse_auth_results([SPOOFED])
    assert (r["spf"], r["dkim"], r["dmarc"]) == ("fail", "fail", "fail")


def test_T11_naive_dict_collapse_trusts_the_attacker():
    """The vulnerability, demonstrated. `{name: value}` keeps the last header,
    which is the one the sender wrote. This test asserts the BAD behaviour."""
    r = parse_auth_results_naive(DELIVERED_ATTACK)
    assert r["spf"] == "pass"
    assert r["auth_source"] == "attacker.example.com"


def test_T11_trusted_parser_keeps_googles_verdict():
    r = parse_auth_results(DELIVERED_ATTACK)
    assert (r["spf"], r["dkim"], r["dmarc"]) == ("fail", "fail", "fail")
    assert r["auth_source"] == "mx.google.com"


def test_T11_forgery_claiming_google_below_the_real_header_is_ignored():
    r = parse_auth_results([SPOOFED, FORGED_AS_GOOGLE])
    assert r["spf"] == "fail"


def test_topmost_header_not_ours_means_trust_nothing():
    """Impossible for mail delivered via Gmail; fails safe to unknown."""
    r = parse_auth_results([FORGED, SPOOFED])
    assert r["auth_source"] == "" and r["spf"] == "none"


def test_no_trusted_assertion_means_unknown_not_safe():
    r = parse_auth_results([FORGED])
    assert r["auth_source"] == "" and r["spf"] == "none"


def test_arc_headers_are_not_trusted():
    r = parse_auth_results([("ARC-Authentication-Results", GENUINE[1])])
    assert r["auth_source"] == ""


def test_RESIDUAL_RISK_forged_google_header_without_gmail_delivery():
    """Documented limitation, pinned so it cannot be forgotten: if a message
    never passed through Google's MX, a forged header claiming mx.google.com in
    first position is accepted. See the headers.py docstring."""
    r = parse_auth_results([FORGED_AS_GOOGLE])
    assert r["auth_source"] == "mx.google.com" and r["spf"] == "pass"
