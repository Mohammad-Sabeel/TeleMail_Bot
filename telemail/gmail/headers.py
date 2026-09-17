"""Authentication-Results parsing.

On delivery, Gmail PREPENDS its own Authentication-Results header, so in a
delivered message the receiving server's verdict sits above anything the sender
wrote. An attacker can still add their own header lower down claiming
spf=pass dkim=pass dmarc=pass.

`parse_auth_results` trusts exactly one header: the FIRST Authentication-Results
in the message, and only if it was asserted by mx.google.com. Anything below it
is sender-controlled and ignored.

`parse_auth_results_naive` is the bug people actually write: collapsing headers
into a dict (`{h["name"]: h["value"] for h in headers}`), where the LAST
occurrence wins — which is the attacker's. It exists so the two can be measured
against each other as technique T11. Do not delete it; it is an experimental
arm, not dead code.

Residual risk, stated rather than hidden: a message that never passed through
Google's MX (an import, for instance) has no genuine header on top, so a forged
header claiming mx.google.com in first position would be accepted. Trust is
only as good as delivery through Google's own servers.
"""
import re

TRUSTED_AUTHSERV = "mx.google.com"
HEADER = "authentication-results"

_METHOD = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_VALID = {"pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"}


def _empty() -> dict[str, str]:
    return {"spf": "none", "dkim": "none", "dmarc": "none", "auth_source": ""}


def _authserv_id(value: str) -> str:
    """The asserting server: everything before the first ';'."""
    return value.split(";", 1)[0].strip().lower()


def _methods(value: str) -> dict[str, str]:
    """First result seen per method. Later duplicates are ignored."""
    found: dict[str, str] = {}
    for method, result in _METHOD.findall(value):
        m, r = method.lower(), result.lower()
        if r in _VALID:
            found.setdefault(m, r)
    return found


def parse_auth_results(headers: list[tuple[str, str]]) -> dict[str, str]:
    """Trustworthy parse. Only the topmost Authentication-Results counts, and
    only if our own MX asserted it.

    `headers` is [(name, value), ...] in message order, as the Gmail API returns
    them. auth_source == "" means no trusted assertion: read as unknown, never
    as passed.
    """
    for name, value in headers:
        # ARC-Authentication-Results is a forwarded chain, not our own verdict.
        if name.lower() != HEADER:
            continue
        if _authserv_id(value) != TRUSTED_AUTHSERV:
            return _empty()        # topmost header is not ours: trust nothing below
        return {**_empty(), **_methods(value), "auth_source": TRUSTED_AUTHSERV}
    return _empty()


def parse_auth_results_naive(headers: list[tuple[str, str]]) -> dict[str, str]:
    """T11 comparison arm: dict-collapse semantics, last occurrence wins."""
    collapsed = {name.lower(): value for name, value in headers}
    value = collapsed.get(HEADER)
    if value is None:
        return _empty()
    return {**_empty(), **_methods(value), "auth_source": _authserv_id(value)}
