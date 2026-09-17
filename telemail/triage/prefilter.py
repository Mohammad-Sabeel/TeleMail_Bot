"""Deterministic triage. No model, no network, no mailbox access.

Returns a verdict only when certain; `None` means "ask the model". That return
value is the whole design — it produces three measurable populations
(prefilter-decided, model-decided, and the split between them via
TriageResult.source) which is what makes the ablation possible at all.

Rule order is load-bearing. Two orderings below are deliberate and each is
worth a paragraph in the report; both are pinned by tests.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from telemail.models import Email, TriageResult

# Subject-line vocabulary that must never be silently filed as bulk mail.
# Matched with word boundaries and optional suffixes, on the subject only.
SECURITY_TERMS = {
    "password", "passcode", "verify", "verification", "suspend", "suspended",
    "unauthorised", "unauthorized", "breach", "compromised", "login", "sign-in",
    "2fa", "otp", "authenticat", "security", "invoice", "payment", "wire",
    "transfer", "refund", "fraud", "overdue", "deactivat", "locked",
}

MACHINE_LOCALPARTS = {
    "no-reply", "noreply", "no_reply", "donotreply", "do-not-reply",
    "mailer-daemon", "postmaster", "bounce", "bounces", "notifications",
}

_TERM_RE = re.compile(
    r"\b(" + "|".join(sorted(SECURITY_TERMS, key=len, reverse=True)) + r")\w*",
    re.I)


@dataclass
class PrefilterConfig:
    vip_senders: set[str] = field(default_factory=set)
    vip_domains: set[str] = field(default_factory=set)
    security_terms: re.Pattern = _TERM_RE


def matches_security_terms(subject: str, cfg: PrefilterConfig) -> bool:
    return bool(cfg.security_terms.search(subject or ""))


def local_part(address: str) -> str:
    return address.split("@", 1)[0].strip().lower()


def _hard_auth_failure(email: Email) -> list[str]:
    """Positive evidence of spoofing, not merely absence of evidence.

    `spf=none` is common for legitimate small senders, so only explicit `fail`
    results count. Two independent failures are required: a single dkim=fail
    happens to legitimate mail that was forwarded or modified in transit.
    """
    s = email.signals
    hard = [k for k in ("spf", "dkim", "dmarc") if getattr(s, k) == "fail"]
    return hard if len(hard) >= 2 else []


def _verdict(email: Email, *, category: str, urgency: int, action: bool,
             reason: str, confidence: float) -> TriageResult:
    return TriageResult(message_id=email.message_id, category=category,
                        urgency=urgency, requires_action=action, reason=reason,
                        confidence=confidence, source="prefilter")


def prefilter(email: Email, cfg: PrefilterConfig | None = None) -> TriageResult | None:
    cfg = cfg or PrefilterConfig()
    s = email.signals

    # 1. Authentication failure outranks everything, INCLUDING the VIP list.
    #    A message spoofing a priority sender is precisely the attack; if the
    #    VIP rule ran first it would award urgency 5 and a trusted framing to
    #    the forgery. Identity is checked before identity is trusted.
    hard = _hard_auth_failure(email)
    if hard:
        extra = [c for c in ("display_name_mismatch", "reply_to_differs")
                 if getattr(s, c)]
        return _verdict(email, category="suspicious", urgency=5, action=True,
                        reason=f"Sender authentication failed: {', '.join(hard + extra)}",
                        confidence=0.95)

    # 2. Priority senders. No model output can suppress a VIP alert, because
    #    the model is never consulted for these.
    if email.sender_email in cfg.vip_senders or email.sender_domain in cfg.vip_domains:
        return _verdict(email, category="personal", urgency=5, action=True,
                        reason="Sender on priority list", confidence=1.0)

    # 3. Security and financial language escalates — checked BEFORE the
    #    unsubscribe rule. A genuine breach notice frequently carries
    #    List-Unsubscribe because it left through the same bulk mailer as the
    #    newsletters. Reverse these two and you will confidently suppress the
    #    most important email you receive all year.
    if matches_security_terms(email.subject, cfg):
        return None

    # 4. Bulk mail, nothing above having fired.
    if email.has_list_unsubscribe:
        return _verdict(email, category="promotional", urgency=1, action=False,
                        reason="Bulk mail with List-Unsubscribe header",
                        confidence=0.9)

    # 5. Machine senders.
    if local_part(email.sender_email) in MACHINE_LOCALPARTS:
        return _verdict(email, category="notification", urgency=2, action=False,
                        reason="Automated sender address", confidence=0.85)

    # 6. A judgement call. This is the model's population.
    return None


def decision_share(emails: list[Email], cfg: PrefilterConfig | None = None) -> dict:
    """Target 40-60% decided. Above ~80% the model has nothing to contribute
    and the ablation becomes meaningless."""
    decided = [e for e in emails if prefilter(e, cfg) is not None]
    n = len(emails) or 1
    return {"total": len(emails), "decided": len(decided),
            "deferred": len(emails) - len(decided),
            "share": round(len(decided) / n, 3)}
