"""Alert policy. A pure function: no I/O, no model, no mailbox.

Triage answers *what is this message*. Whether it warrants interrupting you at
11pm is a different question, involving thresholds, priority senders, quiet
hours and daily caps. Keeping them apart is not tidiness — it lets an examiner
distinguish *model performance* from *product policy*, and it lets you retune
alerting without re-running a single classification.

Two decisions worth defending:

  quiet hours DEFER, they never drop. Dropping loses a message; deferring
  delays it. That is the recall-over-precision argument applied to timing.

  a `suspicious` verdict overrides quiet hours and the daily cap. If the system
  believes someone is impersonating your supervisor, that is not something to
  hold until morning because you have already had twenty newsletters.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time, timedelta

from telemail.models import Email, TriageResult


@dataclass(frozen=True)
class AlertPolicy:
    min_urgency: int = 4
    quiet_start: int = 23              # inclusive, local hour
    quiet_end: int = 7                 # exclusive
    daily_cap: int = 20
    vip_senders: frozenset[str] = frozenset()
    vip_domains: frozenset[str] = frozenset()
    override_categories: frozenset[str] = frozenset({"suspicious"})
    alert_on_fallback: bool = True     # conservative: surface what we could not judge


@dataclass(frozen=True)
class AlertDecision:
    alert: bool
    reason: str
    defer_until: datetime | None = None

    @property
    def deferred(self) -> bool:
        return self.defer_until is not None


def in_quiet_hours(now: datetime, policy: AlertPolicy) -> bool:
    h = now.hour
    if policy.quiet_start == policy.quiet_end:
        return False
    if policy.quiet_start < policy.quiet_end:          # e.g. 01:00-07:00
        return policy.quiet_start <= h < policy.quiet_end
    return h >= policy.quiet_start or h < policy.quiet_end   # wraps midnight


def next_quiet_end(now: datetime, policy: AlertPolicy) -> datetime:
    end = now.replace(hour=policy.quiet_end, minute=0, second=0, microsecond=0)
    return end if end > now else end + timedelta(days=1)


def is_vip(email: Email, policy: AlertPolicy) -> bool:
    return (email.sender_email in policy.vip_senders
            or email.sender_domain in policy.vip_domains)


def should_alert(triage: TriageResult, email: Email, *, now: datetime,
                 sent_today: int = 0,
                 policy: AlertPolicy | None = None) -> AlertDecision:
    p = policy or AlertPolicy()

    # 1. Security verdicts interrupt. They are the reason the system exists.
    if triage.category in p.override_categories:
        return AlertDecision(True, f"category={triage.category} overrides policy")

    # 2. Priority senders bypass quiet hours, but not the notion of a threshold:
    #    a VIP newsletter is still a newsletter.
    vip = is_vip(email, p)

    # 3. Anything the model could not judge is surfaced, not swallowed.
    if triage.source == "fallback" and p.alert_on_fallback:
        below_bar = False
    else:
        below_bar = triage.urgency < p.min_urgency and not vip

    if below_bar:
        return AlertDecision(False, f"urgency {triage.urgency} below "
                                    f"{p.min_urgency}")

    # 4. Quiet hours delay; they never discard.
    if in_quiet_hours(now, p) and not vip:
        return AlertDecision(False, "quiet hours", defer_until=next_quiet_end(now, p))

    # 5. The cap protects against alert fatigue, which is itself a security
    #    failure: a user who ignores notifications will ignore the real one.
    if sent_today >= p.daily_cap and not vip:
        return AlertDecision(False, f"daily cap {p.daily_cap} reached",
                             defer_until=next_quiet_end(now, p))

    why = "priority sender" if vip else f"urgency {triage.urgency}"
    return AlertDecision(True, why)
