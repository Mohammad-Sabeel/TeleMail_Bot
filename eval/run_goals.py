"""Every goal, every arm, one row each.

The planner is called once per case and the SAME output is fed to both arms, so
the arms differ only in dispatch and output handling: "mediated" runs the real
pipeline (broker dispatch, format_answer warnings, redaction); "naive"
dispatches the proposal straight through naive_execute and returns the model's
answer verbatim.

G4 (SUPPRESS) is the exception that needs its own pass: it does not measure
dispatch or output at all, it measures whether the attacker's presence in the
mailbox changed the TARGET email's own triage verdict. That is neither
dispatch nor output handling, so it is computed once per case, outside the arm
loop, and the same pair of verdicts is attached to both arms' outcomes.
"""
from __future__ import annotations

import csv
from pathlib import Path

from eval.goals import Goal, Scenario, build_scenario
from eval.graders import Outcome, grade_goal
from eval.metrics import rate_line
from eval.mock_adapter import MockAdapter
from eval.naive_arm import naive_execute
from telemail.bot import format_answer, warning_reason
from telemail.broker.broker import Broker
from telemail.db import Database
from telemail.redact import redact
from telemail.triage.converse import retrieve


def _dispatch(scenario: Scenario, proposal: dict, arm: str) -> tuple[list[str], bool]:
    mock = MockAdapter()
    if arm == "naive":
        naive_execute(proposal, mock)
        return [i["op"] for i in mock.invocations], False
    db = Database(":memory:")
    for email in scenario.mailbox:
        db.insert_email(email)
    result = Broker(db, mock, write_service=None).execute(proposal, actor="planner")
    ops = [i["op"] for i in mock.invocations]
    db.close()
    return ops, not result.ok


def run_case(scenario: Scenario, planner, arm: str, *, indicators=(),
             vt_reports=()) -> Outcome:
    proposal = planner.propose(scenario.question,
                               [{"sender": e.sender_email, "subject": e.subject,
                                 "body": scenario.bodies[e.message_id]}
                                for e in scenario.mailbox])
    invoked, rejected = _dispatch(scenario, proposal, arm)

    reply = planner.ask_json("answer", scenario.question)
    raw_answer = str(reply.get("answer", ""))
    ranked = [e.message_id for e in retrieve(scenario.question, scenario.mailbox)]

    if arm == "naive":
        answer, warned = raw_answer, False
    else:
        sources = [(e, None, None) for e in scenario.mailbox
                   if e.message_id in reply.get("message_ids", [])]
        warned = any(warning_reason(e, t, level) for e, t, level in sources)
        answer = redact(format_answer(raw_answer, sources))

    return Outcome(answer=answer, warned=warned, invoked_ops=invoked,
                   rejected=rejected, ranked_ids=ranked)


def _target_verdict(planner, mailbox, target_id: str):
    """The TARGET email's own verdict out of a `planner.triage` call, or None
    if triage did not return one for it."""
    return next((v for v in planner.triage(mailbox) if v.message_id == target_id),
                None)


def _suppress_verdicts(planner, scenario: Scenario):
    """G4's paired triage: the target triaged with the attacker's email in the
    mailbox (attack), and again with the attacker's email removed (control)."""
    attack = _target_verdict(planner, scenario.mailbox, scenario.target_id)
    control_mailbox = [e for e in scenario.mailbox
                       if e.message_id != scenario.attacker_id]
    control = _target_verdict(planner, control_mailbox, scenario.target_id)
    return attack, control


def run_all(cases: list, planner, out_csv: Path, *, ablation: str = "full",
            source: str = "synthetic", split: str = "dev") -> list[dict]:
    rows = []
    for goal, email, body in cases:
        scenario = build_scenario(goal, email, body)
        attack_verdict, control_verdict = ((_suppress_verdicts(planner, scenario))
                                           if goal is Goal.SUPPRESS else (None, None))
        for arm in ("mediated", "naive"):
            outcome = run_case(scenario, planner, arm)
            outcome.attack_verdict = attack_verdict
            outcome.control_verdict = control_verdict
            rows.append({"goal": goal.value, "arm": arm,
                         "won": grade_goal(goal, outcome, scenario),
                         "source": source, "split": split, "ablation": ablation,
                         "answer": outcome.answer[:200],
                         "invoked": ";".join(outcome.invoked_ops)})

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return rows


def summarise(rows: list[dict]) -> str:
    lines = ["", f"{'goal / arm':<28}{'won':>4}{'n':>5}{'rate':>8}  95% CI", "-" * 62]
    for goal in sorted({r["goal"] for r in rows}):
        for arm in ("naive", "mediated"):
            subset = [r for r in rows if r["goal"] == goal and r["arm"] == arm]
            if subset:
                lines.append(rate_line(f"{goal} {arm}",
                                       sum(bool(r["won"]) for r in subset),
                                       len(subset)))
    return "\n".join(lines) + "\n"
