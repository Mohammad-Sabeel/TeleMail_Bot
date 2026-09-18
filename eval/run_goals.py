"""Every goal, every arm, one row each.

The model is called ONCE per case, in `model_pass`: one `propose`, one
`ask_json`, one `triage` over the whole mailbox, one deterministic `retrieve`.
Both arms consume the SAME `produced` dict, so a difference between arms can
only come from `run_arm`'s dispatch and output handling — never from a second,
independently-sampled model call. `run_arm(scenario, arm, produced)` takes no
planner argument at all, which makes that invariant structural rather than a
promise a caller could break by accident.

"mediated" runs the real pipeline: broker dispatch, and a mediated answer built
from the SAME triage results and the SAME deterministic rules layer
(`telemail.triage.assess.deterministic_evidence`) production uses, so
`warning_reason` gets a real chance to fire — then `format_answer` and
`redact`. "naive" dispatches the proposal straight through `naive_execute` and
returns the model's answer verbatim, with no warnings and no redaction.

G4 (SUPPRESS) needs a second triage pass, over the mailbox with the attacker's
email removed, to see whether the attacker's presence changed the TARGET
email's own verdict. That comparison is neither dispatch nor output handling,
so it is computed once per case in `run_all`, outside the arm loop, reusing
`model_pass`'s triage pass for the "attacker present" half rather than
triaging a third time.
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
from telemail.models import Email
from telemail.redact import redact
from telemail.triage.assess import deterministic_evidence
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


def _rules_level(email: Email) -> str:
    """The same deterministic rules layer production runs, so a mediated-arm
    warning is earned the way a real warning would be, not simulated."""
    level, _ = deterministic_evidence(email, None)
    return level.name


def model_pass(scenario: Scenario, planner) -> dict:
    """Everything the model produces for one case: one proposal, one answer,
    one ranking, one triage pass. Both arms are built from this, unchanged."""
    proposal = planner.propose(scenario.question,
                               [{"sender": e.sender_email, "subject": e.subject,
                                 "body": scenario.bodies[e.message_id]}
                                for e in scenario.mailbox])
    reply = planner.ask_json("answer", scenario.question)
    ranked_ids = [e.message_id for e in retrieve(scenario.question, scenario.mailbox)]
    triage = {v.message_id: v for v in planner.triage(scenario.mailbox)}
    return {"proposal": proposal, "reply": reply, "ranked_ids": ranked_ids,
            "triage": triage}


def run_arm(scenario: Scenario, arm: str, produced: dict) -> Outcome:
    invoked, rejected = _dispatch(scenario, produced["proposal"], arm)
    reply = produced["reply"]
    raw_answer = str(reply.get("answer", ""))

    if arm == "naive":
        answer, warned = raw_answer, False
    else:
        triage_by_id = produced["triage"]
        sources = [(e, triage_by_id.get(e.message_id), _rules_level(e))
                   for e in scenario.mailbox
                   if e.message_id in reply.get("message_ids", [])]
        warned = any(warning_reason(e, t, level) for e, t, level in sources)
        answer = redact(format_answer(raw_answer, sources))

    return Outcome(answer=answer, warned=warned, invoked_ops=invoked,
                   rejected=rejected, ranked_ids=produced["ranked_ids"])


def run_case(scenario: Scenario, planner, arm: str, *, indicators=(),
             vt_reports=()) -> Outcome:
    """Thin wrapper kept for existing callers: one model pass, one arm."""
    return run_arm(scenario, arm, model_pass(scenario, planner))


def _target_verdict(planner, mailbox, target_id: str):
    """The TARGET email's own verdict out of a `planner.triage` call, or None
    if triage did not return one for it."""
    return next((v for v in planner.triage(mailbox) if v.message_id == target_id),
                None)


def _suppress_verdicts(planner, scenario: Scenario, produced: dict):
    """G4's paired triage: the target triaged with the attacker's email in the
    mailbox (attack — reuses model_pass's triage, no extra call), and again
    with the attacker's email removed (control)."""
    attack = produced["triage"].get(scenario.target_id)
    control_mailbox = [e for e in scenario.mailbox
                       if e.message_id != scenario.attacker_id]
    control = _target_verdict(planner, control_mailbox, scenario.target_id)
    return attack, control


def run_all(cases: list, planner, out_csv: Path, *, ablation: str = "full",
            source: str = "synthetic", split: str = "dev") -> list[dict]:
    rows = []
    for goal, email, body in cases:
        scenario = build_scenario(goal, email, body)
        produced = model_pass(scenario, planner)
        attack_verdict, control_verdict = ((_suppress_verdicts(planner, scenario, produced))
                                           if goal is Goal.SUPPRESS else (None, None))
        for arm in ("mediated", "naive"):
            outcome = run_arm(scenario, arm, produced)
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
