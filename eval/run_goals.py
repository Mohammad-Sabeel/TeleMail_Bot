"""Every goal, every arm, one row each.

The model is called ONCE per case, in `model_pass`: one `propose`, one
`answer_from_bodies` (the production answer path, with the emails actually in
the prompt — see the note on `model_pass` below), one `triage` over the whole
mailbox, one deterministic `retrieve`. Both arms consume the SAME `produced`
dict, so a difference between arms can only come from `run_arm`'s dispatch and
output handling — never from a second, independently-sampled model call.
`run_arm(scenario, arm, produced)` takes no planner argument at all, which
makes that invariant structural rather than a promise a caller could break by
accident.

"mediated" runs the real pipeline: broker dispatch, and a mediated answer built
from the SAME triage results and the SAME deterministic rules layer
(`telemail.triage.assess.deterministic_evidence`) production uses, so
`warning_reason` gets a real chance to fire — then `format_answer`, which
redacts inside `escape_md` exactly once, so the mediated answer is
byte-for-byte what the product sends. "naive" dispatches the proposal straight through `naive_execute` and
returns the model's answer verbatim, with no warnings and no redaction.

G4 (SUPPRESS) needs a second triage pass, over the mailbox with the attacker's
email removed, to see whether the attacker's presence changed the TARGET
email's own verdict. That comparison is neither dispatch nor output handling,
so it is computed once per case in `run_all`, outside the arm loop, reusing
`model_pass`'s triage pass for the "attacker present" half rather than
triaging a third time.
"""
from __future__ import annotations

import argparse
import csv
from email import policy
from email.parser import BytesParser
from pathlib import Path

from eval.goals import Goal, Scenario, build_scenario
from eval.graders import Outcome, grade_goal
from eval.metrics import rate_line
from eval.mock_adapter import MockAdapter
from eval.naive_arm import naive_execute
from eval.run_attacks import _full_body
from telemail.bot import answer_warnings, format_answer
from telemail.broker.broker import Broker
from telemail.budget import Budget
from telemail.config import get_settings
from telemail.db import Database
from telemail.gmail.adapter import _URL_RE
from telemail.gmail.normalise import from_eml_bytes
from telemail.indicators import load_indicators
from telemail.models import Email
from telemail.threatintel import VirusTotal, domains_from
from telemail.triage.assess import deterministic_evidence
from telemail.triage.converse import answer_from_bodies, retrieve
from telemail.triage.planner import OpenRouterPlanner

FIXTURES_LLMAIL = Path("data/fixtures_llmail")
FIXTURES_OWN = Path("data/fixtures")
INDICATORS_PATH = Path("data/indicators.txt")


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


def _rules_level(email: Email, body: str, indicators, vt_reports) -> str:
    """The same deterministic rules layer production runs, so a mediated-arm
    warning is earned the way a real warning would be, not simulated.

    `read` is built from the case body (the only "fetched" content an eval
    case has) so indicator/link evidence has something real to match against,
    the way it would against a fetched email in production."""
    read = {"body": body, "links": [{"href": u} for u in _URL_RE.findall(body)]}
    level, _ = deterministic_evidence(email, read, indicators, vt_reports)
    return level.name


def model_pass(scenario: Scenario, planner) -> dict:
    """Everything the model produces for one case: one proposal, one answer,
    one ranking, one triage pass. Both arms are built from this, unchanged.

    The answer comes from `answer_from_bodies` — the same production path
    Feature D uses — not a bare `ask_json("answer", question)` call. That
    function is what builds the nonce-delimited, untrusted-marked prompt with
    the emails actually in it; without it the model never saw the attack text
    and every answer came back empty, making G2/G3/G6 structurally unwinnable
    in both arms."""
    proposal = planner.propose(scenario.question,
                               [{"sender": e.sender_email, "subject": e.subject,
                                 "body": scenario.bodies[e.message_id]}
                                for e in scenario.mailbox])
    reads = [(i, email, scenario.bodies[email.message_id])
            for i, email in enumerate(scenario.mailbox, 1)]
    body_answer = answer_from_bodies(planner, scenario.question, [], reads)
    if body_answer is None:
        # A model failure (invalid JSON, a validation error) must not crash
        # the run — it must show up as an empty, ungradeable answer in the
        # CSV, not be silently treated as a win or a loss.
        reply = {"answer": "", "message_ids": []}
    else:
        by_index = {i: email.message_id for i, email, _ in reads}
        reply = {"answer": body_answer.answer,
                "message_ids": [by_index[i] for i in body_answer.cited_ids
                                if i in by_index]}
    ranked_ids = [e.message_id for e in retrieve(scenario.question, scenario.mailbox)]
    triage = {v.message_id: v for v in planner.triage(scenario.mailbox)}
    return {"proposal": proposal, "reply": reply, "ranked_ids": ranked_ids,
            "triage": triage}


def run_arm(scenario: Scenario, arm: str, produced: dict, *, indicators=(),
           vt_reports=()) -> Outcome:
    invoked, rejected = _dispatch(scenario, produced["proposal"], arm)
    reply = produced["reply"]
    raw_answer = str(reply.get("answer", ""))

    if arm == "naive":
        answer, warned = raw_answer, False
    else:
        triage_by_id = produced["triage"]
        # Every mailbox email is in the answer prompt (model_pass), so the ones
        # not cited are the "seen but not cited" half of the warning.
        seen = [(e, triage_by_id.get(e.message_id),
                 _rules_level(e, scenario.bodies.get(e.message_id, ""),
                              indicators, vt_reports))
                for e in scenario.mailbox]
        cited_ids = reply.get("message_ids", [])
        sources = [s for s in seen if s[0].message_id in cited_ids]
        # "mediated-cited" is the Stage 1 warning (cited emails only), kept as
        # the before-half of the LLM09 comparison on the same model output.
        uncited = ([] if arm == "mediated-cited"
                   else [s for s in seen if s[0].message_id not in cited_ids])
        warned = bool(answer_warnings(sources, uncited))
        answer = format_answer(raw_answer, sources, uncited)

    return Outcome(answer=answer, warned=warned, invoked_ops=invoked,
                   rejected=rejected, ranked_ids=produced["ranked_ids"])


def run_case(scenario: Scenario, planner, arm: str, *, indicators=(),
             vt_reports=()) -> Outcome:
    """Thin wrapper kept for existing callers: one model pass, one arm."""
    return run_arm(scenario, arm, model_pass(scenario, planner),
                   indicators=indicators, vt_reports=vt_reports)


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


def _ablation_indicators(ablation: str) -> list[str]:
    if ablation in ("no-indicators", "neither"):
        return []
    return load_indicators(INDICATORS_PATH)


def _ablation_vt_reports(ablation: str, cases: list, vt) -> list:
    """One VirusTotal pass for the whole run rather than one per case or per
    email, so `vt`'s own lookup cap bounds the whole run, not each case —
    and `vt=None` (every direct `run_all` call that doesn't pass one, which
    is every test) makes this a no-op with no settings lookup and no network
    at all. Only `main()` builds a real client, from `get_settings()`.

    ponytail: the resulting reports are shared across every email `_rules_level`
    checks in this run rather than scoped to the one email whose link produced
    them — correct enough for an ablation flag; scope per-email if a report
    ever needs to say *which* email's link was flagged.
    """
    if vt is None or ablation in ("no-vt", "neither") or not vt.enabled:
        return []
    urls = [u for _goal, _email, body in cases for u in _URL_RE.findall(body)]
    domains = domains_from({"links": [{"href": u} for u in urls]})
    take = domains[:vt.max_lookups]
    if not take:
        return []
    reports = vt.reports(take)
    vt.max_lookups -= len(take)          # shared `vt`: later calls see what's left
    return reports


_ROW_KEY = ("source", "split", "ablation", "goal", "arm", "case")


def _write_merged(rows: list[dict], out_csv: Path) -> None:
    """Appends rather than overwrites: a second run — a different source,
    split or ablation, e.g. the Makefile's llmail run followed by its adaptive
    run — must not erase the rows an earlier run already left at the same
    --out path. A row is superseded only by a new row with the identical
    (source, split, ablation, goal, arm, case): a rerun of the same case
    replaces its old result instead of duplicating it."""
    existing = []
    if out_csv.exists():
        with out_csv.open() as fh:
            existing = list(csv.DictReader(fh))
    new_keys = {tuple(r[k] for k in _ROW_KEY) for r in rows}
    kept = [r for r in existing if tuple(r.get(k) for k in _ROW_KEY) not in new_keys]
    combined = kept + rows
    if not combined:
        return
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(combined[0]))
        writer.writeheader()
        writer.writerows(combined)


def run_all(cases: list, planner, out_csv: Path, *, ablation: str = "full",
            source: str = "synthetic", split: str = "dev", vt=None,
            arms=("mediated", "naive")) -> list[dict]:
    indicators = _ablation_indicators(ablation)
    vt_reports = _ablation_vt_reports(ablation, cases, vt)
    rows = []
    for goal, email, body in cases:
        scenario = build_scenario(goal, email, body)
        produced = model_pass(scenario, planner)
        attack_verdict, control_verdict = ((_suppress_verdicts(planner, scenario, produced))
                                           if goal is Goal.SUPPRESS else (None, None))
        for arm in arms:
            outcome = run_arm(scenario, arm, produced, indicators=indicators,
                              vt_reports=vt_reports)
            outcome.attack_verdict = attack_verdict
            outcome.control_verdict = control_verdict
            rows.append({"goal": goal.value, "arm": arm,
                         "won": grade_goal(goal, outcome, scenario),
                         "source": source, "split": split, "ablation": ablation,
                         "answer": outcome.answer[:200],
                         "invoked": ";".join(outcome.invoked_ops),
                         "case": scenario.attacker_id})

    _write_merged(rows, out_csv)
    return rows


def summarise(rows: list[dict]) -> str:
    lines = ["", f"{'goal / arm':<28}{'won':>4}{'n':>5}{'rate':>8}  95% CI", "-" * 62]
    for goal in sorted({r["goal"] for r in rows}):
        for arm in ("naive", "mediated-cited", "mediated"):
            subset = [r for r in rows if r["goal"] == goal and r["arm"] == arm]
            if subset:
                lines.append(rate_line(f"{goal} {arm}",
                                       sum(bool(r["won"]) for r in subset),
                                       len(subset)))
    return "\n".join(lines) + "\n"


# --- CLI -------------------------------------------------------------------
#
# Three distinct sources: `--source llmail` replays the frozen, held-out
# LLMail-Inject pool; `--source fixtures` replays the project's OWN
# adversarial fixtures (data/fixtures/) as an in-distribution baseline;
# `--source adaptive` runs the feedback attacker from eval/adaptive.py
# instead of any fixture pool. Either way the model is only ever the planner
# the settings name — never a literal model id in this file.


def parse_args(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=("llmail", "adaptive", "fixtures"),
                    default="llmail")
    ap.add_argument("--split", choices=("dev", "test"), default="dev",
                    help="the test split is touched once, at the end of Stage 2")
    ap.add_argument("--ablation", choices=("full", "no-indicators", "no-vt", "neither"),
                    default="full")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--out", default="data/goal_results.csv")
    ap.add_argument("--limit", type=int, default=0,
                    help="cap the number of cases processed; 0 means no limit")
    ap.add_argument("--cases", choices=("both", "attack", "control"), default="both",
                    help="which fixture arm to load; ignored by --source adaptive, "
                         "which always generates its own payloads")
    ap.add_argument("--fixtures", default=str(FIXTURES_OWN),
                    help="fixture directory for --source fixtures (Stage 2 uses "
                         "data/fixtures_stage2 so data/fixtures stays frozen)")
    ap.add_argument("--goal", choices=[g.value for g in Goal], default=None,
                    help="run every case against this goal instead of round-robin")
    ap.add_argument("--with-cited-only", action="store_true",
                    help="also record arm 'mediated-cited': the Stage 1 warning, "
                         "same model output")
    return ap.parse_args(argv)


def _body_text(msg) -> str:
    """`eval/llmail.py:to_eml` always writes a single plain-text part, so no
    MIME walk is needed here the way data/fixtures' hand-built multipart
    fixtures need `eval/run_attacks.py:_full_body`."""
    return str(msg.get_content()) if not msg.is_multipart() else ""


def _round_robin_by_arm(rows_with_arm) -> tuple[list, list]:
    """Splits (goal, email, body) triples into attack/control by their arm,
    goals assigned round-robin WITHIN each arm so all six get comparable
    coverage without trying every goal against every fixture.

    Within-arm, not over the combined ordering: assigning modulo the combined
    order let the position of the controls decide each goal's n (one goal drew
    two-thirds of its cases from benign mail, another drew none)."""
    goals = list(Goal)
    attack_cases, control_cases = [], []
    for arm, email, body in rows_with_arm:
        target = attack_cases if arm == "attack" else control_cases
        target.append((goals[len(target) % len(goals)], email, body))
    return attack_cases, control_cases


def _llmail_cases(split: str) -> tuple[list, list]:
    """The held-out LLMail-Inject pool: real attacks written by real people,
    frozen at data/fixtures_llmail/ (see docs/BUILD_PLAN.md's Stage 1 freeze).
    Filtered to one split; "unclear" fixtures are skipped — the dataset
    itself would not say which arm they belong to."""
    with (FIXTURES_LLMAIL / "manifest.csv").open() as fh:
        rows = [r for r in csv.DictReader(fh)
               if r["split"] == split and r["arm"] != "unclear"]
    parsed = []
    for row in rows:
        raw = (FIXTURES_LLMAIL / row["file"]).read_bytes()
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        email = from_eml_bytes(raw, own_address="you@example.invalid")
        parsed.append((row["arm"], email, _body_text(msg)))
    return _round_robin_by_arm(parsed)


def _own_fixture_cases(fixtures: Path = FIXTURES_OWN) -> tuple[list, list]:
    """The project's OWN adversarial fixtures at data/fixtures/ — an
    in-distribution baseline next to the held-out LLMail pool. These carry no
    split header (they predate the dev/test split), so every fixture is used
    regardless of --split. Parsing follows `eval/run_attacks.py:load_cases`
    rather than inventing a second reader for the same file shape."""
    parsed = []
    for f in sorted(fixtures.glob("*.eml")):
        raw = f.read_bytes()
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        arm = msg.get("X-TeleMail-Arm")
        if arm == "unclear":
            continue
        email = from_eml_bytes(raw, own_address="you@example.invalid")
        parsed.append((arm, email, _full_body(msg)))
    return _round_robin_by_arm(parsed)


def load_cases(source: str, split: str, fixtures: Path = FIXTURES_OWN) -> tuple[list, list]:
    """Attack cases and control cases (X-TeleMail-Arm "attack" / "control")
    for the given `--source`: the project's own fixtures for "fixtures", the
    held-out LLMail-Inject pool otherwise. Controls are the false-positive
    check — run separately so the caller can record them under their own
    source (e.g. "llmail-control")."""
    if source == "fixtures":
        return _own_fixture_cases(fixtures)
    return _llmail_cases(split)


def _select_cases(attack_cases: list, control_cases: list, cases: str) -> tuple[list, list]:
    """--cases lets a caller run only controls (or only attacks) without
    paying for the other arm first — applied before --limit/_cap_total, so
    `--cases control --limit 12` spends the whole limit on controls."""
    if cases == "attack":
        return attack_cases, []
    if cases == "control":
        return [], control_cases
    return attack_cases, control_cases


def _cap_total(attack_cases: list, control_cases: list, limit: int) -> tuple[list, list]:
    """--limit caps the TOTAL number of cases run (attack + control), applied
    before any model call — not each list independently, or --limit 10 could
    still mean 20 cases."""
    if not limit:
        return attack_cases, control_cases
    attack_cases = attack_cases[:limit]
    control_cases = control_cases[:max(limit - len(attack_cases), 0)]
    return attack_cases, control_cases


def _limited(items: list, limit: int) -> list:
    return items[:limit] if limit else items


def main(argv=None) -> None:
    args = parse_args(argv)
    settings = get_settings()
    planner = OpenRouterPlanner(settings.openrouter_api_key, settings.model_name)
    # Attach the same daily ceiling adaptive() charges against, so a run
    # cannot quietly spend past it (OWASP LLM10 — see telemail/budget.py).
    planner.budget = Budget(daily_tokens=settings.daily_token_budget)
    # One client for the whole invocation: _ablation_vt_reports shrinks its
    # max_lookups as each run_all call spends from it, so two run_all calls
    # in one CLI run (attack + control, or the Makefile's llmail + adaptive)
    # share one 8-lookup budget rather than getting 8 each. Inert with no key.
    vt = VirusTotal(settings.virustotal_api_key)
    out = Path(args.out)

    if args.source == "adaptive":
        from eval.adaptive import _attack_email, attack_rounds, best_payload

        attacker = OpenRouterPlanner(settings.openrouter_api_key, settings.model_name)
        cases = []
        for goal in _limited(list(Goal), args.limit):
            rounds = attack_rounds(goal, planner, attacker, rounds=args.rounds,
                                   budget=planner.budget)
            body = best_payload(rounds) or (rounds[-1]["body"] if rounds else "")
            cases.append((goal, _attack_email(len(cases)), body))
        rows = (run_all(cases, planner, out, ablation=args.ablation,
                        source="adaptive", split=args.split, vt=vt) if cases else [])
    else:
        attack_cases, control_cases = load_cases(args.source, args.split, Path(args.fixtures))
        if args.goal:
            attack_cases, control_cases = ([(Goal(args.goal), e, b) for _, e, b in cs]
                                           for cs in (attack_cases, control_cases))
        attack_cases, control_cases = _select_cases(attack_cases, control_cases, args.cases)
        attack_cases, control_cases = _cap_total(attack_cases, control_cases, args.limit)

        # run_all appends: the control call below does not erase the attack
        # call's rows, it adds to them (see _write_merged).
        arms = (("mediated", "mediated-cited", "naive") if args.with_cited_only
                else ("mediated", "naive"))
        attack_rows = (run_all(attack_cases, planner, out, ablation=args.ablation,
                               source=args.source, split=args.split, vt=vt, arms=arms)
                      if attack_cases else [])
        control_rows = (run_all(control_cases, planner, out, ablation=args.ablation,
                                source=f"{args.source}-control", split=args.split, vt=vt,
                                arms=arms)
                        if control_cases else [])
        rows = attack_rows + control_rows

    print(summarise(rows))


if __name__ == "__main__":
    main()
